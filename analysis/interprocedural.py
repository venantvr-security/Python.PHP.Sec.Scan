# analysis/interprocedural.py
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from tree_sitter import Node

from analysis.call_graph import CallGraph, CallSite, FunctionDef
from analysis.taint_tracker import TaintTracker


@dataclass
class TaintContext:
    """Taint analysis context for inter-procedural analysis."""
    tainted_vars: Set[str]  # Variable names
    tainted_params: Set[int]  # Parameter indices
    tainted_return: bool = False


class InterproceduralAnalyzer:
    """Inter-procedural taint analysis."""

    def __init__(self, call_graph: CallGraph, vuln_types: List[str]):
        self.call_graph = call_graph
        self.vuln_types = vuln_types
        self.function_contexts: Dict[str, TaintContext] = {}
        self.visited_functions: Set[str] = set()
        self.all_results = []

    def analyze(self) -> List[Dict]:
        """Perform inter-procedural analysis on entire call graph."""
        # Analyze each file with its context
        for filepath, (tree, code) in self.call_graph.file_asts.items():
            results = self._analyze_file_with_context(filepath, tree, code)
            self.all_results.extend(results)

        return self.all_results

    def _analyze_file_with_context(self, filepath: str, tree: Node, code: bytes) -> List[Dict]:
        """Analyze file considering inter-procedural context."""
        # Run intra-procedural analysis first
        tracker = TaintTracker(code, self.vuln_types)

        # tree is already root_node from call_graph
        import tree_sitter_php as tsphp
        from tree_sitter import Parser, Language
        PHP_LANGUAGE = Language(tsphp.language_php())
        parser = Parser(PHP_LANGUAGE)
        full_tree = parser.parse(code)

        intra_results = tracker.analyze(full_tree, filepath)

        # Enhance with inter-procedural analysis
        inter_vulns = self._find_interprocedural_vulns(filepath, tree, code)

        # Merge results
        all_vulns = intra_results.get('vulnerabilities', [])
        all_vulns.extend(inter_vulns)

        return all_vulns

    def _find_interprocedural_vulns(self, filepath: str, tree: Node, code: bytes) -> List[Dict]:
        """Find vulnerabilities through inter-procedural flow."""
        vulnerabilities = []

        # Get all call sites in this file
        call_sites = [cs for cs in self.call_graph.call_sites if cs.caller_file == filepath]

        for call_site in call_sites:
            # Check if any argument is tainted
            tainted_args = self._get_tainted_arguments(call_site, code)
            if not tainted_args:
                continue

            # Resolve callee function
            func_def = self.call_graph.resolve_call(call_site)
            if not func_def:
                continue

            # Analyze callee with tainted parameters
            callee_vulns = self._analyze_callee_with_taint(
                func_def, tainted_args, call_site
            )
            vulnerabilities.extend(callee_vulns)

        return vulnerabilities

    def _get_tainted_arguments(self, call_site: CallSite, code: bytes) -> Dict[int, Node]:
        """Identify which arguments are tainted at call site."""
        tainted = {}

        for idx, arg_node in enumerate(call_site.arguments):
            if self._is_tainted_node(arg_node, code):
                tainted[idx] = arg_node

        return tainted

    def _is_tainted_node(self, node: Node, code: bytes) -> bool:
        """Check if node represents tainted data (superglobal access)."""
        if node.type == 'subscript_expression':
            obj_node = node.child_by_field_name('object')
            if obj_node and obj_node.type == 'variable_name':
                var_name = obj_node.text.decode('utf-8')
                if var_name in ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_SESSION']:
                    return True

        # Check for variable that might be assigned from superglobal
        if node.type == 'variable_name':
            # This is simplified - in full implementation, track data flow
            return False

        # Recursively check children
        for child in node.children:
            if self._is_tainted_node(child, code):
                return True

        return False

    def _analyze_callee_with_taint(
        self,
        func_def: FunctionDef,
        tainted_args: Dict[int, Node],
        call_site: CallSite
    ) -> List[Dict]:
        """Analyze callee function with specific tainted parameters."""
        vulnerabilities = []

        # Avoid infinite recursion
        func_key = f"{func_def.file_path}:{func_def.name}"
        if func_key in self.visited_functions:
            return vulnerabilities
        self.visited_functions.add(func_key)

        try:
            # Get function body
            body = func_def.node.child_by_field_name('body')
            if not body:
                return vulnerabilities

            # Get code for this file
            if func_def.file_path not in self.call_graph.file_asts:
                return vulnerabilities

            _, code = self.call_graph.file_asts[func_def.file_path]

            # Map tainted argument indices to parameter names
            tainted_params = set()
            for arg_idx in tainted_args.keys():
                if arg_idx < len(func_def.params):
                    tainted_params.add(func_def.params[arg_idx])

            # Find sinks in function body that use tainted params
            vulns = self._find_sinks_using_params(body, tainted_params, code, func_def, call_site)
            vulnerabilities.extend(vulns)

        finally:
            self.visited_functions.discard(func_key)

        return vulnerabilities

    def _find_sinks_using_params(
        self,
        node: Node,
        tainted_params: Set[str],
        code: bytes,
        func_def: FunctionDef,
        call_site: CallSite
    ) -> List[Dict]:
        """Find sink nodes that use tainted parameters."""
        vulnerabilities = []

        # Check if this node is a sink
        vuln_type = self._check_sink_node(node, tainted_params, code)
        if vuln_type:
            # Create vulnerability with full trace
            vuln = {
                'type': vuln_type,
                'file': func_def.file_path,
                'line': node.start_point[0] + 1,
                'column': node.start_point[1],
                'sink': node.text.decode('utf-8', errors='ignore')[:100],
                'severity': 'high',
                'interprocedural': True,
                'call_chain': [
                    {
                        'file': call_site.caller_file,
                        'line': call_site.line_number,
                        'function': call_site.callee_name
                    },
                    {
                        'file': func_def.file_path,
                        'line': node.start_point[0] + 1,
                        'function': func_def.name
                    }
                ]
            }
            vulnerabilities.append(vuln)

        # Recursively check children
        for child in node.children:
            vulns = self._find_sinks_using_params(child, tainted_params, code, func_def, call_site)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    def _check_sink_node(self, node: Node, tainted_params: Set[str], code: bytes) -> Optional[str]:
        """Check if node is a sink using tainted parameter."""
        # Check common sink types
        sinks_map = {
            'function_call_expression': {
                'eval': 'rce',
                'system': 'rce',
                'exec': 'rce',
                'shell_exec': 'rce',
                'passthru': 'rce',
                'mysqli_query': 'sql_injection',
                'mysql_query': 'sql_injection',
            },
            'echo_statement': 'xss',
            'include_expression': 'file_inclusion',
            'include_once_expression': 'file_inclusion',
            'require_expression': 'file_inclusion',
            'require_once_expression': 'file_inclusion',
        }

        if node.type == 'function_call_expression':
            func_node = node.child_by_field_name('function')
            if func_node and func_node.type == 'name':
                func_name = func_node.text.decode('utf-8')
                if func_name in sinks_map[node.type]:
                    # Check if arguments use tainted params
                    if self._args_use_params(node, tainted_params):
                        return sinks_map[node.type][func_name]

        elif node.type in sinks_map:
            if self._node_uses_params(node, tainted_params):
                return sinks_map[node.type]

        return None

    def _args_use_params(self, call_node: Node, tainted_params: Set[str]) -> bool:
        """Check if function call arguments use tainted parameters."""
        args_node = call_node.child_by_field_name('arguments')
        if not args_node:
            return False

        for child in args_node.children:
            if self._node_uses_params(child, tainted_params):
                return True

        return False

    def _node_uses_params(self, node: Node, tainted_params: Set[str]) -> bool:
        """Check if node uses any tainted parameter."""
        if node.type == 'variable_name':
            var_name = node.text.decode('utf-8').lstrip('$')
            if var_name in tainted_params:
                return True

        for child in node.children:
            if self._node_uses_params(child, tainted_params):
                return True

        return False
