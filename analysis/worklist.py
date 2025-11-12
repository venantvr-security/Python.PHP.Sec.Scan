# analysis/worklist.py
"""Worklist-based inter-procedural taint analysis using fixpoint iteration."""

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional

from tree_sitter import Node

from analysis.call_graph import CallGraph, FunctionDef


@dataclass
class TaintFact:
    """Taint fact: parameter index -> tainted status."""
    function_name: str
    tainted_params: Set[int] = field(default_factory=set)
    tainted_return: bool = False

    def merge(self, other: 'TaintFact') -> bool:
        """Merge with another taint fact. Return True if changed."""
        changed = False

        new_params = other.tainted_params - self.tainted_params
        if new_params:
            self.tainted_params.update(new_params)
            changed = True

        if other.tainted_return and not self.tainted_return:
            self.tainted_return = True
            changed = True

        return changed


class WorklistAnalyzer:
    """Worklist-based inter-procedural analysis."""

    def __init__(self, call_graph: CallGraph, vuln_types: List[str]):
        self.call_graph = call_graph
        self.vuln_types = vuln_types
        self.worklist: deque = deque()
        self.taint_facts: Dict[str, TaintFact] = {}
        self.vulnerabilities: List[Dict] = []

    def analyze(self) -> List[Dict]:
        """Run worklist algorithm."""
        # Initialize worklist with entry points (functions called with tainted args)
        self._initialize_worklist()

        # Iterate until fixpoint
        iterations = 0
        max_iterations = 1000  # Safety limit

        while self.worklist and iterations < max_iterations:
            iterations += 1
            func_name = self.worklist.popleft()

            if func_name not in self.call_graph.functions:
                continue

            # Process function
            changed = self._analyze_function(func_name)

            # If taint facts changed, add callers to worklist
            if changed:
                self._propagate_to_callers(func_name)

        return self.vulnerabilities

    def _initialize_worklist(self):
        """Find entry points: functions with superglobal sources."""
        for filepath, (tree, code) in self.call_graph.file_asts.items():
            self._find_tainted_calls(tree, code, filepath)

    def _find_tainted_calls(self, node: Node, code: bytes, filepath: str, current_func: Optional[str] = None, tainted_vars: Optional[Set[str]] = None):
        """Find function calls with tainted arguments."""
        if tainted_vars is None:
            tainted_vars = set()

        # Track current function - new scope
        if node.type == 'function_definition':
            name_node = node.child_by_field_name('name')
            if name_node:
                current_func = name_node.text.decode('utf-8')
            # Process function body with new tainted_vars set
            body = node.child_by_field_name('body')
            if body:
                self._find_tainted_calls(body, code, filepath, current_func, set())
            return

        # Track variable assignments from superglobals
        if node.type == 'assignment_expression':
            left = node.child_by_field_name('left')
            right = node.child_by_field_name('right')
            if left and right:
                if self._is_superglobal_access(right) or self._uses_tainted_var(right, tainted_vars):
                    # Extract variable name from left side
                    var_name = self._extract_var_name(left)
                    if var_name:
                        tainted_vars.add(var_name)

        # Check for function calls with tainted args
        if node.type == 'function_call_expression':
            func_node = node.child_by_field_name('function')
            if func_node and func_node.type == 'name':
                callee_name = func_node.text.decode('utf-8')

                # Check if any argument is tainted
                args_node = node.child_by_field_name('arguments')
                if args_node:
                    tainted_indices = set()
                    arg_idx = 0
                    for child in args_node.children:
                        if child.type not in ['(', ')', ',']:
                            if self._is_superglobal_access(child) or self._uses_tainted_var(child, tainted_vars):
                                tainted_indices.add(arg_idx)
                            arg_idx += 1

                    if tainted_indices:
                        # Initialize taint fact
                        if callee_name not in self.taint_facts:
                            self.taint_facts[callee_name] = TaintFact(callee_name)
                        self.taint_facts[callee_name].tainted_params.update(tainted_indices)
                        if callee_name not in self.worklist:
                            self.worklist.append(callee_name)

        # Recursively process children (except function body which was handled above)
        if node.type != 'function_definition':
            for child in node.children:
                self._find_tainted_calls(child, code, filepath, current_func, tainted_vars)

    def _extract_var_name(self, node: Node) -> Optional[str]:
        """Extract variable name from variable_name node."""
        if node.type == 'variable_name':
            # variable_name has children: $ and name
            for child in node.children:
                if child.type == 'name':
                    return child.text.decode('utf-8')
        elif node.type == 'dynamic_variable_name':
            for child in node.children:
                if child.type == 'name':
                    return child.text.decode('utf-8')
        return None

    def _uses_tainted_var(self, node: Node, tainted_vars: Set[str]) -> bool:
        """Check if node uses any tainted variable."""
        if node.type == 'variable_name':
            var_name = self._extract_var_name(node)
            if var_name and var_name in tainted_vars:
                return True

        for child in node.children:
            if self._uses_tainted_var(child, tainted_vars):
                return True
        return False

    def _is_superglobal_access(self, node: Node) -> bool:
        """Check if node accesses superglobal."""
        if node.type == 'subscript_expression':
            obj_node = node.child_by_field_name('object')
            if obj_node and obj_node.type == 'variable_name':
                var_name = obj_node.text.decode('utf-8')
                return var_name in ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_SESSION']

        # Recursively check children
        for child in node.children:
            if self._is_superglobal_access(child):
                return True
        return False

    def _analyze_function(self, func_name: str) -> bool:
        """Analyze function and return True if taint facts changed."""
        func_defs = self.call_graph.functions.get(func_name, [])
        if not func_defs:
            return False

        func_def = func_defs[0]  # Take first definition
        taint_fact = self.taint_facts.get(func_name, TaintFact(func_name))

        # Get function body
        body = func_def.node.child_by_field_name('body')
        if not body:
            return False

        # Get code
        if func_def.file_path not in self.call_graph.file_asts:
            return False
        _, code = self.call_graph.file_asts[func_def.file_path]

        # Check for vulnerabilities in function body
        self._check_sinks(body, func_def, taint_fact, code)

        # Propagate taint to callees
        changed = self._propagate_to_callees(body, func_def, taint_fact)

        return changed

    def _check_sinks(self, node: Node, func_def: FunctionDef, taint_fact: TaintFact, code: bytes):
        """Check for vulnerable sinks using tainted parameters."""
        sink_map = {
            'eval': 'rce',
            'system': 'rce',
            'exec': 'rce',
            'shell_exec': 'rce',
            'passthru': 'rce',
            'include': 'file_inclusion',
            'require': 'file_inclusion',
            'mysqli_query': 'sql_injection',
            'mysql_query': 'sql_injection',
        }

        if node.type == 'function_call_expression':
            func_node = node.child_by_field_name('function')
            if func_node and func_node.type == 'name':
                sink_name = func_node.text.decode('utf-8')
                if sink_name in sink_map:
                    # Check if arguments use tainted params
                    if self._uses_tainted_param(node, func_def.params, taint_fact.tainted_params):
                        vuln = {
                            'type': sink_map[sink_name],
                            'file': func_def.file_path,
                            'line': node.start_point[0] + 1,
                            'column': node.start_point[1],
                            'sink': sink_name,
                            'severity': 'high',
                            'interprocedural': True,
                            'function': func_def.name,
                            'tainted_params': list(taint_fact.tainted_params)
                        }
                        self.vulnerabilities.append(vuln)

        # Check include/require expressions
        if node.type in ['include_expression', 'require_expression',
                         'include_once_expression', 'require_once_expression']:
            if self._uses_tainted_param(node, func_def.params, taint_fact.tainted_params):
                vuln = {
                    'type': 'file_inclusion',
                    'file': func_def.file_path,
                    'line': node.start_point[0] + 1,
                    'column': node.start_point[1],
                    'sink': node.type,
                    'severity': 'high',
                    'interprocedural': True,
                    'function': func_def.name,
                    'tainted_params': list(taint_fact.tainted_params)
                }
                self.vulnerabilities.append(vuln)

        for child in node.children:
            self._check_sinks(child, func_def, taint_fact, code)

    def _uses_tainted_param(self, node: Node, param_names: List[str], tainted_indices: Set[int]) -> bool:
        """Check if node uses any tainted parameter."""
        if node.type == 'variable_name':
            var_name = node.text.decode('utf-8').lstrip('$')
            for idx in tainted_indices:
                if idx < len(param_names) and param_names[idx] == var_name:
                    return True

        for child in node.children:
            if self._uses_tainted_param(child, param_names, tainted_indices):
                return True
        return False

    def _propagate_to_callees(self, node: Node, func_def: FunctionDef, taint_fact: TaintFact) -> bool:
        """Propagate taint to functions called from this function."""
        changed = False

        if node.type == 'function_call_expression':
            func_node = node.child_by_field_name('function')
            if func_node and func_node.type == 'name':
                callee_name = func_node.text.decode('utf-8')

                # Check which arguments are tainted
                args_node = node.child_by_field_name('arguments')
                if args_node:
                    tainted_arg_indices = set()
                    arg_idx = 0
                    for child in args_node.children:
                        if child.type not in ['(', ')', ',']:
                            if self._uses_tainted_param(child, func_def.params, taint_fact.tainted_params):
                                tainted_arg_indices.add(arg_idx)
                            arg_idx += 1

                    if tainted_arg_indices:
                        # Update callee's taint fact
                        if callee_name not in self.taint_facts:
                            self.taint_facts[callee_name] = TaintFact(callee_name)

                        old_params = self.taint_facts[callee_name].tainted_params.copy()
                        self.taint_facts[callee_name].tainted_params.update(tainted_arg_indices)

                        if self.taint_facts[callee_name].tainted_params != old_params:
                            self.worklist.append(callee_name)
                            changed = True

        for child in node.children:
            if self._propagate_to_callees(child, func_def, taint_fact):
                changed = True

        return changed

    def _propagate_to_callers(self, func_name: str):
        """Add callers to worklist when taint facts change."""
        for call_site in self.call_graph.call_sites:
            if call_site.callee_name == func_name and call_site.caller_function:
                if call_site.caller_function not in [item for item in self.worklist]:
                    self.worklist.append(call_site.caller_function)
