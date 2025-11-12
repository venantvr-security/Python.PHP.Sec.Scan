# analysis/call_graph.py
import os
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path

from tree_sitter import Node


@dataclass
class FunctionDef:
    """Function definition metadata."""
    name: str
    file_path: str
    node: Node
    params: List[str]
    line_number: int
    namespace: Optional[str] = None


@dataclass
class CallSite:
    """Function call site metadata."""
    caller_function: Optional[str]
    caller_file: str
    callee_name: str
    arguments: List[Node]
    node: Node
    line_number: int


class CallGraph:
    """Optimized inter-procedural call graph for PHP codebase."""

    def __init__(self):
        self.functions: Dict[str, List[FunctionDef]] = {}
        self.call_sites: List[CallSite] = []
        self.includes: Dict[str, Set[str]] = {}
        self.file_asts: Dict[str, Tuple[Node, bytes]] = {}
        self._resolution_cache: Dict[str, Optional[FunctionDef]] = {}

    def add_function(self, func_def: FunctionDef):
        """Register function definition."""
        if func_def.name not in self.functions:
            self.functions[func_def.name] = []
        self.functions[func_def.name].append(func_def)

    def add_call_site(self, call_site: CallSite):
        """Register function call site."""
        self.call_sites.append(call_site)

    def add_include(self, from_file: str, to_file: str):
        """Register include/require relationship."""
        if from_file not in self.includes:
            self.includes[from_file] = set()
        self.includes[from_file].add(to_file)

    def resolve_call(self, call_site: CallSite) -> Optional[FunctionDef]:
        """Resolve call site to function definition with caching."""
        cache_key = f"{call_site.caller_file}:{call_site.callee_name}"
        if cache_key in self._resolution_cache:
            return self._resolution_cache[cache_key]

        candidates = self.functions.get(call_site.callee_name, [])
        if not candidates:
            self._resolution_cache[cache_key] = None
            return None

        # Prioritize same-file definitions
        for candidate in candidates:
            if candidate.file_path == call_site.caller_file:
                self._resolution_cache[cache_key] = candidate
                return candidate

        # Return first candidate from included files
        included = self.get_included_files(call_site.caller_file)
        for candidate in candidates:
            if candidate.file_path in included:
                self._resolution_cache[cache_key] = candidate
                return candidate

        # Fallback to first candidate
        result = candidates[0]
        self._resolution_cache[cache_key] = result
        return result

    def get_callees(self, function_name: str) -> List[CallSite]:
        """Get all call sites from a function."""
        return [cs for cs in self.call_sites
                if cs.caller_function == function_name]

    def get_included_files(self, file_path: str) -> Set[str]:
        """Get all files included by a file (transitive)."""
        visited = set()
        to_visit = {file_path}

        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue
            visited.add(current)

            if current in self.includes:
                to_visit.update(self.includes[current] - visited)

        return visited - {file_path}


class CallGraphBuilder:
    """Build call graph from PHP files."""

    def __init__(self, parser):
        self.parser = parser
        self.call_graph = CallGraph()
        self.current_file = None
        self.current_function = None

    def build_from_files(self, filepaths: List[str]) -> CallGraph:
        """Build call graph from multiple files."""
        # First pass: extract function definitions and includes
        for filepath in filepaths:
            self._process_file(filepath)

        return self.call_graph

    def _process_file(self, filepath: str):
        """Process single file."""
        self.current_file = filepath

        try:
            with open(filepath, 'rb') as f:
                code = f.read()
        except Exception:
            return

        tree = self.parser.parse(code)
        self.call_graph.file_asts[filepath] = (tree.root_node, code)

        self._extract_functions(tree.root_node)
        self._extract_calls(tree.root_node)
        self._extract_includes(tree.root_node, code)

    def _extract_functions(self, node: Node):
        """Extract function definitions from AST."""
        if node.type == 'function_definition':
            name_node = node.child_by_field_name('name')
            if not name_node:
                return

            func_name = name_node.text.decode('utf-8')
            params = self._extract_params(node)

            func_def = FunctionDef(
                name=func_name,
                file_path=self.current_file,
                node=node,
                params=params,
                line_number=node.start_point[0] + 1
            )
            self.call_graph.add_function(func_def)

        for child in node.children:
            self._extract_functions(child)

    def _extract_params(self, func_node: Node) -> List[str]:
        """Extract parameter names from function definition."""
        params_node = func_node.child_by_field_name('parameters')
        if not params_node:
            return []

        params = []
        for child in params_node.children:
            if child.type == 'simple_parameter':
                name_node = child.child_by_field_name('name')
                if name_node:
                    param_name = name_node.text.decode('utf-8').lstrip('$')
                    params.append(param_name)
            elif child.type == 'property_promotion_parameter':
                name_node = child.child_by_field_name('name')
                if name_node:
                    param_name = name_node.text.decode('utf-8').lstrip('$')
                    params.append(param_name)

        return params

    def _extract_calls(self, node: Node, current_func: Optional[str] = None):
        """Extract function calls from AST."""
        # Track current function scope
        if node.type == 'function_definition':
            name_node = node.child_by_field_name('name')
            if name_node:
                current_func = name_node.text.decode('utf-8')

        if node.type == 'function_call_expression':
            name_node = node.child_by_field_name('function')
            if name_node and name_node.type == 'name':
                func_name = name_node.text.decode('utf-8')
                args = self._extract_arguments(node)

                call_site = CallSite(
                    caller_function=current_func,
                    caller_file=self.current_file,
                    callee_name=func_name,
                    arguments=args,
                    node=node,
                    line_number=node.start_point[0] + 1
                )
                self.call_graph.add_call_site(call_site)

        for child in node.children:
            self._extract_calls(child, current_func)

    def _extract_arguments(self, call_node: Node) -> List[Node]:
        """Extract argument nodes from function call."""
        args = []
        args_node = call_node.child_by_field_name('arguments')
        if not args_node:
            return args

        for child in args_node.children:
            if child.type not in ['(', ')', ',']:
                args.append(child)

        return args

    def _extract_includes(self, node: Node, code: bytes):
        """Extract include/require statements."""
        if node.type in ['include_expression', 'include_once_expression',
                         'require_expression', 'require_once_expression']:
            # Try to resolve static include path
            arg_node = None
            for child in node.children:
                if child.type in ['string', 'encapsed_string']:
                    arg_node = child
                    break

            if arg_node:
                path_text = arg_node.text.decode('utf-8').strip('\'"')
                resolved = self._resolve_include_path(path_text)
                if resolved:
                    self.call_graph.add_include(self.current_file, resolved)

        for child in node.children:
            self._extract_includes(child, code)

    def _resolve_include_path(self, path: str) -> Optional[str]:
        """Resolve include path to absolute file path."""
        current_dir = os.path.dirname(self.current_file)

        # Handle PHP constants
        replacements = {
            '__DIR__': current_dir,
            '__FILE__': self.current_file,
        }
        for const, value in replacements.items():
            if const in path:
                path = path.replace(const, value)

        # Make absolute if relative
        if not os.path.isabs(path):
            path = os.path.join(current_dir, path)

        path = os.path.normpath(path)

        # Check if file exists
        if os.path.isfile(path):
            return path

        # Try with .php extension
        if not path.endswith('.php') and os.path.isfile(path + '.php'):
            return path + '.php'

        return None
