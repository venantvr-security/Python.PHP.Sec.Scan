# optimization/node_cache.py
"""AST node caching within files."""

from functools import lru_cache
from typing import List, Dict, Any
from tree_sitter import Node


class NodeCache:
    """Cache frequently accessed node properties."""

    def __init__(self):
        self._type_cache = {}
        self._children_cache = {}
        self._text_cache = {}

    def get_node_type(self, node: Node) -> str:
        """Get cached node type."""
        node_id = id(node)
        if node_id not in self._type_cache:
            self._type_cache[node_id] = node.type
        return self._type_cache[node_id]

    def get_children(self, node: Node) -> List[Node]:
        """Get cached children."""
        node_id = id(node)
        if node_id not in self._children_cache:
            self._children_cache[node_id] = list(node.children)
        return self._children_cache[node_id]

    def get_text(self, node: Node, source: bytes) -> str:
        """Get cached node text."""
        node_id = id(node)
        if node_id not in self._text_cache:
            self._text_cache[node_id] = source[node.start_byte:node.end_byte].decode('utf-8')
        return self._text_cache[node_id]

    def clear(self):
        """Clear all caches."""
        self._type_cache.clear()
        self._children_cache.clear()
        self._text_cache.clear()


@lru_cache(maxsize=10000)
def get_node_signature(node_id: int, node_type: str, start_byte: int, end_byte: int) -> tuple:
    """Get cached node signature for deduplication."""
    return (node_type, start_byte, end_byte)
