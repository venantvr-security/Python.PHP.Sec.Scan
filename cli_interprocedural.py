#!/usr/bin/env python3
# cli_interprocedural.py
"""CLI for inter-procedural scanner."""

import argparse
import os
import tree_sitter_php as tsphp
from tree_sitter import Parser, Language
from pathlib import Path

from analysis.call_graph import CallGraphBuilder
from analysis.interprocedural import InterproceduralAnalyzer


def find_php_files(directory: str) -> list:
    """Find all PHP files in directory."""
    php_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.php'):
                php_files.append(os.path.join(root, file))
    return php_files


def main():
    parser = argparse.ArgumentParser(description='Inter-procedural PHP security scanner')
    parser.add_argument('--dir', required=True, help='Directory to scan')
    parser.add_argument('--vuln-types', nargs='+',
                       default=['sql_injection', 'xss', 'rce', 'file_inclusion'],
                       help='Vulnerability types to detect')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Initialize parser
    PHP_LANGUAGE = Language(tsphp.language_php())
    php_parser = Parser(PHP_LANGUAGE)

    # Find PHP files
    php_files = find_php_files(args.dir)
    print(f"Found {len(php_files)} PHP files")

    if not php_files:
        print("No PHP files found")
        return

    # Build call graph
    print("\nBuilding call graph...")
    builder = CallGraphBuilder(php_parser)
    call_graph = builder.build_from_files(php_files)

    print(f"  Functions: {len(call_graph.functions)}")
    print(f"  Call sites: {len(call_graph.call_sites)}")
    print(f"  Include relationships: {len(call_graph.includes)}")

    if args.verbose:
        print("\nFunctions found:")
        for func_name, func_defs in call_graph.functions.items():
            for func_def in func_defs:
                print(f"  {func_name} in {os.path.basename(func_def.file_path)}:{func_def.line_number}")

    # Run inter-procedural analysis
    print("\nRunning inter-procedural analysis...")
    analyzer = InterproceduralAnalyzer(call_graph, args.vuln_types)
    results = analyzer.analyze()

    # Display results
    print(f"\n{'='*60}")
    print("ANALYSIS RESULTS")
    print(f"{'='*60}")
    print(f"Total vulnerabilities: {len(results)}")

    # Group by type
    vuln_by_type = {}
    for vuln in results:
        vtype = vuln['type']
        if vtype not in vuln_by_type:
            vuln_by_type[vtype] = []
        vuln_by_type[vtype].append(vuln)

    for vtype, vulns in vuln_by_type.items():
        print(f"\n{vtype.upper()}: {len(vulns)}")
        for vuln in vulns:
            print(f"  {os.path.basename(vuln['file'])}:{vuln['line']}")
            if vuln.get('interprocedural'):
                print(f"    [Inter-procedural] Call chain:")
                for call in vuln.get('call_chain', []):
                    print(f"      -> {os.path.basename(call['file'])}:{call['line']} ({call['function']})")


if __name__ == '__main__':
    main()
