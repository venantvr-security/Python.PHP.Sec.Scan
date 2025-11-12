# tests/test_worklist.py
import os
import tempfile

import pytest
import tree_sitter_php as tsphp
from tree_sitter import Parser, Language

from analysis.call_graph import CallGraphBuilder
from analysis.worklist import WorklistAnalyzer

PHP_LANGUAGE = Language(tsphp.language_php())
PARSER = Parser(PHP_LANGUAGE)

# Worklist algorithm requires more sophisticated dataflow analysis
# These tests are marked as WIP (work in progress)
pytestmark = pytest.mark.skip(reason="Worklist algorithm WIP - requires dataflow analysis")


def test_worklist_simple_interprocedural():
    """Test worklist algorithm with simple inter-procedural flow."""
    builder = CallGraphBuilder(PARSER)

    code = b"""<?php
    function main() {
        $input = $_GET['cmd'];
        executeCommand($input);
    }

    function executeCommand($cmd) {
        system($cmd);
    }
    ?>"""

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.php', delete=False) as f:
        f.write(code)
        temp_path = f.name

    try:
        call_graph = builder.build_from_files([temp_path])
        analyzer = WorklistAnalyzer(call_graph, ['rce'])
        results = analyzer.analyze()

        # Should detect RCE via inter-procedural analysis
        rce_vulns = [v for v in results if v['type'] == 'rce']
        assert len(rce_vulns) >= 1

        # Verify it's marked as interprocedural
        vuln = rce_vulns[0]
        assert vuln['interprocedural'] == True
        assert vuln['function'] == 'executeCommand'
        assert 0 in vuln['tainted_params']
    finally:
        os.unlink(temp_path)


def test_worklist_multi_level():
    """Test worklist with multi-level call chain."""
    builder = CallGraphBuilder(PARSER)

    code = b"""<?php
    function level1() {
        $input = $_POST['data'];
        level2($input);
    }

    function level2($data) {
        level3($data);
    }

    function level3($payload) {
        eval($payload);
    }
    ?>"""

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.php', delete=False) as f:
        f.write(code)
        temp_path = f.name

    try:
        call_graph = builder.build_from_files([temp_path])
        analyzer = WorklistAnalyzer(call_graph, ['rce'])
        results = analyzer.analyze()

        # Should detect RCE through 3-level call chain
        rce_vulns = [v for v in results if v['type'] == 'rce']
        assert len(rce_vulns) >= 1
        assert rce_vulns[0]['function'] == 'level3'
    finally:
        os.unlink(temp_path)


def test_worklist_multiple_tainted_params():
    """Test worklist with multiple tainted parameters."""
    builder = CallGraphBuilder(PARSER)

    code = b"""<?php
    function process() {
        $a = $_GET['a'];
        $b = $_GET['b'];
        doStuff($a, "safe", $b);
    }

    function doStuff($x, $y, $z) {
        eval($x);
        eval($z);
    }
    ?>"""

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.php', delete=False) as f:
        f.write(code)
        temp_path = f.name

    try:
        call_graph = builder.build_from_files([temp_path])
        analyzer = WorklistAnalyzer(call_graph, ['rce'])
        results = analyzer.analyze()

        rce_vulns = [v for v in results if v['type'] == 'rce']
        # Should detect both eval() calls (params 0 and 2 are tainted)
        assert len(rce_vulns) >= 2
    finally:
        os.unlink(temp_path)


def test_worklist_no_false_positive():
    """Test worklist doesn't create false positives."""
    builder = CallGraphBuilder(PARSER)

    code = b"""<?php
    function main() {
        $safe = "constant";
        processData($safe);
    }

    function processData($data) {
        eval($data);
    }
    ?>"""

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.php', delete=False) as f:
        f.write(code)
        temp_path = f.name

    try:
        call_graph = builder.build_from_files([temp_path])
        analyzer = WorklistAnalyzer(call_graph, ['rce'])
        results = analyzer.analyze()

        # Should NOT detect anything (no tainted input)
        rce_vulns = [v for v in results if v['type'] == 'rce']
        assert len(rce_vulns) == 0
    finally:
        os.unlink(temp_path)


def test_worklist_file_inclusion():
    """Test worklist with file inclusion vulnerability."""
    builder = CallGraphBuilder(PARSER)

    code = b"""<?php
    function router() {
        $page = $_GET['page'];
        loadPage($page);
    }

    function loadPage($file) {
        include($file);
    }
    ?>"""

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.php', delete=False) as f:
        f.write(code)
        temp_path = f.name

    try:
        call_graph = builder.build_from_files([temp_path])
        analyzer = WorklistAnalyzer(call_graph, ['file_inclusion'])
        results = analyzer.analyze()

        file_vulns = [v for v in results if v['type'] == 'file_inclusion']
        assert len(file_vulns) >= 1
        assert file_vulns[0]['interprocedural'] == True
    finally:
        os.unlink(temp_path)
