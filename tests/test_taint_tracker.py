# tests/test_taint_tracker.py
import tree_sitter_php as tsphp
from tree_sitter import Parser, Language

from analysis.taint_tracker import TaintTracker

# Initialiser le parseur pour PHP
PHP_LANGUAGE = Language(tsphp.language_php())
PARSER = Parser(PHP_LANGUAGE)


def test_taint_tracker_sql_injection():
    """Teste la détection d'une injection SQL."""
    code = """
    <?php
    $id = $_GET['id'];
    mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['sql_injection'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "sql_injection"
    assert vulns[0]["sink"] == "mysqli_query"
    assert vulns[0]["variable"] == "$id"


def test_taint_tracker_xss_sanitized():
    """Teste la non-détection de XSS avec désinfection."""
    code = """
    <?php
    $input = $_GET['input'];
    $safe = htmlspecialchars($input);
    echo $safe;
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['xss'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 0


def test_taint_tracker_auth_bypass():
    """Teste la détection d'une comparaison faible."""
    code = """
    <?php
    if ($password == $_POST['password']) {
        login();
    }
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['auth_bypass'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "auth_bypass"
    assert "weak_comparison" in vulns[0]["sink"]


def test_taint_tracker_sql_injection_function_param():
    """Teste la détection d'une injection SQL via un paramètre de fonction."""
    code = """
    <?php
    function run_query($conn, $value) {
        mysqli_query($conn, "SELECT * FROM users WHERE id = $value");
    }
    $id = $_GET['id'];
    run_query($conn, $id);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['sql_injection'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "sql_injection"
    assert vulns[0]["sink"] == "mysqli_query"
    assert vulns[0]["variable"] == "$value"


def test_taint_tracker_xss_htmlentities_warning():
    """Teste l'avertissement pour l'usage de htmlentities au lieu de sanitize_text_field."""
    code = """
    <?php
    $input = $_POST['data'];
    $safe = htmlentities($input);
    echo $safe;
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['xss'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    warnings = result["warnings"]
    assert len(vulns) == 0
    assert len(warnings) == 1
    assert warnings[0]["type"] == "non_preferred_filter"
    assert warnings[0]["function"] == "htmlentities"
    assert warnings[0]["message"] == "Use sanitize_text_field instead"
    assert warnings[0]["file"] == "test.php"


def test_taint_tracker_xss_class_method_sanitization():
    """Teste la détection d'une méthode de classe comme filtre XSS."""
    code = """
    <?php
    class Sanitizer {
        static function sanitizeText($input) {
            return sanitize_text_field($input);
        }
    }
    $input = $_POST['data'];
    $safe = Sanitizer::sanitizeText($input);
    echo $safe;
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['xss'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    warnings = result["warnings"]
    assert len(vulns) == 0
    assert len(warnings) == 0


def test_taint_tracker_xss_function_return():
    """Teste la détection d'une vulnérabilité XSS via le retour d'une fonction."""
    code = """
    <?php
    function get_tainted() {
        return $_POST['data'];
    }
    $x = get_tainted();
    echo $x;
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['xss'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    warnings = result["warnings"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "xss"
    assert vulns[0]["sink"] == "echo"
    assert vulns[0]["variable"] == "$x"
    assert len(warnings) == 0


def test_taint_tracker_unsanitized_source():
    """Teste l'avertissement pour une source lue sans sanitization."""
    code = """
    <?php
    $id = $_GET['id'];
    $var = $id; // Propagation sans sanitization
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['sql_injection'], verbose=True)  # Activer verbose
    result = tracker.analyze(tree, "test.php")
    warnings = result["warnings"]
    assert len(warnings) >= 1
    assert any(w["type"] == "unsanitized_source" and w["variable"] == "$id" for w in warnings)
    assert any(w["type"] == "unsanitized_source" and w["variable"] == "$var" for w in warnings)


def test_taint_tracker_rce_eval():
    """Teste la détection de RCE via eval."""
    code = """
    <?php
    $cmd = $_GET['cmd'];
    eval($cmd);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['rce'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "rce"
    assert vulns[0]["sink"] == "eval"
    assert vulns[0]["variable"] == "$cmd"


def test_taint_tracker_rce_system():
    """Teste la détection de RCE via system."""
    code = """
    <?php
    $cmd = $_POST['command'];
    system($cmd);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['rce'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "rce"
    assert vulns[0]["sink"] == "system"
    assert vulns[0]["variable"] == "$cmd"


def test_taint_tracker_rce_sanitized():
    """Teste la non-détection de RCE avec escapeshellarg."""
    code = """
    <?php
    $cmd = $_GET['file'];
    $safe = escapeshellarg($cmd);
    system($safe);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['rce'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 0


def test_taint_tracker_rce_exec():
    """Teste la détection de RCE via exec."""
    code = """
    <?php
    $input = $_REQUEST['input'];
    exec($input);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['rce'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "rce"
    assert vulns[0]["sink"] == "exec"
    assert vulns[0]["variable"] == "$input"


def test_taint_tracker_rce_shell_exec():
    """Teste la détection de RCE via shell_exec."""
    code = """
    <?php
    $data = $_COOKIE['data'];
    shell_exec($data);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['rce'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "rce"
    assert vulns[0]["sink"] == "shell_exec"
    assert vulns[0]["variable"] == "$data"


def test_taint_tracker_rce_passthru():
    """Teste la détection de RCE via passthru."""
    code = """
    <?php
    $arg = $_SERVER['HTTP_USER_AGENT'];
    passthru($arg);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['rce'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "rce"
    assert vulns[0]["sink"] == "passthru"
    assert vulns[0]["variable"] == "$arg"


def test_taint_tracker_file_inclusion_include():
    """Teste la détection de File Inclusion via include."""
    code = """
    <?php
    $page = $_GET['page'];
    include($page);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['file_inclusion'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "file_inclusion"
    assert vulns[0]["sink"] == "include"
    assert vulns[0]["variable"] == "$page"


def test_taint_tracker_file_inclusion_require():
    """Teste la détection de File Inclusion via require."""
    code = """
    <?php
    $file = $_POST['file'];
    require($file);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['file_inclusion'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "file_inclusion"
    assert vulns[0]["sink"] == "require"
    assert vulns[0]["variable"] == "$file"


def test_taint_tracker_file_inclusion_sanitized():
    """Teste la non-détection de File Inclusion avec basename."""
    code = """
    <?php
    $page = $_GET['page'];
    $safe = basename($page);
    include($safe);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['file_inclusion'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 0


def test_taint_tracker_file_inclusion_include_once():
    """Teste la détection de File Inclusion via include_once."""
    code = """
    <?php
    $module = $_REQUEST['module'];
    include_once($module);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['file_inclusion'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "file_inclusion"
    assert vulns[0]["sink"] == "include_once"
    assert vulns[0]["variable"] == "$module"


def test_taint_tracker_file_inclusion_require_once():
    """Teste la détection de File Inclusion via require_once."""
    code = """
    <?php
    $lib = $_COOKIE['lib'];
    require_once($lib);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['file_inclusion'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "file_inclusion"
    assert vulns[0]["sink"] == "require_once"
    assert vulns[0]["variable"] == "$lib"


def test_taint_tracker_command_injection_exec():
    """Teste la détection de Command Injection via exec."""
    code = """
    <?php
    $cmd = $_GET['cmd'];
    exec($cmd);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['command_injection'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "command_injection"
    assert vulns[0]["sink"] == "exec"
    assert vulns[0]["variable"] == "$cmd"


def test_taint_tracker_command_injection_system():
    """Teste la détection de Command Injection via system."""
    code = """
    <?php
    $input = $_POST['command'];
    system($input);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['command_injection'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "command_injection"
    assert vulns[0]["sink"] == "system"
    assert vulns[0]["variable"] == "$input"


def test_taint_tracker_command_injection_sanitized():
    """Teste la non-détection de Command Injection avec escapeshellarg."""
    code = """
    <?php
    $cmd = $_GET['file'];
    $safe = escapeshellarg($cmd);
    system($safe);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['command_injection'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 0


def test_taint_tracker_command_injection_passthru():
    """Teste la détection de Command Injection via passthru."""
    code = """
    <?php
    $data = $_COOKIE['data'];
    passthru($data);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['command_injection'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "command_injection"
    assert vulns[0]["sink"] == "passthru"
    assert vulns[0]["variable"] == "$data"


def test_taint_tracker_path_traversal_file_get_contents():
    """Teste la détection de Path Traversal via file_get_contents."""
    code = """
    <?php
    $file = $_GET['file'];
    file_get_contents($file);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['path_traversal'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "path_traversal"
    assert vulns[0]["sink"] == "file_get_contents"
    assert vulns[0]["variable"] == "$file"


def test_taint_tracker_path_traversal_fopen():
    """Teste la détection de Path Traversal via fopen."""
    code = """
    <?php
    $path = $_POST['path'];
    fopen($path, 'r');
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['path_traversal'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "path_traversal"
    assert vulns[0]["sink"] == "fopen"
    assert vulns[0]["variable"] == "$path"


def test_taint_tracker_path_traversal_sanitized():
    """Teste la non-détection de Path Traversal avec basename."""
    code = """
    <?php
    $file = $_GET['file'];
    $safe = basename($file);
    readfile($safe);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['path_traversal'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 0


def test_taint_tracker_path_traversal_readfile():
    """Teste la détection de Path Traversal via readfile."""
    code = """
    <?php
    $document = $_REQUEST['doc'];
    readfile($document);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['path_traversal'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "path_traversal"
    assert vulns[0]["sink"] == "readfile"
    assert vulns[0]["variable"] == "$document"


def test_taint_tracker_path_traversal_unlink():
    """Teste la détection de Path Traversal via unlink."""
    code = """
    <?php
    $file = $_GET['delete'];
    unlink($file);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['path_traversal'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "path_traversal"
    assert vulns[0]["sink"] == "unlink"
    assert vulns[0]["variable"] == "$file"


def test_taint_tracker_sql_intval_sanitizer():
    """Teste la désinfection SQL via intval."""
    code = """
    <?php
    $id = $_GET['id'];
    $safe_id = intval($id);
    mysqli_query($conn, "SELECT * FROM users WHERE id = $safe_id");
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['sql_injection'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 0


def test_taint_tracker_sql_floatval_sanitizer():
    """Teste la désinfection SQL via floatval."""
    code = """
    <?php
    $price = $_POST['price'];
    $safe_price = floatval($price);
    mysqli_query($conn, "SELECT * FROM products WHERE price = $safe_price");
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['sql_injection'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 0


def test_taint_tracker_nested_function_propagation():
    """Teste la propagation du taint via retour de fonction."""
    code = """
    <?php
    function get_input() {
        return $_GET['data'];
    }
    $input = get_input();
    echo $input;
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['xss'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "xss"
    assert vulns[0]["variable"] == "$input"


def test_taint_tracker_session_source():
    """Teste la détection de $_SESSION comme source."""
    code = """
    <?php
    $data = $_SESSION['user_input'];
    echo $data;
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['xss'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "xss"
    assert vulns[0]["variable"] == "$data"


def test_taint_tracker_getenv_source():
    """Teste la détection de getenv comme source."""
    code = """
    <?php
    $env = getenv('USER_DATA');
    mysqli_query($conn, "SELECT * FROM users WHERE name = '$env'");
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['sql_injection'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "sql_injection"
    assert vulns[0]["variable"] == "$env"


def test_taint_tracker_pdo_query():
    """Teste la détection SQL via PDO query."""
    code = """
    <?php
    $user = $_GET['user'];
    $pdo->query("SELECT * FROM users WHERE name = '$user'");
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['sql_injection'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "sql_injection"
    assert vulns[0]["sink"] == "query"
    assert vulns[0]["variable"] == "$user"


def test_taint_tracker_pdo_exec():
    """Teste la détection SQL via PDO exec."""
    code = """
    <?php
    $id = $_POST['id'];
    $pdo->exec("DELETE FROM users WHERE id = $id");
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['sql_injection'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "sql_injection"
    assert vulns[0]["sink"] == "exec"
    assert vulns[0]["variable"] == "$id"
