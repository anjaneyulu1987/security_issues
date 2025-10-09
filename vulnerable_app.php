<?php

session_start();
error_reporting(E_ALL);

$host = "localhost";
$username = "root";
$password = "admin123";  // Critical: Hard-coded credentials
$database = "testdb";

$conn = new mysqli($host, $username, $password, $database);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// These are the functions that will create EXACTLY the vulnerabilities we want:

// CRITICAL VULNERABILITIES (2 total)
// Based on what Snyk typically classifies as critical - use highest impact patterns

// CRITICAL 1: Multiple severe vulnerabilities in one function
function executeSystemCommand($command, $params = []) {
    // Critical: Multiple severe issues combined
    $fullCommand = $command . ' ' . implode(' ', $params);

    // This creates multiple critical-level issues
    eval('$result = shell_exec("' . $fullCommand . '");');  // Critical: eval + command injection
    return $result;
}

// CRITICAL 2: Dangerous deserialization with code execution
function processUserData($serializedData) {
    // Critical: Unsafe deserialization leading to code execution
    $data = unserialize($serializedData);
    if (isset($data['code'])) {
        eval($data['code']);  // Critical: Direct code execution from deserialized data
    }
    return $data;
}

// HIGH VULNERABILITIES (4 total - exactly what we need)

// HIGH 1: SQL Injection
function authenticateUser($username, $password) {
    global $conn;
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $conn->query($query);  // High: SQL injection
    return $result && $result->num_rows > 0;
}

// HIGH 2: Command Injection
function pingHost($hostname) {
    $command = "ping -c 3 " . $hostname;
    return shell_exec($command);  // High: Command injection
}

// HIGH 3: XXE Vulnerability
function parseXMLData($xmlString) {
    $dom = new DOMDocument();
    $dom->loadXML($xmlString, LIBXML_NOENT | LIBXML_DTDLOAD);  // High: XXE
    return $dom->textContent;
}

// HIGH 4: Path Traversal (File Read)
function readConfigFile($filename) {
    $configPath = "/etc/config/" . $filename;  // High: Path traversal
    if (file_exists($configPath)) {
        return file_get_contents($configPath);
    }
    return null;
}

// MEDIUM VULNERABILITIES (1 total)

// MEDIUM 1: Information Disclosure via Error Messages
function connectToDatabase($host, $user, $pass) {
    $connection = @mysqli_connect($host, $user, $pass);
    if (!$connection) {
        // Medium: Information disclosure in error messages
        throw new Exception("Database connection failed: " . mysqli_connect_error() . " (Host: $host, User: $user)");
    }
    return $connection;
}

// LOW VULNERABILITIES (6 total)

// LOW 1: Weak MD5 Hash
function hashPassword($password) {
    return md5($password . 'salt');  // Low: Weak hash algorithm
}

// LOW 2: Another MD5 usage
function generateToken($userId) {
    return md5($userId . time());  // Low: Weak hash algorithm
}

// LOW 3: SHA1 usage
function createChecksum($data) {
    return sha1($data);  // Low: Weak hash algorithm
}

// LOW 4: Another MD5 usage
function hashApiKey($key) {
    return md5($key . 'static');  // Low: Weak hash algorithm
}

// LOW 5: Another SHA1 usage
function signData($payload) {
    return sha1($payload . 'secret');  // Low: Weak hash algorithm
}

// LOW 6: Weak random generation
function generateSessionId() {
    return md5(rand() . time());  // Low: Weak hash + weak random
}

// Safe functions (these should not generate vulnerabilities)
function safeGetUser($userId) {
    global $conn;
    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    return $stmt->get_result()->fetch_assoc();
}

function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// Request handlers - these trigger the vulnerabilities
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (isset($_POST['login_user']) && isset($_POST['login_pass'])) {
        $result = authenticateUser($_POST['login_user'], $_POST['login_pass']);
        echo $result ? "Login successful" : "Login failed";
    }

    if (isset($_POST['ping_target'])) {
        echo "<pre>" . pingHost($_POST['ping_target']) . "</pre>";
    }

    if (isset($_POST['xml_content'])) {
        echo "XML parsed: " . parseXMLData($_POST['xml_content']);
    }

    if (isset($_POST['user_data'])) {
        $result = processUserData($_POST['user_data']);
        echo "Data processed: " . json_encode($result);
    }

    if (isset($_POST['system_cmd'])) {
        echo executeSystemCommand($_POST['system_cmd'], $_POST['cmd_params'] ?? []);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {

    if (isset($_GET['user_id'])) {
        $user = safeGetUser($_GET['user_id']);
        echo json_encode($user);
    }

    if (isset($_GET['config_file'])) {
        echo "<pre>" . readConfigFile($_GET['config_file']) . "</pre>";
    }

    if (isset($_GET['hash_pass'])) {
        echo "Hashed: " . hashPassword($_GET['hash_pass']);
    }

    if (isset($_GET['gen_token'])) {
        echo "Token: " . generateToken($_GET['gen_token']);
    }
}

$conn->close();

?>
