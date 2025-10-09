<?php

session_start();
error_reporting(E_ALL);

$host = "localhost";
$username = "root";
$password = "admin123";
$database = "testdb";

$conn = new mysqli($host, $username, $password, $database);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// CRITICAL VULNERABILITIES (2 total)
// These typically require very specific patterns that Snyk classifies as critical

// CRITICAL 1: Deserialization of untrusted data (typically critical)
function loadUserSession($serializedData) {
    $sessionData = unserialize($serializedData);  // Critical: Object injection
    $_SESSION = array_merge($_SESSION, $sessionData);
    return $sessionData;
}

// CRITICAL 2: Log4j-style injection vulnerability (critical pattern)
function logUserActivity($username, $activity) {
    $logEntry = date('Y-m-d H:i:s') . " [" . $username . "] " . $activity;

    // Critical: JNDI injection pattern (like Log4j)
    if (strpos($activity, '${jndi:') !== false) {
        file_put_contents('exploit.log', 'JNDI INJECTION ATTEMPT: ' . $logEntry . "\n", FILE_APPEND);
        eval('$result = ' . str_replace('${jndi:', '', $activity) . ';');  // Critical
    }

    file_put_contents('app.log', $logEntry . "\n", FILE_APPEND);
}

// HIGH VULNERABILITIES (4 total)

// HIGH 1: SQL Injection
function adminAuthentication($username, $password) {
    global $conn;
    $query = "SELECT * FROM admin_users WHERE username = '$username' AND password = '$password'";
    $result = $conn->query($query);  // High: SQL injection

    if ($result && $result->num_rows > 0) {
        $_SESSION['admin_logged_in'] = true;
        $_SESSION['admin_user'] = $username;
        return true;
    }
    return false;
}

// HIGH 2: Command Injection
function networkDiagnostics($hostname) {
    $command = "ping -c 3 " . $hostname;
    $output = shell_exec($command);  // High: Command injection
    return $output;
}

// HIGH 3: Code Injection via eval
function executeUserCode($input) {
    $result = eval($input);  // High: Direct code execution
    return "Code executed: " . $result;
}

// HIGH 4: XXE Vulnerability
function parseUserXMLData($xmlString) {
    $dom = new DOMDocument();
    $dom->loadXML($xmlString, LIBXML_NOENT | LIBXML_DTDLOAD);  // High: XXE vulnerability
    return $dom->textContent;
}

// MEDIUM VULNERABILITIES (1 total)

// MEDIUM 1: Path Traversal (medium severity)
function readUserFile($filename) {
    $basePath = "user_files/";
    $fullPath = $basePath . $filename;  // Medium: Path traversal vulnerability

    if (file_exists($fullPath)) {
        return file_get_contents($fullPath);
    }
    return "File not found: " . $fullPath;
}

// LOW VULNERABILITIES (6 total)

// LOW 1: Weak MD5 hashing
function hashUserPassword($password, $salt = 'defaultsalt') {
    $weakHash = md5($password . $salt);  // Low: Weak hash algorithm
    return $weakHash;
}

// LOW 2: Another MD5 usage
function generateUserToken($userId) {
    return md5($userId . time());  // Low: Weak hash algorithm
}

// LOW 3: SHA1 usage (also considered weak)
function createSessionHash($sessionData) {
    return sha1($sessionData . 'secret');  // Low: Weak hash algorithm
}

// LOW 4: Weak random generation
function generateInsecureToken() {
    $randomPart = rand(1000, 9999);  // Low: Weak random number generation
    return $randomPart;
}

// LOW 5: Information disclosure in headers
function setVulnerableHeaders() {
    header('Server: Apache/2.4.1 (Vulnerable-Server)');  // Low: Information disclosure
    header('X-Powered-By: PHP/' . phpversion());
}

// LOW 6: Another weak hash
function hashApiKey($key) {
    return md5($key . 'static_salt');  // Low: Weak hash algorithm
}

// Safe utility functions (no vulnerabilities detected)
function getUserProfile($userId) {
    global $conn;
    $stmt = $conn->prepare("SELECT * FROM user_profiles WHERE user_id = ? AND status = 'active'");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result();

    $profiles = [];
    while ($row = $result->fetch_assoc()) {
        $profiles[] = $row;
    }
    return $profiles;
}

function fetchRemoteContent($url) {
    // Validate URL format
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return "Invalid URL format";
    }

    $context = stream_context_create([
        'http' => [
            'timeout' => 10,
            'method' => 'GET',
            'header' => "User-Agent: SafeApp/1.0\r\n"
        ]
    ]);

    return file_get_contents($url, false, $context);
}

function displayUserContent($userInput, $contentType = 'comment') {
    // Safe version with proper escaping
    echo "<div class='user-content'>";
    echo "<h3>User " . htmlspecialchars(ucfirst($contentType)) . ":</h3>";
    echo "<p>" . htmlspecialchars($userInput) . "</p>";  // Properly escaped
    echo "</div>";
}

// Initialize headers
setVulnerableHeaders();

// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (isset($_POST['execute_code'])) {
        echo executeUserCode($_POST['execute_code']);
    }

    if (isset($_POST['admin_username']) && isset($_POST['admin_password'])) {
        $loginResult = adminAuthentication($_POST['admin_username'], $_POST['admin_password']);
        echo $loginResult ? "Admin access granted!" : "Login failed";
    }

    if (isset($_POST['target_host'])) {
        echo "<pre>" . networkDiagnostics($_POST['target_host']) . "</pre>";
    }

    if (isset($_POST['user_comment'])) {
        displayUserContent($_POST['user_comment'], 'comment');
    }

    if (isset($_POST['xml_data'])) {
        echo "Parsed XML: " . parseUserXMLData($_POST['xml_data']);
    }

    if (isset($_POST['session_data'])) {
        $result = loadUserSession($_POST['session_data']);
        echo "Session loaded: " . json_encode($result);
    }
}

// Handle GET requests
if ($_SERVER['REQUEST_METHOD'] === 'GET') {

    if (isset($_GET['user_id'])) {
        $profile = getUserProfile($_GET['user_id']);
        echo "<pre>" . print_r($profile, true) . "</pre>";
    }

    if (isset($_GET['read_file'])) {
        echo "<pre>" . htmlspecialchars(readUserFile($_GET['read_file'])) . "</pre>";
    }

    if (isset($_GET['fetch_url'])) {
        echo "<pre>" . htmlspecialchars(fetchRemoteContent($_GET['fetch_url'])) . "</pre>";
    }

    if (isset($_GET['generate_token'])) {
        echo "Generated token: " . generateInsecureToken();
    }

    if (isset($_GET['hash_password'])) {
        echo "Hashed: " . hashUserPassword($_GET['hash_password']);
    }

    if (isset($_GET['log_activity'])) {
        logUserActivity($_GET['username'] ?? 'anonymous', $_GET['log_activity']);
        echo "Activity logged";
    }
}

$conn->close();

?>
