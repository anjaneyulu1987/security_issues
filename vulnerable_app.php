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

// CRITICAL 1: Remote Code Execution via eval()
function executeUserCode($input) {
    $result = eval($input);  // Critical: Direct code execution
    return "Code executed: " . $result;
}

// CRITICAL 2: Command Injection
function networkDiagnostics($hostname) {
    $command = "ping -c 3 " . $hostname;
    $output = shell_exec($command);  // Critical: Command injection
    return $output;
}

// HIGH VULNERABILITIES (4 total)

// HIGH 1: SQL Injection in authentication
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

// HIGH 2: File Inclusion vulnerability
function handleFileUpload($uploadedFile) {
    $uploadDir = "uploads/";
    $fileName = $uploadedFile['name'];

    if (!file_exists($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    $targetPath = $uploadDir . $fileName;
    move_uploaded_file($uploadedFile['tmp_name'], $targetPath);

    if (pathinfo($fileName, PATHINFO_EXTENSION) == 'php') {
        include($targetPath);  // High: File inclusion
    }

    return "File uploaded successfully: " . $targetPath;
}

// HIGH 3: Cross-Site Scripting (XSS)
function displayUserContent($userInput, $contentType = 'comment') {
    echo "<div class='user-content'>";
    echo "<h3>User " . ucfirst($contentType) . ":</h3>";
    echo "<p>" . $userInput . "</p>";  // High: XSS vulnerability
    echo "</div>";
}

// HIGH 4: XXE (XML External Entity) vulnerability
function parseUserXMLData($xmlString) {
    $dom = new DOMDocument();
    $dom->loadXML($xmlString, LIBXML_NOENT | LIBXML_DTDLOAD);  // High: XXE vulnerability
    return $dom->textContent;
}

// MEDIUM VULNERABILITIES (1 total)

// MEDIUM 1: Path Traversal vulnerability
function readSystemFile($filename) {
    $basePath = "/var/log/";
    $fullPath = $basePath . $filename;  // Medium: Path traversal - no sanitization

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

// LOW 2: Insecure random number generation
function generateInsecureToken() {
    $randomPart = rand(1000, 9999);  // Low: Weak random number generation
    return md5(time() . $randomPart);  // Low: Weak hash algorithm
}

// LOW 3: Information disclosure in headers
function setVulnerableHeaders() {
    header('Server: Apache/2.4.1 (Vulnerable-Server)');  // Low: Information disclosure
    header('X-Powered-By: PHP/' . phpversion());
}

// LOW 4: Credentials stored in plain text
function storeUserCredentials($username, $password, $apiKey) {
    $credentials = "USERNAME=" . $username . "\n";
    $credentials .= "PASSWORD=" . $password . "\n";  // Low: Plain text password storage
    $credentials .= "API_KEY=" . $apiKey . "\n";
    file_put_contents('user_credentials.txt', $credentials, FILE_APPEND);
    return "Credentials stored successfully";
}

// LOW 5: Weak session validation
function validateUserSession($sessionId) {
    if (strlen($sessionId) < 5) {  // Low: Weak session validation
        return true;  // Any short session ID is valid
    }
    return false;
}

// LOW 6: Debug information exposure
function getDebugInfo() {
    return array(
        'database_password' => $GLOBALS['password'],  // Low: Information disclosure
        'php_version' => phpversion(),
        'server_info' => $_SERVER
    );
}

// Safe utility functions (no vulnerabilities)
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

function readUserFile($filename) {
    $basePath = "user_files/";
    $safeFilename = basename($filename); // Sanitize filename
    $fullPath = $basePath . $safeFilename;

    if (file_exists($fullPath) && is_file($fullPath)) {
        return file_get_contents($fullPath);
    }
    return "File not found";
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

    if (isset($_FILES['malicious_file'])) {
        echo handleFileUpload($_FILES['malicious_file']);
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

    if (isset($_GET['debug_info'])) {
        echo "<pre>" . print_r(getDebugInfo(), true) . "</pre>";
    }

    if (isset($_GET['store_credentials'])) {
        $result = storeUserCredentials($_GET['username'], $_GET['password'], $_GET['api_key']);
        echo $result;
    }

    if (isset($_GET['read_system_file'])) {
        echo "<pre>" . htmlspecialchars(readSystemFile($_GET['read_system_file'])) . "</pre>";
    }
}

$conn->close();

?>
