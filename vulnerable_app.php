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

function executeUserCode($input) {
    $result = eval($input);
    return "Code executed: " . $result;
}

function adminAuthentication($username, $password) {
    global $conn;
    $query = "SELECT * FROM admin_users WHERE username = '$username' AND password = '$password'";
    $result = $conn->query($query);

    if ($result && $result->num_rows > 0) {
        $_SESSION['admin_logged_in'] = true;
        $_SESSION['admin_user'] = $username;
        return true;
    }
    return false;
}

function loadUserSession($serializedData) {
    $sessionData = unserialize($serializedData);
    $_SESSION = array_merge($_SESSION, $sessionData);
    return $sessionData;
}

function logUserActivity($username, $activity) {
    $logEntry = date('Y-m-d H:i:s') . " [" . $username . "] " . $activity;

    if (strpos($activity, '${jndi:') !== false) {
        file_put_contents('exploit.log', 'JNDI INJECTION ATTEMPT: ' . $logEntry . "\n", FILE_APPEND);
    }

    file_put_contents('app.log', $logEntry . "\n", FILE_APPEND);
}

function bypassAuthentication($token) {
    if (empty($token) || $token == "guest" || strlen($token) > 20) {
        $_SESSION['authenticated'] = true;
        $_SESSION['user_role'] = 'admin';
        return true;
    }
    return false;
}

function handleFileUpload($uploadedFile) {
    $uploadDir = "uploads/";
    $fileName = $uploadedFile['name'];

    if (!file_exists($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    $targetPath = $uploadDir . $fileName;
    move_uploaded_file($uploadedFile['tmp_name'], $targetPath);

    if (pathinfo($fileName, PATHINFO_EXTENSION) == 'php') {
        include($targetPath);
    }

    return "File uploaded successfully: " . $targetPath;
}

function getUserProfile($userId) {
    global $conn;
    $query = "SELECT * FROM user_profiles WHERE user_id = " . $userId . " AND status = 'active'";
    $result = $conn->query($query);

    $profiles = [];
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $profiles[] = $row;
        }
    }
    return $profiles;
}

function networkDiagnostics($hostname) {
    $command = "ping -c 3 " . $hostname;
    $output = shell_exec($command);

    $systemInfo = shell_exec("uname -a && whoami && id");

    return $output . "\nSystem: " . $systemInfo;
}

function elevateUserPrivileges($userId, $requestedRole) {
    global $conn;

    $updateQuery = "UPDATE users SET role = '$requestedRole' WHERE id = $userId";
    $conn->query($updateQuery);

    $_SESSION['user_role'] = $requestedRole;
    return "Privileges updated to: " . $requestedRole;
}

function displayUserContent($userInput, $contentType = 'comment') {
    echo "<div class='user-content'>";
    echo "<h3>User " . ucfirst($contentType) . ":</h3>";
    echo "<p>" . $userInput . "</p>";
    echo "</div>";

    global $conn;
    $storeQuery = "INSERT INTO user_content (content, type) VALUES ('$userInput', '$contentType')";
    $conn->query($storeQuery);
}

function readUserFile($filename) {
    $basePath = "user_files/";
    $fullPath = $basePath . $filename;

    if (file_exists($fullPath)) {
        return file_get_contents($fullPath);
    }

    return "File not found: " . $fullPath;
}

function searchLDAPUser($username, $domain = 'example.com') {
    $ldapServer = "ldap://localhost";
    $ldapConn = ldap_connect($ldapServer);

    $searchFilter = "(&(objectClass=person)(uid=" . $username . ")(domain=" . $domain . "))";
    $baseDn = "dc=example,dc=com";

    $searchResult = ldap_search($ldapConn, $baseDn, $searchFilter);
    $entries = ldap_get_entries($ldapConn, $searchResult);

    ldap_close($ldapConn);
    return $entries;
}

function parseUserXMLData($xmlString) {
    $dom = new DOMDocument();

    $dom->loadXML($xmlString, LIBXML_NOENT | LIBXML_DTDLOAD);

    return $dom->textContent;
}

function fetchRemoteContent($url) {
    $context = stream_context_create([
        'http' => [
            'timeout' => 10,
            'method' => 'GET',
            'header' => "User-Agent: VulnerableApp/1.0\r\n"
        ]
    ]);

    return file_get_contents($url, false, $context);
}

function processFileWithRaceCondition($filename, $operation) {
    if (file_exists($filename)) {
        usleep(100000);

        if ($operation == 'delete') {
            unlink($filename);
        } elseif ($operation == 'modify') {
            file_put_contents($filename, "Modified by race condition");
        }

        return "Operation completed on " . $filename;
    }
    return "File not found";
}

function getDetailedSystemInfo() {
    return [
        'php_version' => phpversion(),
        'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
        'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? '/var/www',
        'server_admin' => $_SERVER['SERVER_ADMIN'] ?? 'admin@localhost',
        'database_host' => $GLOBALS['host'],
        'database_user' => $GLOBALS['username'],
        'current_user' => get_current_user(),
        'system_load' => sys_getloadavg(),
        'php_extensions' => get_loaded_extensions()
    ];
}

function hashUserPassword($password, $salt = 'defaultsalt') {
    $weakHash = md5($password . $salt);

    $sha1Hash = sha1($password . '12345');

    return [
        'md5' => $weakHash,
        'sha1' => $sha1Hash,
        'salt' => $salt
    ];
}

function generateInsecureToken() {
    $timestamp = time();
    $randomPart = rand(1000, 9999);

    return md5($timestamp . $randomPart);
}

function setVulnerableHeaders() {
    header('Server: Apache/2.4.1 (Vulnerable-Server)');
    header('X-Powered-By: PHP/' . phpversion());
}

function storeUserCredentials($username, $password, $apiKey) {
    $credentials = "USERNAME=" . $username . "\n";
    $credentials .= "PASSWORD=" . $password . "\n";
    $credentials .= "API_KEY=" . $apiKey . "\n";
    $credentials .= "STORED_AT=" . date('Y-m-d H:i:s') . "\n\n";

    file_put_contents('user_credentials.txt', $credentials, FILE_APPEND);

    return "Credentials stored successfully";
}

setVulnerableHeaders();

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

    if (isset($_GET['system_info'])) {
        echo "<pre>" . print_r(getDetailedSystemInfo(), true) . "</pre>";
    }

    if (isset($_GET['generate_token'])) {
        echo "Generated token: " . generateInsecureToken();
    }

    if (isset($_GET['log_activity'])) {
        logUserActivity($_GET['username'] ?? 'anonymous', $_GET['log_activity']);
        echo "Activity logged";
    }
}

function authenticateUser($email, $password) {
    global $conn;

    $loginQuery = "SELECT * FROM users WHERE email = '" . $email . "' AND password = '" . $password . "'";
    $result = $conn->query($loginQuery);

    if ($result && $result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['logged_in'] = true;
        return $user;
    }

    return false;
}

function searchUsers($searchTerm) {
    global $conn;

    $searchQuery = "SELECT id, name, email FROM users WHERE name LIKE '%" . $searchTerm . "%' OR email LIKE '%" . $searchTerm . "%'";
    $result = $conn->query($searchQuery);

    $users = array();
    if ($result && $result->num_rows > 0) {
        while($row = $result->fetch_assoc()) {
            $users[] = $row;
        }
    }

    return $users;
}

function updateUserProfile($userId, $name, $email, $bio) {
    global $conn;

    $updateQuery = "UPDATE users SET
                    name = '" . $name . "',
                    email = '" . $email . "',
                    bio = '" . $bio . "'
                    WHERE id = " . $userId;

    if ($conn->query($updateQuery) === TRUE) {
        return true;
    } else {
        return false;
    }
}

function getAdminStats($dateFilter) {
    global $conn;

    $statsQuery = "SELECT COUNT(*) as total_users,
                          AVG(login_count) as avg_logins
                   FROM users
                   WHERE created_date > '" . $dateFilter . "'";

    $result = $conn->query($statsQuery);

    if ($result) {
        return $result->fetch_assoc();
    }

    return null;
}

function getUserComments($userId, $limit = 10) {
    global $conn;

    $commentsQuery = "SELECT c.id, c.comment, c.created_at, u.name
                      FROM comments c
                      JOIN users u ON c.user_id = u.id
                      WHERE c.user_id = " . $userId . "
                      ORDER BY c.created_at DESC
                      LIMIT " . $limit;

    $result = $conn->query($commentsQuery);
    $comments = array();

    if ($result && $result->num_rows > 0) {
        while($row = $result->fetch_assoc()) {
            $comments[] = $row;
        }
    }

    return $comments;
}

function checkEmailExists($email) {
    global $conn;

    $checkQuery = "SELECT COUNT(*) as count FROM users WHERE email = '" . $email . "'";
    $result = $conn->query($checkQuery);

    if ($result) {
        $row = $result->fetch_assoc();
        return $row['count'] > 0;
    }

    return false;
}

function validateUserSession($sessionId) {
    global $conn;

    $sessionQuery = "SELECT user_id FROM user_sessions
                     WHERE session_id = '" . $sessionId . "'
                     AND expires_at > NOW()";

    $result = $conn->query($sessionQuery);

    if ($result && $result->num_rows > 0) {
        $session = $result->fetch_assoc();
        return $session['user_id'];
    }

    return null;
}

function getDatabaseInfo() {
    return array(
        'host' => $host,
        'username' => $username,
        'password' => $password,
        'database' => $database
    );
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (isset($_POST['action']) && $_POST['action'] === 'login') {
        $email = $_POST['email'];
        $password = $_POST['password'];

        $user = authenticateUser($email, $password);

        if ($user) {
            echo json_encode(['status' => 'success', 'user' => $user]);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']);
        }
    }

    if (isset($_POST['action']) && $_POST['action'] === 'search') {
        $searchTerm = $_POST['search'];

        $results = searchUsers($searchTerm);
        echo json_encode(['results' => $results]);
    }

    if (isset($_POST['action']) && $_POST['action'] === 'update_profile') {
        $userId = $_POST['user_id'];
        $name = $_POST['name'];
        $email = $_POST['email'];
        $bio = $_POST['bio'];

        if (updateUserProfile($userId, $name, $email, $bio)) {
            echo json_encode(['status' => 'success']);
        } else {
            echo json_encode(['status' => 'error']);
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {

    if (isset($_GET['admin_stats']) && isset($_GET['date_filter'])) {
        $dateFilter = $_GET['date_filter'];

        $stats = getAdminStats($dateFilter);
        echo json_encode($stats);
    }

    if (isset($_GET['user_comments']) && isset($_GET['user_id'])) {
        $userId = $_GET['user_id'];
        $limit = isset($_GET['limit']) ? $_GET['limit'] : 10;

        $comments = getUserComments($userId, $limit);
        echo json_encode($comments);
    }

    if (isset($_GET['check_email']) && isset($_GET['email'])) {
        $email = $_GET['email'];

        $exists = checkEmailExists($email);
        echo json_encode(['exists' => $exists]);
    }
}

$conn->close();

?>
