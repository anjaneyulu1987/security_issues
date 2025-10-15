Here's the complete corrected file content with all security vulnerabilities fixed:

```php
<?php
session_start();

// CSRF token generation and validation
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Whitelist of allowed commands for security
$allowedCommands = [
    'ls' => 'ls -la',
    'date' => 'date',
    'whoami' => 'whoami',
    'pwd' => 'pwd'
];

// Function to safely execute whitelisted commands
function executeAllowedCommand($commandKey) {
    global $allowedCommands;
    
    if (!array_key_exists($commandKey, $allowedCommands)) {
        return "Error: Command not allowed";
    }
    
    $command = $allowedCommands[$commandKey];
    
    // Additional security: use escapeshellcmd as extra protection
    $command = escapeshellcmd($command);
    
    // Execute with proper error handling
    $output = shell_exec($command . ' 2>&1');
    
    return $output !== null ? $output : "Command execution failed";
}

// Function to safely output HTML content
function safeOutput($content) {
    return htmlspecialchars($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// Check if a 'command' parameter was passed via POST (changed from GET for better security)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['command']) && isset($_POST['csrf_token'])) {
    
    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'])) {
        die("Error: Invalid CSRF token");
    }
    
    // Retrieve and validate user input
    $commandKey = trim($_POST['command']);
    
    // Input validation: only allow alphanumeric characters and underscores
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $commandKey)) {
        $errorMessage = "Error: Invalid command format";
    } else {
        // Execute the whitelisted command safely
        $output = executeAllowedCommand($commandKey);
    }
    
    // Display the output with proper HTML encoding to prevent XSS
    if (isset($output)) {
        echo "<h2>Command Output:</h2>";
        echo "<pre>" . safeOutput($output) . "</pre>";
    } else {
        echo "<p style='color: red;'>" . safeOutput($errorMessage) . "</p>";
    }
    
    echo "<hr>";
}

// Safe instruction display with CSRF protection
echo "<h1>Secure Command Execution Demo</h1>";
echo "<p>Select a command to execute:</p>";

echo "<form method='POST' action=''>";
echo "<input type='hidden' name='csrf_token' value='" . safeOutput($_SESSION['csrf_token']) . "'>";
echo "<select name='command' required>";
echo "<option value=''>-- Select Command --</option>";

// Generate safe options from whitelist
foreach ($allowedCommands as $key => $description) {
    $safeKey = safeOutput($key);
    $safeDesc = safeOutput($description);
    echo "<option value='$safeKey'>$safeDesc</option>";
}

echo "</select><br><br>";
echo "<input type='submit' value='Execute Command'>";
echo "</form>";

echo "<h3>Security Features Implemented:</h3>";
echo "<ul>";
echo "<li>Command whitelist - only predefined safe commands allowed</li>";
echo "<li>Input validation and sanitization</li>";
echo "<li>Output encoding to prevent XSS</li>";
echo "<li>CSRF token protection</li>";
echo "<li>POST method instead of GET for command execution</li>";
echo "<li>Proper error handling</li>";
echo "</ul>";

?>
```

## Security Fixes Applied:

### 1. **Command Injection Prevention (Line 10 fix):**
- **Implemented command whitelist**: Only predefined, safe commands are allowed
- **Input validation**: Using regex to validate command format
- **Removed direct user input to shell_exec**: User can only select from approved commands
- **Added escapeshellcmd()**: Extra layer of protection for command execution
- **Changed from GET to POST**: Better security practice for command execution

### 2. **Cross-Site Scripting (XSS) Prevention (Line 13 fix):**
- **HTML encoding**: All output is properly encoded using `htmlspecialchars()`
- **Safe output function**: Created `safeOutput()` function with proper encoding flags
- **Input sanitization**: All user inputs are validated and encoded before display

### 3. **Additional Security Enhancements:**
- **CSRF Protection**: Added token-based CSRF protection
- **Session Security**: Proper session handling
- **Error Handling**: Safe error messages without information disclosure
- **Input Method**: Changed from GET to POST for better security
- **Form-based Interface**: Replaced URL parameter with secure form submission

### 4. **Security Configuration:**
- **ENT_QUOTES | ENT_HTML5**: Comprehensive HTML encoding
- **UTF-8 encoding**: Proper character encoding
- **hash_equals()**: Timing-safe CSRF token comparison
- **random_bytes()**: Cryptographically secure random token generation

This implementation completely eliminates both command injection and XSS vulnerabilities while maintaining functionality through a secure, whitelist-based approach.