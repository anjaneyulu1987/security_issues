Here's the complete corrected file content with all security vulnerabilities fixed:

```php
<?php
session_start();

// Enable strict error reporting for security
error_reporting(E_ALL);
ini_set('display_errors', 0); // Don't display errors to users in production

// CSRF Protection
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Function to safely escape output for HTML display
function escapeHtml($string) {
    return htmlspecialchars($string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// Function to validate and sanitize commands
function validateCommand($command) {
    // Whitelist of allowed commands for security
    $allowedCommands = [
        'ls' => 'ls -la',
        'date' => 'date',
        'whoami' => 'whoami',
        'pwd' => 'pwd',
        'uptime' => 'uptime'
    ];
    
    // Check if the command is in our whitelist
    if (array_key_exists(trim($command), $allowedCommands)) {
        return $allowedCommands[trim($command)];
    }
    
    return false;
}

// Check if a 'command' parameter was passed via GET
if (isset($_GET['command']) && isset($_GET['csrf_token'])) {
    
    // CSRF Token validation
    if (!hash_equals($_SESSION['csrf_token'], $_GET['csrf_token'])) {
        die('CSRF token validation failed');
    }
    
    // Retrieve and validate user-supplied input
    $userCommand = trim($_GET['command']);
    
    // Validate the command against whitelist
    $safeCommand = validateCommand($userCommand);
    
    if ($safeCommand !== false) {
        // Execute only the validated command
        // Using escapeshellcmd as additional protection, though whitelist is primary defense
        $sanitizedCommand = escapeshellcmd($safeCommand);
        
        // Execute with additional safety measures
        $output = shell_exec($sanitizedCommand . ' 2>&1'); // Capture stderr too
        
        // Limit output length to prevent potential DoS
        if (strlen($output) > 10000) {
            $output = substr($output, 0, 10000) . "\n[Output truncated...]";
        }
        
        // Safely display the output with proper HTML escaping
        echo "<h1>Command Execution Demo</h1>";
        echo "<div style='background-color: #f0f0f0; padding: 10px; border: 1px solid #ccc;'>";
        echo "<strong>Executed command:</strong> " . escapeHtml($safeCommand) . "<br><br>";
        echo "<strong>Output:</strong><br>";
        echo "<pre>" . escapeHtml($output) . "</pre>";
        echo "</div>";
        
    } else {
        // Command not allowed
        echo "<h1>Command Execution Demo</h1>";
        echo "<div style='color: red; padding: 10px; border: 1px solid red;'>";
        echo "<strong>Error:</strong> Command '" . escapeHtml($userCommand) . "' is not allowed.";
        echo "</div>";
    }
    
} else {
    // Display instructions with CSRF protection
    echo "<h1>Command Execution Demo</h1>";
    echo "<p>This is a secure command execution demo with the following safety measures:</p>";
    echo "<ul>";
    echo "<li>Command whitelist validation</li>";
    echo "<li>CSRF protection</li>";
    echo "<li>XSS protection through output escaping</li>";
    echo "<li>Input sanitization</li>";
    echo "</ul>";
    echo "<p><strong>Allowed commands:</strong> ls, date, whoami, pwd, uptime</p>";
    echo "<p>To test, use one of these formats:</p>";
    echo "<ul>";
    echo "<li><code>?command=ls&csrf_token=" . escapeHtml($_SESSION['csrf_token']) . "</code></li>";
    echo "<li><code>?command=date&csrf_token=" . escapeHtml($_SESSION['csrf_token']) . "</code></li>";
    echo "<li><code>?command=whoami&csrf_token=" . escapeHtml($_SESSION['csrf_token']) . "</code></li>";
    echo "</ul>";
    
    // Display current CSRF token for testing
    echo "<p><small>Current CSRF Token: " . escapeHtml($_SESSION['csrf_token']) . "</small></p>";
}

?>
```

## Security Fixes Implemented:

### 1. **Command Injection Protection (Line 10 vulnerability):**
- **Command Whitelist**: Only predefined, safe commands are allowed
- **Input Validation**: User input is validated against the whitelist before execution
- **escapeshellcmd()**: Additional protection layer for the validated commands
- **Error Handling**: Invalid commands are rejected with safe error messages

### 2. **XSS Protection (Line 13 vulnerability):**
- **HTML Escaping**: All user input and output is properly escaped using `htmlspecialchars()`
- **Dedicated Function**: `escapeHtml()` function ensures consistent escaping throughout the application
- **Output Filtering**: All dynamic content is escaped before being displayed to users

### 3. **Additional Security Enhancements:**
- **CSRF Protection**: Added CSRF tokens to prevent cross-site request forgery
- **Session Security**: Proper session management with secure token generation
- **Output Limiting**: Prevents potential DoS by limiting output length
- **Error Handling**: Secure error reporting that doesn't expose system information
- **Input Sanitization**: Proper trimming and validation of user input

### 4. **Security Best Practices Applied:**
- **Defense in Depth**: Multiple layers of security controls
- **Principle of Least Privilege**: Only specific, necessary commands are allowed
- **Secure by Default**: Safe configuration and conservative security settings
- **Input Validation**: All user input is validated before processing

This implementation transforms a highly vulnerable application into a secure one while maintaining functionality for legitimate use cases.