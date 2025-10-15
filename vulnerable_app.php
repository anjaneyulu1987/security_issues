Here's the complete corrected file content with all security vulnerabilities fixed:

```php
<?php
session_start();

// CSRF Token generation and validation
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Input validation and sanitization functions
function validateCommand($command) {
    // Whitelist of allowed commands - only allow safe, predefined commands
    $allowedCommands = [
        'date' => 'date',
        'uptime' => 'uptime',
        'whoami' => 'whoami',
        'pwd' => 'pwd',
        'ls' => 'ls -la',
        'df' => 'df -h'
    ];
    
    return isset($allowedCommands[$command]) ? $allowedCommands[$command] : false;
}

function sanitizeOutput($output) {
    // Escape HTML special characters to prevent XSS
    return htmlspecialchars($output, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// Generate CSRF token for the form
$csrfToken = generateCSRFToken();

// Check if a 'command' parameter was passed via POST (changed from GET for better security)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['command']) && isset($_POST['csrf_token'])) {
    
    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'])) {
        die('<div style="color: red; font-weight: bold;">Security Error: Invalid CSRF token</div>');
    }
    
    // Retrieve and trim user input
    $userCommand = trim($_POST['command']);
    
    // Validate the command against whitelist
    $validatedCommand = validateCommand($userCommand);
    
    if ($validatedCommand === false) {
        echo '<div style="color: red; font-weight: bold;">Error: Command not allowed. Please select from the available options.</div>';
    } else {
        // Execute only the validated command with proper error handling
        $output = shell_exec($validatedCommand . ' 2>&1');
        
        if ($output === null) {
            echo '<div style="color: red;">Error: Command execution failed.</div>';
        } else {
            // Sanitize output before displaying to prevent XSS
            $sanitizedOutput = sanitizeOutput($output);
            echo "<h3>Command Output:</h3>";
            echo "<pre style='background-color: #f4f4f4; padding: 10px; border: 1px solid #ddd;'>" . $sanitizedOutput . "</pre>";
        }
    }
    
    echo "<hr>";
}

// Display the secure form interface
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Command Execution Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .form-group { margin: 15px 0; }
        select, button { padding: 8px; font-size: 14px; }
        button { background-color: #007cba; color: white; border: none; cursor: pointer; }
        button:hover { background-color: #005a87; }
        .info { background-color: #e7f3ff; padding: 15px; border-left: 4px solid #007cba; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>Secure Command Execution Demo</h1>
    
    <div class="info">
        <strong>Security Notice:</strong> This application only allows execution of predefined, safe commands to prevent security vulnerabilities.
    </div>
    
    <form method="POST" action="">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
        
        <div class="form-group">
            <label for="command"><strong>Select a command to execute:</strong></label><br>
            <select name="command" id="command" required>
                <option value="">-- Choose a command --</option>
                <option value="date">Show current date and time</option>
                <option value="uptime">Show system uptime</option>
                <option value="whoami">Show current user</option>
                <option value="pwd">Show current directory</option>
                <option value="ls">List directory contents</option>
                <option value="df">Show disk usage</option>
            </select>
        </div>
        
        <div class="form-group">
            <button type="submit">Execute Command</button>
        </div>
    </form>
    
    <div class="info">
        <h3>Security Measures Implemented:</h3>
        <ul>
            <li><strong>Command Injection Prevention:</strong> Input validation with command whitelisting</li>
            <li><strong>XSS Prevention:</strong> Output sanitization using htmlspecialchars()</li>
            <li><strong>CSRF Protection:</strong> CSRF tokens to prevent cross-site request forgery</li>
            <li><strong>Input Method:</strong> Changed from GET to POST for better security</li>
            <li><strong>Error Handling:</strong> Proper error messages without exposing system information</li>
        </ul>
    </div>
</body>
</html>
```

## Key Security Fixes Applied:

### 1. **Command Injection Prevention (Line 10 vulnerability):**
- **Whitelisting approach**: Only predefined, safe commands are allowed
- **Input validation**: `validateCommand()` function checks against allowed commands
- **No direct user input**: User input is validated before any shell execution
- **Error handling**: Invalid commands are rejected with appropriate error messages

### 2. **XSS Prevention (Line 13 vulnerability):**
- **Output sanitization**: All output is passed through `htmlspecialchars()` with proper flags
- **HTML encoding**: Special characters are encoded to prevent script injection
- **Safe rendering**: Output is properly escaped before being displayed in HTML

### 3. **Additional Security Enhancements:**
- **CSRF Protection**: Implemented CSRF tokens to prevent cross-site request forgery
- **Method change**: Changed from GET to POST for better security practice
- **Session security**: Proper session handling for CSRF token management
- **Input validation**: Comprehensive input validation and sanitization
- **Error handling**: Secure error messages that don't expose system information
- **User interface**: Dropdown selection instead of free-text input to limit attack surface

### 4. **Security Functions:**
- `validateCommand()`: Validates input against whitelist of safe commands
- `sanitizeOutput()`: Sanitizes output to prevent XSS attacks
- `generateCSRFToken()` & `validateCSRFToken()`: CSRF protection mechanisms

This implementation transforms a highly vulnerable application into a secure one while maintaining functionality through a controlled, whitelist-based approach.