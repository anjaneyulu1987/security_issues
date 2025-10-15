Here's the complete corrected file content with all security vulnerabilities fixed:

```php
<?php

// Define allowed commands as a whitelist for security
$allowed_commands = [
    'ls' => 'ls -la',
    'date' => 'date',
    'whoami' => 'whoami',
    'pwd' => 'pwd'
];

// Check if a 'command' parameter was passed via GET
if (isset($_GET['command'])) {
    // Retrieve user-supplied input
    $user_input = $_GET['command'];
    
    // Input validation: Check if the command is in the allowed list
    if (!array_key_exists($user_input, $allowed_commands)) {
        // Sanitize error message for XSS protection
        $safe_input = htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
        echo "<div style='color: red;'>Error: Command '" . $safe_input . "' is not allowed.</div>";
        echo "<p>Allowed commands: " . implode(', ', array_keys($allowed_commands)) . "</p>";
        exit;
    }
    
    // Use the predefined safe command from whitelist (prevents command injection)
    $safe_command = $allowed_commands[$user_input];
    
    // Execute the whitelisted command
    $output = shell_exec($safe_command);
    
    // Sanitize output to prevent XSS attacks
    $safe_output = htmlspecialchars($output, ENT_QUOTES, 'UTF-8');
    
    // Display the sanitized output
    echo "<h2>Command Output:</h2>";
    echo "<pre>" . $safe_output . "</pre>";
} else {
    // Safe instruction display
    echo "<h1>Secure Command Execution Demo</h1>";
    echo "<p>To test, append a 'command' query parameter to the URL with one of the allowed commands.</p>";
    echo "<p>Allowed commands:</p>";
    echo "<ul>";
    foreach (array_keys($allowed_commands) as $cmd) {
        // Sanitize command names for display
        $safe_cmd = htmlspecialchars($cmd, ENT_QUOTES, 'UTF-8');
        $safe_url_cmd = urlencode($cmd);
        echo "<li><a href='?command=" . $safe_url_cmd . "'>" . $safe_cmd . "</a></li>";
    }
    echo "</ul>";
}

?>
```

## Security Fixes Applied:

### 1. **Command Injection Fix (Line 10)**:
- **Whitelist Approach**: Implemented a strict whitelist of allowed commands (`$allowed_commands` array)
- **Input Validation**: User input is validated against the whitelist before execution
- **No Direct Input Usage**: User input is never directly passed to `shell_exec()`
- **Predefined Commands**: Only predefined, safe commands from the whitelist are executed

### 2. **Cross-Site Scripting (XSS) Fix (Line 13)**:
- **Output Sanitization**: All user input and command output is sanitized using `htmlspecialchars()`
- **Proper Encoding**: Used `ENT_QUOTES` flag and UTF-8 encoding for comprehensive protection
- **Safe Error Messages**: Error messages containing user input are properly escaped
- **URL Encoding**: Command parameters in links are properly URL-encoded

### 3. **Additional Security Enhancements**:
- **Error Handling**: Proper error messages for invalid commands
- **User Experience**: Clear display of allowed commands with clickable links
- **Input Validation**: Comprehensive validation before any processing
- **Defense in Depth**: Multiple layers of security controls

### 4. **Security Principles Applied**:
- **Principle of Least Privilege**: Only specific, necessary commands are allowed
- **Input Validation**: All user input is validated against a whitelist
- **Output Encoding**: All output is properly encoded to prevent XSS
- **Fail Secure**: Default behavior is to deny unauthorized commands

This implementation ensures that both the command injection and XSS vulnerabilities are completely eliminated while maintaining basic functionality in a secure manner.