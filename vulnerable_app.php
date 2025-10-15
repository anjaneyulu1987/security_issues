Here's the complete corrected file content with all security vulnerabilities fixed:

```php
<?php

// Define a whitelist of allowed commands for security
$allowed_commands = [
    'ls' => 'ls -la',
    'pwd' => 'pwd',
    'date' => 'date',
    'whoami' => 'whoami'
];

// Check if a 'command' parameter was passed via GET
if (isset($_GET['command'])) {
    // Retrieve and sanitize user-supplied input
    $user_command = trim($_GET['command']);
    
    // Validate against whitelist to prevent command injection
    if (array_key_exists($user_command, $allowed_commands)) {
        // Execute only pre-approved commands
        $safe_command = $allowed_commands[$user_command];
        $output = shell_exec($safe_command . ' 2>&1'); // Capture stderr as well
        
        // Sanitize output to prevent XSS
        $safe_output = htmlspecialchars($output, ENT_QUOTES, 'UTF-8');
        
        // Display the sanitized output
        echo "<pre>" . $safe_output . "</pre>";
        
        // Log the executed command for security monitoring
        error_log("Command executed: " . $safe_command . " by IP: " . $_SERVER['REMOTE_ADDR']);
        
    } else {
        // Invalid command - display error message
        echo "<div style='color: red; font-weight: bold;'>Error: Command not allowed.</div>";
        echo "<p>Allowed commands: " . htmlspecialchars(implode(', ', array_keys($allowed_commands)), ENT_QUOTES, 'UTF-8') . "</p>";
        
        // Log security violation attempt
        error_log("Security violation - Invalid command attempted: " . $user_command . " by IP: " . $_SERVER['REMOTE_ADDR']);
    }
} else {
    // Safe instruction display with proper HTML encoding
    echo "<h1>Command Execution Demo</h1>";
    echo "<p>To test, append a 'command' query parameter to the URL.<br>";
    echo "Allowed commands: " . htmlspecialchars(implode(', ', array_keys($allowed_commands)), ENT_QUOTES, 'UTF-8') . "<br>";
    echo "For example: <code>?command=ls</code></p>";
}

?>
```

## Security Fixes Applied:

### 1. **Command Injection Prevention (Line 10)**:
- **Whitelist Approach**: Implemented a strict whitelist of allowed commands instead of accepting arbitrary user input
- **Input Validation**: Added validation to ensure only pre-approved commands can be executed
- **Safe Command Mapping**: User input is mapped to predefined safe commands, eliminating the possibility of command injection
- **Error Handling**: Invalid commands are rejected with appropriate error messages
- **Security Logging**: Added logging for both successful executions and violation attempts

### 2. **Cross-Site Scripting (XSS) Prevention (Line 13)**:
- **Output Encoding**: Used `htmlspecialchars()` with `ENT_QUOTES` and `UTF-8` encoding to sanitize all output before displaying
- **Comprehensive Sanitization**: Applied HTML encoding to all user-controlled data that gets rendered in the browser
- **Safe Error Messages**: Even error messages and allowed command lists are properly encoded

### 3. **Additional Security Enhancements**:
- **Input Trimming**: Added `trim()` to remove whitespace that could be used in bypass attempts
- **Error Capture**: Added `2>&1` to capture stderr output safely
- **Security Monitoring**: Implemented logging for security monitoring and incident response
- **IP Tracking**: Added IP address logging for security violation attempts

### 4. **Defense in Depth**:
- Multiple layers of protection ensure that even if one control fails, others will prevent exploitation
- The whitelist approach is the most secure method for this type of functionality
- All output is properly encoded regardless of its source

This implementation completely eliminates both the Command Injection and XSS vulnerabilities while maintaining the basic functionality of the application in a secure manner.