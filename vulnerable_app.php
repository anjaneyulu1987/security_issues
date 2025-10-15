Here's the complete corrected file content with all security vulnerabilities fixed:

```php
<?php

// Define allowed commands for security
$allowed_commands = [
    'ls' => 'ls -la',
    'date' => 'date',
    'whoami' => 'whoami',
    'pwd' => 'pwd'
];

// Check if a 'command' parameter was passed via GET
if (isset($_GET['command'])) {
    // Retrieve and sanitize user-supplied input
    $user_command = trim($_GET['command']);
    
    // Validate against whitelist of allowed commands
    if (array_key_exists($user_command, $allowed_commands)) {
        // Use the predefined safe command from whitelist
        $safe_command = $allowed_commands[$user_command];
        
        // Execute the validated command
        $output = shell_exec(escapeshellcmd($safe_command));
        
        // Sanitize output before displaying to prevent XSS
        $safe_output = htmlspecialchars($output, ENT_QUOTES, 'UTF-8');
        
        // Display the sanitized output
        echo "<pre>" . $safe_output . "</pre>";
    } else {
        // Display error for invalid command
        echo "<div style='color: red;'>Error: Command not allowed. Please use one of the following commands: " . 
             htmlspecialchars(implode(', ', array_keys($allowed_commands)), ENT_QUOTES, 'UTF-8') . "</div>";
    }
} else {
    // Safe instruction display
    echo "<h1>Secure Command Execution Demo</h1>";
    echo "<p>Available commands:</p>";
    echo "<ul>";
    foreach (array_keys($allowed_commands) as $cmd) {
        $safe_cmd = htmlspecialchars($cmd, ENT_QUOTES, 'UTF-8');
        echo "<li><a href='?command=" . urlencode($cmd) . "'>" . $safe_cmd . "</a></li>";
    }
    echo "</ul>";
    echo "<p>Only predefined safe commands are allowed for security purposes.</p>";
}

?>
```

## Security Fixes Applied:

### 1. **Command Injection Prevention (Line 10)**:
- **Whitelist Validation**: Implemented a strict whitelist of allowed commands (`$allowed_commands` array)
- **Input Validation**: User input is validated against the whitelist before execution
- **Command Sanitization**: Used `escapeshellcmd()` as an additional layer of protection
- **No Direct User Input**: User input is never directly passed to `shell_exec()`

### 2. **Cross-Site Scripting (XSS) Prevention (Line 13)**:
- **Output Encoding**: All output is properly encoded using `htmlspecialchars()` with `ENT_QUOTES` and `UTF-8` encoding
- **Input Sanitization**: User input displayed in error messages is sanitized
- **URL Encoding**: Command parameters in links are properly URL-encoded using `urlencode()`

### 3. **Additional Security Enhancements**:
- **Error Handling**: Graceful error messages for invalid commands
- **User Experience**: Clear interface showing available commands
- **Input Trimming**: Whitespace is trimmed from user input
- **Comprehensive Sanitization**: All user-controlled data is sanitized before output

### 4. **Security Best Practices Implemented**:
- **Principle of Least Privilege**: Only specific, safe commands are allowed
- **Defense in Depth**: Multiple layers of security (whitelist + sanitization + encoding)
- **Secure by Default**: The application denies everything except explicitly allowed commands
- **Input/Output Sanitization**: All data is properly handled at input and output boundaries

This implementation transforms the vulnerable application into a secure one that prevents both command injection and XSS attacks while maintaining basic functionality in a controlled manner.