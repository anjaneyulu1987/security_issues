Here's the complete corrected file content with all security vulnerabilities fixed:

```php
<?php

// Security-hardened command execution demo
// Only allow specific whitelisted commands for demonstration purposes

// Define a whitelist of allowed commands (very restrictive for security)
$allowed_commands = [
    'ls' => 'ls -la',
    'date' => 'date',
    'whoami' => 'whoami',
    'pwd' => 'pwd'
];

// Check if a 'command' parameter was passed via GET
if (isset($_GET['command'])) {
    // Retrieve and sanitize user-supplied input
    $user_input = trim($_GET['command']);
    
    // Validate against whitelist - only allow predefined commands
    if (array_key_exists($user_input, $allowed_commands)) {
        // Use the predefined command from whitelist (no user input in actual command)
        $safe_command = $allowed_commands[$user_input];
        
        // Execute the whitelisted command
        $output = shell_exec($safe_command . ' 2>&1');
        
        // Sanitize output to prevent XSS attacks
        $safe_output = htmlspecialchars($output ?? '', ENT_QUOTES, 'UTF-8');
        
        // Display the sanitized output
        echo "<pre>" . $safe_output . "</pre>";
    } else {
        // Invalid command - display error message with XSS protection
        echo "<div style='color: red;'>";
        echo "<strong>Error:</strong> Invalid command. Only the following commands are allowed: ";
        echo htmlspecialchars(implode(', ', array_keys($allowed_commands)), ENT_QUOTES, 'UTF-8');
        echo "</div>";
    }
} else {
    // Safe instruction display with proper HTML encoding
    echo "<h1>Secure Command Execution Demo</h1>";
    echo "<p>To test, append a 'command' query parameter to the URL with one of the allowed commands:</p>";
    echo "<ul>";
    foreach ($allowed_commands as $key => $description) {
        $safe_key = htmlspecialchars($key, ENT_QUOTES, 'UTF-8');
        echo "<li><code>?command=" . $safe_key . "</code></li>";
    }
    echo "</ul>";
    echo "<p><strong>Note:</strong> Only whitelisted commands are allowed for security reasons.</p>";
}

?>
```

## Security Fixes Applied:

### 1. **Command Injection Fix (Line 10)**:
- **Implemented Command Whitelisting**: Instead of allowing arbitrary user input to be executed, only predefined commands from a whitelist are permitted.
- **Input Validation**: User input is validated against the whitelist before any command execution.
- **No Direct User Input in Commands**: The actual commands executed are predefined strings, not user-supplied input.
- **Error Handling**: Invalid commands are rejected with appropriate error messages.

### 2. **Cross-Site Scripting (XSS) Fix (Line 13)**:
- **Output Encoding**: All user-controlled data and command output is properly encoded using `htmlspecialchars()` with `ENT_QUOTES` and `UTF-8` encoding.
- **Safe Error Messages**: Error messages containing user input are properly sanitized.
- **Protected Instructions**: Even the instruction text uses proper HTML encoding where dynamic content is displayed.

### 3. **Additional Security Improvements**:
- **Input Sanitization**: User input is trimmed to remove whitespace.
- **Null Coalescing**: Protected against null returns from `shell_exec()`.
- **Stderr Capture**: Added `2>&1` to capture error output safely.
- **Restrictive Whitelist**: Only safe, read-only commands are allowed in the example.

This implementation follows the principle of "defense in depth" by applying multiple layers of security controls to prevent both command injection and XSS attacks.