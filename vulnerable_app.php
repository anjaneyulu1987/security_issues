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
    // Retrieve user-supplied input and sanitize it
    $user_command = trim($_GET['command']);
    
    // Validate against whitelist to prevent command injection
    if (array_key_exists($user_command, $allowed_commands)) {
        // Use the predefined safe command from whitelist
        $safe_command = $allowed_commands[$user_command];
        
        // Execute only the whitelisted command
        $output = shell_exec(escapeshellcmd($safe_command));
        
        // Sanitize output to prevent XSS attacks
        $safe_output = htmlspecialchars($output, ENT_QUOTES, 'UTF-8');
        
        // Display the sanitized output
        echo "<pre>" . $safe_output . "</pre>";
    } else {
        // Display error message for invalid commands (also XSS-safe)
        echo "<div style='color: red;'>";
        echo "<strong>Error:</strong> Command not allowed. ";
        echo "Allowed commands: " . implode(', ', array_keys($allowed_commands));
        echo "</div>";
    }
} else {
    // Safe instruction display
    echo "<h1>Secure Command Execution Demo</h1>";
    echo "<p>To test, append a 'command' query parameter to the URL.<br>";
    echo "Allowed commands:</p>";
    echo "<ul>";
    foreach (array_keys($allowed_commands) as $cmd) {
        // Escape command names to prevent any potential XSS
        $safe_cmd = htmlspecialchars($cmd, ENT_QUOTES, 'UTF-8');
        echo "<li><code>?command=" . $safe_cmd . "</code></li>";
    }
    echo "</ul>";
}

?>
```

## Security Fixes Applied:

### 1. Command Injection Prevention (Line 10):
- **Implemented command whitelisting**: Only predefined, safe commands are allowed
- **Input validation**: User input is checked against the whitelist before execution
- **Used `escapeshellcmd()`**: Additional layer of protection for shell command execution
- **Eliminated direct user input to shell**: User input never directly reaches the shell execution

### 2. Cross-Site Scripting (XSS) Prevention (Line 13):
- **Used `htmlspecialchars()`**: All output is properly escaped before rendering
- **Specified encoding**: UTF-8 encoding explicitly set
- **Used `ENT_QUOTES` flag**: Both single and double quotes are escaped
- **Applied to all user-influenced output**: Both command output and error messages are sanitized

### Additional Security Improvements:
- **Input trimming**: Removes whitespace that could be used for bypassing
- **Error handling**: Provides user-friendly error messages without exposing system information
- **Principle of least privilege**: Only specific, safe commands are executable
- **Defense in depth**: Multiple security layers implemented

This solution completely eliminates both the command injection and XSS vulnerabilities while maintaining the application's functionality in a secure manner.