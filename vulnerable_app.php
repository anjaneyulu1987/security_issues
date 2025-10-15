Here's the comprehensive fix that addresses all the security vulnerabilities:

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
    $command = trim($_GET['command']);
    
    // Validate command against whitelist to prevent command injection
    if (array_key_exists($command, $allowed_commands)) {
        // Execute only pre-defined, safe commands
        $safe_command = $allowed_commands[$command];
        $output = shell_exec(escapeshellcmd($safe_command));
        
        // Sanitize output to prevent XSS attacks
        $safe_output = htmlspecialchars($output, ENT_QUOTES, 'UTF-8');
        
        // Display the sanitized output
        echo "<pre>" . $safe_output . "</pre>";
    } else {
        // Display error message for invalid commands (also sanitized)
        $safe_command = htmlspecialchars($command, ENT_QUOTES, 'UTF-8');
        echo "<div style='color: red;'>Error: Invalid command '" . $safe_command . "'. Allowed commands: " . implode(', ', array_keys($allowed_commands)) . "</div>";
    }
} else {
    // Instruction for users with safe examples
    echo "<h1>Command Execution Demo</h1>";
    echo "<p>To test, append a 'command' query parameter to the URL with one of the allowed commands:<br>";
    echo "Allowed commands: <code>" . implode(', ', array_keys($allowed_commands)) . "</code><br>";
    echo "For example: <code>?command=ls</code> or <code>?command=date</code></p>";
}

?>
```

## Security Fixes Applied:

### 1. **Command Injection Prevention (Line 10 vulnerability):**
- **Whitelist Approach**: Implemented a strict whitelist of allowed commands using the `$allowed_commands` array
- **Input Validation**: Only commands that exist in the whitelist are executed
- **Command Escaping**: Added `escapeshellcmd()` as an additional layer of protection for the pre-defined commands
- **No Direct User Input**: User input is never directly passed to `shell_exec()`

### 2. **Cross-Site Scripting (XSS) Prevention (Line 13 vulnerability):**
- **Output Encoding**: Used `htmlspecialchars()` with `ENT_QUOTES` and `UTF-8` encoding to sanitize all output before displaying
- **Safe Error Messages**: Error messages also sanitize user input before display
- **Consistent Sanitization**: All user-controlled data that gets displayed is properly encoded

### 3. **Additional Security Improvements:**
- **Input Trimming**: Remove whitespace from user input
- **Error Handling**: Proper error messages for invalid commands
- **User Guidance**: Clear instructions about allowed commands
- **Defensive Programming**: Multiple layers of protection (whitelist + escaping + output encoding)

### 4. **How the fixes work:**
- **Command Injection**: Instead of executing arbitrary commands, the application only allows predefined, safe commands from a whitelist
- **XSS**: All output is HTML-encoded, preventing malicious scripts from being executed in the browser
- **Defense in Depth**: Multiple security controls work together to provide comprehensive protection

This approach ensures that the application is secure while maintaining its intended functionality for legitimate use cases.