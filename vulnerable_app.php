<?php

// Check if a 'command' parameter was passed via GET
if (isset($_GET['command'])) {
    // Retrieve user-supplied input directly
    $command = $_GET['command'];

// Validate and sanitize the command input
if (isset($command) && is_string($command)) {
    // Whitelist allowed commands
    $allowed_commands = ['ls', 'pwd', 'whoami', 'date'];
    $command_parts =...
    echo "<pre>$output</pre>";
} else {
    // Instruction for a user to trigger the vulnerability
    echo "<h1>Command Execution Demo</h1>";
    echo "<p>To test, append a 'command' query parameter to the URL.<br>";
    echo "For example: <code>?command=ls -la</code></p>";
}

?>
