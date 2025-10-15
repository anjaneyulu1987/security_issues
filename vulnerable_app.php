<?php

// Check if a 'command' parameter was passed via GET
if (isset($_GET['command'])) {
    // Retrieve user-supplied input directly
    $command = $_GET['command'];

    // Execute the command without any sanitization or validation
    // This is the source of the critical vulnerability
    $output = shell_exec($command);
echo "<pre>" . htmlspecialchars($output, ENT_QUOTES, 'UTF-8') . "</pre>";
    echo "<h1>Command Execution Demo</h1>";
    echo "<p>To test, append a 'command' query parameter to the URL.<br>";
    echo "For example: <code>?command=ls -la</code></p>";
}

?>
