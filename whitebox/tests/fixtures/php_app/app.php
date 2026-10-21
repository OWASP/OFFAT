<?php
// Intentionally vulnerable PHP fixture (superglobals).
function search($conn) {
    $q = $_GET["q"];
    mysqli_query($conn, "SELECT * FROM u WHERE n = '" . $q . "'");  // VULN sqli
}
function run() {
    system("ping -c 1 " . $_GET["host"]);                           // VULN command_injection
}
function show() {
    echo $_GET["name"];                                             // VULN xss
}
