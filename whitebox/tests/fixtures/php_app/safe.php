<?php
function countRows($conn) {
    $id = intval($_GET["id"]);                                      // SAFE: intval
    mysqli_query($conn, "SELECT * FROM t WHERE id = " . $id);
    echo htmlspecialchars($_GET["name"]);                           // SAFE: htmlspecialchars
}
