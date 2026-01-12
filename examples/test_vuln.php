<?php
/*
 * Test vulnerable PHP page for SQL injection testing
 * WARNING: This is intentionally vulnerable for educational purposes only
 */

// Database configuration
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "testdb";

// Connect to database
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get user input
$id = $_GET['id'];
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

// Vulnerable query examples
echo "<h1>SQL Injection Test Page</h1>";

// Example 1: Vulnerable GET parameter
if (isset($_GET['id'])) {
    echo "<h2>GET Parameter Test</h2>";
    $query = "SELECT * FROM users WHERE id = $id";
    echo "<p>Query: " . $query . "</p>";
    
    $result = $conn->query($query);
    if ($result && $result->num_rows > 0) {
        while($row = $result->fetch_assoc()) {
            echo "<p>ID: " . $row["id"] . " - Name: " . $row["username"] . "</p>";
        }
    } else {
        echo "<p>No results found</p>";
    }
}

// Example 2: Vulnerable POST parameter
if (isset($_POST['username']) && isset($_POST['password'])) {
    echo "<h2>POST Parameter Test</h2>";
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    echo "<p>Query: " . $query . "</p>";
    
    $result = $conn->query($query);
    if ($result && $result->num_rows > 0) {
        echo "<p>Login successful!</p>";
        while($row = $result->fetch_assoc()) {
            echo "<p>Welcome, " . $row["username"] . "!</p>";
        }
    } else {
        echo "<p>Login failed!</p>";
    }
}

// Example 3: Search functionality
if (isset($_GET['search'])) {
    echo "<h2>Search Test</h2>";
    $search = $_GET['search'];
    $query = "SELECT * FROM products WHERE name LIKE '%$search%'";
    echo "<p>Query: " . $query . "</p>";
    
    $result = $conn->query($query);
    if ($result && $result->num_rows > 0) {
        while($row = $result->fetch_assoc()) {
            echo "<p>Product: " . $row["name"] . " - Price: $" . $row["price"] . "</p>";
        }
    } else {
        echo "<p>No products found</p>";
    }
}

// Test forms
?>
<h2>Test Forms</h2>

<!-- GET form -->
<form method="GET" action="">
    <h3>GET Test</h3>
    <input type="text" name="id" placeholder="Enter ID">
    <input type="submit" value="Submit">
</form>

<!-- POST form -->
<form method="POST" action="">
    <h3>Login Test</h3>
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" value="Login">
</form>

<!-- Search form -->
<form method="GET" action="">
    <h3>Search Test</h3>
    <input type="text" name="search" placeholder="Search products">
    <input type="submit" value="Search">
</form>

<?php
$conn->close();
?>
