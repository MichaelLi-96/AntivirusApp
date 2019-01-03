<?php
    // SJSU | SE 174
    // AntiVirus Final Project
    // Michael Li
    // 12-16-2018
    // Setup for antivirus database, admin and malware tables, and 2 admins
    
    // Acquire mysql database connection values
    require_once 'login.php';
    
    // Start a connection with mysql database
    $conn = new mysqli($hn, $un, $pw);
    if ($conn->connect_error) {
        exit("<h4 style='color:red'>There was a problem connecting to mySQL: </h4>" . $conn->connect_error);
    }
    
    // Create a database called antivirus if it does not already exist
    $query = "CREATE DATABASE IF NOT EXISTS antivirus";
    executeQuery($query, $conn);
    // Use the antivirus database
    $query = "USE antivirus";
    executeQuery($query, $conn);
    
    // Create a table called admin if it does not already exist
    // Stores admin credentials
    $query = "CREATE TABLE IF NOT EXISTS admin (
        firstName VARCHAR(128) NOT NULL,
        lastName VARCHAR(128) NOT NULL,
        username VARCHAR(128),
        password VARCHAR(128) NOT NULL,
        PRIMARY KEY (userName)
    )";
    executeQuery($query, $conn);
    
    // Create a table called malware if it does not already exist
    // Store malware name and signature
    $query = "CREATE TABLE IF NOT EXISTS malware (
        name VARCHAR(256),
        signature VARCHAR(20) NOT NULL, 
        PRIMARY KEY (name)
    )";
    executeQuery($query, $conn);
    
    // Salt for password security
    $salt1= "#ju@%^";
    $salt2 = "n!e*2";
    
    // Admin 1 to be added 
    $firstName = "John";
    $lastName = "Doe";
    $username = "JDoe";
    $password= "password";
    // Salt and then hash the password
    $token = hash('ripemd128', "$salt1$password$salt2");
    
    // Add admin 1 to the admin table
    add_admin($conn, $firstName, $lastName, $username, $token);
    
    // Admin 2 to be added 
    $firstName = "Jane";
    $lastName = "Doe";
    $username = "JaneD";
    $password= "mysecret";
    // Salt and then hash the password
    $token = hash('ripemd128', "$salt1$password$salt2");
    
    // Add admin 2 to the admin table
    add_admin($conn, $firstName, $lastName, $username, $token);
    
    // If the admin username does not already exist in the admin table, add the admin to the admin table
    function add_admin($conn, $fn, $ln, $un, $pw) {
        $query = "SELECT * FROM admin WHERE username = '$un'";
        $result = $conn->query($query);
        if(mysqli_num_rows($result) === 0) {
            $query = "INSERT INTO admin VALUES('$fn', '$ln', '$un', '$pw')";
            executeQuery($query, $conn);
        } 
    }
    
    // Execute the mysql query. Returns a red error message if the mysql query fails
    function executeQuery($query, $conn) {
        $result = $conn->query($query);
        if (!$result) {
            exit("<h4 style='color:red'>There was a problem executing the mySQL query: </h4>" . $conn->error);
        }
    }
?>