<?php
    // SJSU | SE 174
    // AntiVirus Final Project
    // Michael Li
    // 12-16-2018
    // Authenication for admin users
    
    // Acquire mysql database connection values
    require_once 'login.php';

    // Start a connection with mysql database
    $conn = new mysqli($hn, $un, $pw, $db);
    if ($conn->connect_error) {
        exit("<h4 style='color:red'>There was a problem connecting to mySQL: </h4>" . $conn->connect_error);
    }
    
    // Admin authentication
    // If admin username and password are supplied, first see if the username exists in the admin table
    // If the admin username exists, check if the supplied password is the valid by salting and hashing and then comparing it to the one stored in the table
    // After checking if the username and password are valid and correct, start a new session for the admin
    // Displays an error is the username and password are invalid or not supplied
    if (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) {
        $un_temp = mysql_entities_fix_string($conn, $_SERVER['PHP_AUTH_USER']);
        $pw_temp = mysql_entities_fix_string($conn, $_SERVER['PHP_AUTH_PW']);
        $query = "SELECT * FROM admin WHERE username = '$un_temp'";
        $result = $conn->query($query);
        
        if (!$result) {
            die($conn->error);
        }
        elseif($result->num_rows) {
            $row = $result->fetch_array(MYSQLI_NUM);
            $result->close();
            $salt1= "#ju@%^";
            $salt2 = "n!e*2";
            $token = hash('ripemd128', "$salt1$pw_temp$salt2");
            
            if($token == $row[3]) {
                // Close the sessions after one day when the user has forgotten or neglected to log out
                ini_set('session.gc_maxlifetime', 60 * 60 * 24);
                session_start();
                $_SESSION['username'] = $un_temp;
                $_SESSION['check'] = hash('ripemd128', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
                
                // Display all the html code onto the server using a Heredoc
                // After successful authentication, shows a welcome message to the admin and a link to the admin session
                echo <<<_END
                    <html>
                        <head>
                            <title>File AntiVirus Checker</title>
                            <h1>File AntiVirus Checker</h1>
                        </head>
                       <body>
                            <h4 style='color:green'>Hello admin: $row[0] $row[1]. You are now logged in as '$row[2]'</h4>
                        </body>
                    </html>
_END;
                exit("<p><a href=adminSession.php>Click here to continue to your session</a></p>");
            }
            else {
                exit("<h4 style='color:red'>Invalid username/password combination. Please close the browser and reopen to try again.</h4>");
            }
        }
        else {
            exit("<h4 style='color:red'>Invalid username/password combination. Please close the browser and reopen to try again.</h4>");
        }
    }
    else {
        header('WWW-Authenticate: Basic realm="Restricted Section“');
        header('HTTP/1.0 401 Unauthorized');
        exit("<h4 style='color:red'>Username and password required. Please close the browser and reopen to try again.</h4>");
    }
    $conn->close();
    
    // Returns the string with html entities
    function mysql_entities_fix_string($conn, $string) {
        return htmlentities(mysql_fix_string($conn, $string));
    }
    
    // If magic quotes are on, strips the backslashes of the string
    // Strip out any characters from the string that a hacker may have inserted in order to break into/alter database
    function mysql_fix_string($conn, $string) {
        if(get_magic_quotes_gpc()) {
            $string = stripslashes($string);
        }
        return $conn->real_escape_string($string);
    }
?>