<?php
    // SJSU | SE 174
    // AntiVirus Final Project
    // Michael Li
    // 12-16-2018
    // Admin session, allows admin to submit the malware name and malware file
    // Then store the malware name and signature into the malware table

    // Acquire mysql database connection values
    require_once 'login.php';
    
    // Start a connection with mysql database
    $conn = new mysqli($hn, $un, $pw, $db);
    if ($conn->connect_error) {
        exit("<h4 style='color:red'>There was a problem connecting to mySQL: </h4>" . $conn->connect_error);
    }
    
    // Close the sessions after one day when the user has forgotten or neglected to log out
    ini_set('session.gc_maxlifetime', 60 * 60 * 24);
    // Start/Resume the admin session
    session_start();
    // Check to prevent session fixation
    if(!isset($_SESSION['initiated'])) {
        session_regenerate_id();
        $_SESSION['initiated'] = 1;
    }
    if(!isset($_SESSION['count'])) {
        $_SESSION['count'] = 0;
    }
    else {
        ++$_SESSION['count'];
    }
    
    // When an Admin adds the name of a malware during the uploading of a Malware file, 
    // it ensures that the string contains only English letters (capitalized or not) and digits.
    // Any other character, or an empty string, must be avoided. 
    function validateMalwareName($malwareName) {
        if ($malwareName == "") {
            exit("<h4 style='color:red'>No malware name was entered.</h4>");
        }
        else if(trim(" ", $malwareName) == "") {
            exit("<h4 style='color:red'>Malware name cannot be whitespace.</h4>");
        }
        else if (!preg_match("/^[a-zA-Z0-9]+$/", $malwareName)) {
            exit("<h4 style='color:red'>Malware names must contain only english letters (captialized or not) and digits.");
        }
    }
    
    // Add the malware data into the malware table given the malware name, malware signature, and mysql connection
    function addMalwareToDatabase($malwareName, $malwareSignature, $conn) {
        $query = "INSERT INTO malware (name, signature) VALUES ('$malwareName', '$malwareSignature')";
        $result = $conn->query($query);
        if (!$result) {
            exit("<h4 style='color:red'>There was a problem inserting malware data into the database: </h4>" . $conn->error);
        }
    }
    
    // Close the connection with mysql and then exit with red error message
    function closeConnectionAndExit($message, &$conn) {
        $conn->close();
        exit("<h4 style='color:red'>$message</h4>");
    }
    
    // Destroys the session and its data
    function destroy_session_and_data() {
        $_SESSION = array();
        setcookie(session_name(), '', time() - 2592000, '/');
        session_destroy();
    }
    
    // Strip out any characters from an input that a hacker may have inserted in order to break into/alter database
    function get_post($conn, $var) {
        return $conn->real_escape_string($_POST[$var]);
    }
    
    // If magic quotes are on, strips the backslashes of the string
    // Returns the string with html entities
    function fix_string($string) {
        if (get_magic_quotes_gpc()) {
            $string = stripslashes($string);
        }
        return htmlentities($string);
    }    
    
    // If the admin clicks the sign out button, close the connection and destroy the session and its data
    if(isset($_POST["signOut"])) {
        $conn->close();
        destroy_session_and_data();
    }
    
    
    // If the session has the 'username' value set, show the admin malware submission form
    // Else, show that the session has been destroyed and a link to restart the session
    if(isset($_SESSION['username'])) {
        // Check to prevent session hijacking
        if($_SESSION['check'] === hash('ripemd128', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'])) {
            // Display all the html code onto the server using a Heredoc
            // Shows a malware name field, a malware file upload field, a signout button, and a upload button
            echo <<<_END
                <html>
                    <head>
                        <title>File AntiVirus Checker</title>
                        <h1>File AntiVirus Checker</h1>
                    </head>
                   <body>
                        <table border="0" cellpadding="2" cellspacing="5" bgcolor="eeeeee">
                            <th colspan="2" align="center">Admin Malware Submission</th>
                            <form method="post" action="adminSession.php" enctype="multipart/form-data">
                                <tr>
                                    <td>Malware Name:</td>
                                    <td><input type="text" name="malwareName" maxlength="30" /></td>
                        		</tr>
                                <tr>
                                    <td>Malware File:</td>
                                    <td><input type="file" name="file" size="20" /></td>
                        		</tr>
                                <tr>
                                    <td colspan="1" align="left">
                                        <input type="submit" name="signOut" value="Sign out" />
                    				</td>
                    				<td colspan="1" align="right">
                                        <input type="submit" name="upload" value="Upload" />
                    				</td>
                    			</tr>
                            </form>
                        </table>
                    </body>
                </html>
_END;
        }
        else {
            $conn->close();
            destroy_session_and_data();
            exit("<h4 style='color:green'>The session was destroyed. Please close the browser and reopen to try again.</h4>");
        }
    }
    else {
        exit("<h4 style='color:green'>Successfully destroyed the session. Please close the browser and reopen or <a href='adminAuthentication.php'>click here</a> to restart your session.</h4>");
    }
    
    // Check if the malware file input was successfully uploaded and that there were no upload errors, and if the malware name was set
    if($_FILES && is_uploaded_file($_FILES['file']['tmp_name']) && $_FILES['file']['error'] == UPLOAD_ERR_OK && isset($_POST["malwareName"])) {
        $malwareName = get_post($conn, "malwareName");
        fix_string($malwareName);
        
        // Check if the malware name only contains english letters and digits
        validateMalwareName($malwareName);

        $file = $_FILES['file']['name'];
        // Sanitizing supplied filename
        $file = strtolower(preg_replace("/[^A-Za-z0-9.]/", "", $file));
        
        // Validation of input data, check if the file type is of plain text
        if($_FILES['file']['type'] == "text/plain" ) {
            // Move the file from a temporary to permanent location
            move_uploaded_file($_FILES['file']['tmp_name'], $file);
            
            // Test for empty file and file of only white space
            $fileContent = file_get_contents($file);
            if(trim($fileContent) == "") {
                closeConnectionAndExit("The malware file cannot be empty.", $conn);
            }
            else {
                // Open file
                $fh = fopen($file, "r");
                if($fh) {
                    // Retrieve first 20 bytes of the malware file (the malware signature)
                    $malwareSignature = fread($fh, 20);
                    // Close file
                    fclose($fh);
                    
                    // Add the malware data into the malware table
                    addMalwareToDatabase($malwareName, $malwareSignature, $conn);
                }
                else {
                    closeConnectionAndExit("There was an error opening the file.", $conn);
                }
            }
            echo "<h4 style='color:green'>The malware '$malwareName' has been successfully added to the malware database.</h4>";
        }
        else {
            closeConnectionAndExit("Only plain text documents are allowed. $file is not an accepted file.", $conn);
        }
    }
    else {
        // Display error message if user tries to execute query without a malware name and/or attached file
        if($_POST) {
            closeConnectionAndExit("Malware name field was empty and/or no file was attached.", $conn);
        }
    } 
?>