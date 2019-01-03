<?php
    // SJSU | SE 174
    // AntiVirus Final Project
    // Michael Li
    // 12-16-2018
    // User session, allows the user to submit a putative infected file and shows if it is infected or not
    
    // Acquire mysql database connection values
    require_once 'login.php';
    
    // Start a connection with mysql database
    $conn = new mysqli($hn, $un, $pw, $db);
    if ($conn->connect_error) {
        exit("<h4 style='color:red'>There was a problem connecting to mySQL: </h4>" . $conn->connect_error);
    }
    
    // Close the sessions after one day when the user has forgotten or neglected to log out
    ini_set('session.gc_maxlifetime', 60 * 60 * 24);
    // Start/Resume the user session
    session_start();
    // initialize session hijacking check
    if(!isset($_SESSION['check'])) {
        $_SESSION['check'] = hash('ripemd128', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
    }
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
    
    // Iterates through the malware table and for each malware,
    // check if the content of the putative infected file contains its malware signature
    // If the file is infected, displays a red warning message and the name of the malware it contains 
    // If the file is not infected, displays a green message saying the file is clean
    function checkFileForMalware($fileContent, $conn) {
        $query = "SELECT * FROM malware";
        $result = $conn->query($query);
        if (!$result) {
            exit("<h4 style='color:red'>There was a problem getting malware data: </h4>" . $conn->error);
        }
        else {
            while ($row = mysqli_fetch_array($result, MYSQLI_ASSOC)) {
                if (strpos($fileContent, $row["signature"]) !== false) {
                    $malwareName = $row["name"];
                    exit("<h4 style='color:red'>Your file is infected! Your file contains the malware called: '$malwareName'.</h4>");
                }
            }
            exit("<h4 style='color:green'>Your file is clean!</h4>");
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
    
    // If the user clicks the close session button, close the connection and destroy the session and its data
    if(isset($_POST["closeSession"])) {
        $conn->close();
        destroy_session_and_data();
    }
    
    // If the session status is active, show the antivirus checker form
    // Else, show that the session has been destroyed and a link to restart the session
    if(session_status() == PHP_SESSION_ACTIVE) {
        // Check to prevent session hijacking
        if($_SESSION['check'] === hash('ripemd128', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'])) {
            // Display all the html code onto the server using a Heredoc
            // Shows a putative infected file upload field, a close session button, and an inspect button 
            echo <<<_END
                <html>
                    <head>
                        <title>File AntiVirus Checker</title>
                        <h1>File AntiVirus Checker</h1>
                    </head>
                   <body>
                        <table border="0" cellpadding="2" cellspacing="5" bgcolor="eeeeee">
                            <th colspan="2" align="center">Is your file infected?</th>
                            <form method="post" action="userSession.php" enctype="multipart/form-data">
                                <tr>
                                    <td>Your file:</td>
                                    <td><input type="file" name="file" size="20" /></td>
                        		</tr>
                                <tr>
                                    <td colspan="1" align="left">
                                        <input type="submit" name="closeSession" value="Close Session" />
                    				</td>
                    				<td colspan="1" align="right">
                                        <input type="submit" name="inspect" value="Inspect" />
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
        exit("<h4 style='color:green'>Successfully destroyed the session. Please close the browser and reopen or <a href='userSession.php'>click here</a> to restart your session.");
    }

    // Check if the putative infected file input was successfully uploaded and that there were no upload errors
    if($_FILES && is_uploaded_file($_FILES['file']['tmp_name']) && $_FILES['file']['error'] == UPLOAD_ERR_OK) {
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
                closeConnectionAndExit("The input file cannot be empty.", $conn);
            }
            else {
                // Check the contents of the putative infected file for malware
               checkFileForMalware($fileContent, $conn);
            }
        }
        else {
            closeConnectionAndExit("Only plain text documents are allowed. $file is not an accepted file.", $conn);
        }
    }
    else {
        // Display error message if user tries to execute query without an attached file
        if($_POST) {
            closeConnectionAndExit("No file was attached.", $conn);
        }
    } 
?>