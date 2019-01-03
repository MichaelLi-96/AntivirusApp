<?php
    // SJSU | SE 174
    // AntiVirus Final Project
    // Michael Li
    // 12-16-2018
    // Admin or regular user session selection menu 

    // Setup the antivirus database that contains admin and malware tables
    require_once 'databaseSetup.php';
    
    // Display all the html code onto the server using a Heredoc
    // Shows a menu for the user whether to start the session as an admin or a regular user
    echo <<<_END
        <html>
            <head>
                <title>File AntiVirus Checker</title>
                <h1>File AntiVirus Checker</h1>
            </head>
            <body>
            	<table border="0" cellpadding="2" cellspacing="5" bgcolor="eeeeee">
            		<th colspan="2" align="center">Start the session as...</th>
            		<form method="post" action="adminAuthentication.php" enctype="multipart/form-data">
            			<tr>
            				<td colspan="2" align="center">
            					<input type="submit" value="Admin">
            				</td>
            			</tr>
                    </form>
                    <form method="post" action="userSession.php" enctype="multipart/form-data">
            			<tr>
            				<td colspan="2" align="center">
            					<input type="submit" value="User">
            				</td>
            			</tr>
            		</form>
            	</table>
            </body>
        </html>
_END;
?>