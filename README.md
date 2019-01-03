# Antivirus App
SJSU | SE 174 </br>
Michael Li </br>

The antivirus application is only accessed through sessionMenu.php.
Through sessionMenu.php, you can start an admin session after going through admin authentication or start a user session.
The sessionMenu.php requires databaseSetup.php. (Runs databaseSetup.php script once at the beginning)
The antivirus database, admin table, and malware table are automatically created if they do not already exist.
Two admins are also automatically created if they don't already exist which are:

|  | Admin1 | Admin2 |
| --- | --- | --- |
| firstName: | John | Jane |
| lastName: | Doe | Doe |
| userName: | JDoe | JaneD |
| password: | password | mysecret |

To authenticate another admin or switch sessions from admin to user and vice versa, you must close your browser and run sessionMenu.php again.

	
