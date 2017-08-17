<?php
$pass = $_POST['upass'];

$host = 'localhost';
$user = 'root';
$pass = ' ';
mysql_connect($host, $user, $pass);
mysql_select_db('demo');

$dologin = "select pass from user where pass = $pass ";
$result = mysql_query( $dologin );

if($result)
{
 echo "Successfully Logged In";
}
else
{
 echo "Wrong Id Or Password";
}
?>