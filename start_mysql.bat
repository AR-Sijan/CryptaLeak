@echo off
echo Starting MySQL Server for Project CryptaLeak...
start "" /B "C:\Program Files\MySQL\MySQL Server 8.4\bin\mysqld.exe" --datadir="C:\Users\arafa\mysql_data"
timeout /t 2 /nobreak >nul
"C:\Program Files\MySQL\MySQL Server 8.4\bin\mysqladmin.exe" -u root ping
echo MySQL Server is ready on localhost:3306.