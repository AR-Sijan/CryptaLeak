@echo off
echo Stopping MySQL Server...
"C:\Program Files\MySQL\MySQL Server 8.4\bin\mysqladmin.exe" -u root shutdown
echo MySQL Server stopped.