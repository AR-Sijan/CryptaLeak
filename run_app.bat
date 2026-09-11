@echo off
echo ===================================================
echo  Starting Project CryptaLeak - Cyber Defense Suite
echo ===================================================

echo [1/2] Verifying MySQL Server...
"C:\Program Files\MySQL\MySQL Server 8.4\bin\mysqladmin.exe" -u root ping >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Starting MySQL Server in background...
    start "" /B "C:\Program Files\MySQL\MySQL Server 8.4\bin\mysqld.exe" --datadir="C:\Users\arafa\mysql_data"
    timeout /t 2 /nobreak >nul
)

echo [2/2] Launching Java Swing Application...
java -cp "bin;lib\mysql-connector-j-8.4.0.jar" com.cryptaleak.ui.LoginFrame