@echo off
echo Starting SQL Injection Toolkit...
echo.

echo [1/2] Starting Test Server...
start "Test Server" cmd /k "cd /d %~dp0 && python test_server.py"

timeout /t 2 /nobreak >nul

echo [2/2] Starting Web Interface...
start "Web Interface" cmd /k "cd /d %~dp0 && python run_web.py"

echo.
echo All services started!
echo Test Server: http://localhost:8080
echo Web Interface: http://localhost:5000
echo.
pause
