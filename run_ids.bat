@echo off
title Network Intrusion Detection System (IDS)
color 0A

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Administrator rights required for raw packet sniffing.
    echo [*] Requesting Administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/k cd /d \"%~dp0\" && python main.py' -Verb RunAs"
    exit /b
)

:: Running with Administrator privileges
cd /d "%~dp0"
echo =======================================================
echo    Starting Network Intrusion Detection System (IDS)
echo =======================================================
echo.
python main.py

if %errorLevel% neq 0 (
    echo.
    echo [!] Application exited with an error.
    pause
)
