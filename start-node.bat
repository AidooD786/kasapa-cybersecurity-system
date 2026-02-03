@echo off
chcp 65001 >nul
title Kasapa FM Cybersecurity System - Group 7
color 0A
echo ===========================================
echo   KASAPA FM CYBERSECURITY SYSTEM
echo   Ghana Communication Technology University
echo   BSc Computer Science (Cyber Security)
echo   Group 7 - Field Trip Report Project
echo ===========================================
echo.

:: Check if Node.js is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed!
    echo.
    echo Please install Node.js from: https://nodejs.org/
    echo.
    echo Steps:
    echo 1. Visit https://nodejs.org/
    echo 2. Download the LTS version (Recommended)
    echo 3. Run the installer
    echo 4. Restart Command Prompt after installation
    echo.
    pause
    exit /b 1
)

:: Check Node.js version
node --version >nul 2>nul
if %errorlevel% equ 0 (
    for /f "tokens=*" %%i in ('node --version') do set NODE_VERSION=%%i
    echo Node.js %NODE_VERSION% detected
)

:: Install dependencies
echo.
echo Installing/updating dependencies...
call npm install

:: Check if installation was successful
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to install dependencies
    echo Please check your internet connection and try again
    pause
    exit /b 1
)

:: Clear console
cls
color 0A
echo ===========================================
echo   KASAPA FM CYBERSECURITY SYSTEM
echo   Ghana Communication Technology University
echo ===========================================
echo.
echo Starting the application...
echo.
echo Server will be available at:
echo    http://localhost:3000
echo.
echo Demo Login Credentials:
echo    Admin: admin@kasapafm.com / admin123
echo    Technician: tech@kasapafm.com / tech123
echo    Journalist: journalist@kasapafm.com / journo123
echo.
echo Press CTRL+C to stop the server
echo ===========================================
echo.

:: Start the server
node server.js

:: If server crashes, show error message
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Server crashed or failed to start
    echo Possible reasons:
    echo 1. Port 3000 is already in use
    echo 2. Node.js installation is corrupted
    echo 3. Missing dependencies
    echo.
    echo Try these solutions:
    echo 1. Close other applications using port 3000
    echo 2. Run: netstat -ano | findstr :3000
    echo 3. Kill the process using that port
    echo 4. Or change port in server.js file
    echo.
    pause
)