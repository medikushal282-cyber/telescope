@echo off
title Telescope 4.1 Server
cd /d "%~dp0"

echo ========================================================
echo   Starting Telescope 4.1 Server...
echo ========================================================
echo.

where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Node.js is not found in PATH!
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo [OK] Launching http://localhost:8000 in your browser...
start "" http://localhost:8000

echo [OK] Starting Node.js backend...
node server.js
if %ERRORLEVEL% neq 0 (
    echo.
    echo Server exited with an error.
    pause
)
