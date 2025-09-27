@echo off
REM CyberSentinel AI Production Startup Script for Windows
REM This script starts the application in production mode

echo 🛡️ Starting CyberSentinel AI in Production Mode
echo ==============================================

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed. Please install Node.js first.
    pause
    exit /b 1
)

REM Check if PM2 is installed
pm2 --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️  PM2 is not installed. Installing PM2...
    npm install -g pm2
)

REM Create necessary directories
if not exist "logs" mkdir logs
if not exist "uploads" mkdir uploads

REM Set production environment
set NODE_ENV=production
set PORT=3000
set HOST=0.0.0.0

REM Check if .env file exists
if not exist ".env" (
    echo ⚠️  .env file not found. Creating from template...
    if exist "env.example" (
        copy env.example .env
        echo 📝 Please update .env file with your configuration
    ) else (
        echo ❌ No env.example file found. Please create .env file manually.
        pause
        exit /b 1
    )
)

REM Install dependencies if node_modules doesn't exist
if not exist "node_modules" (
    echo 📦 Installing dependencies...
    npm install --production
)

REM Start the application
echo 🚀 Starting CyberSentinel AI...

REM Option 1: Start with PM2 (recommended for production)
pm2 --version >nul 2>&1
if %errorlevel% equ 0 (
    echo Using PM2 process manager...
    pm2 start ecosystem.config.js --env production
    echo ✅ Application started with PM2
    echo 📊 Monitor with: pm2 monit
    echo 📋 View logs with: pm2 logs cybersentinel-ai
) else (
    REM Option 2: Start directly with Node.js
    echo Using direct Node.js startup...
    node server.js
)

pause
