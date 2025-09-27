#!/bin/bash

# CyberSentinel AI Production Startup Script
# This script starts the application in production mode

set -e

echo "🛡️ Starting CyberSentinel AI in Production Mode"
echo "=============================================="

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    exit 1
fi

# Check if PM2 is installed
if ! command -v pm2 &> /dev/null; then
    echo "⚠️  PM2 is not installed. Installing PM2..."
    npm install -g pm2
fi

# Create necessary directories
mkdir -p logs uploads

# Set production environment
export NODE_ENV=production
export PORT=${PORT:-3000}
export HOST=0.0.0.0

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found. Creating from template..."
    if [ -f "env.example" ]; then
        cp env.example .env
        echo "📝 Please update .env file with your configuration"
    else
        echo "❌ No env.example file found. Please create .env file manually."
        exit 1
    fi
fi

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install --production
fi

# Start the application
echo "🚀 Starting CyberSentinel AI..."

# Option 1: Start with PM2 (recommended for production)
if command -v pm2 &> /dev/null; then
    echo "Using PM2 process manager..."
    pm2 start ecosystem.config.js --env production
    echo "✅ Application started with PM2"
    echo "📊 Monitor with: pm2 monit"
    echo "📋 View logs with: pm2 logs cybersentinel-ai"
else
    # Option 2: Start directly with Node.js
    echo "Using direct Node.js startup..."
    node server.js
fi
