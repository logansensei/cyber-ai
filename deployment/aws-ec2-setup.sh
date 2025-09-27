#!/bin/bash

# CyberSentinel AI - AWS EC2 Deployment Script
# This script sets up CyberSentinel AI on an AWS EC2 instance

set -e

echo "🛡️ CyberSentinel AI - AWS EC2 Deployment"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons"
   exit 1
fi

# Update system packages
print_status "Updating system packages..."
sudo apt-get update -y
sudo apt-get upgrade -y

# Install required system dependencies
print_status "Installing system dependencies..."
sudo apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    build-essential \
    python3 \
    python3-pip \
    nginx \
    certbot \
    python3-certbot-nginx \
    ufw \
    fail2ban

# Install Node.js 18 LTS
print_status "Installing Node.js 18 LTS..."
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify Node.js installation
NODE_VERSION=$(node --version)
print_success "Node.js installed: $NODE_VERSION"

# Install PM2 for process management
print_status "Installing PM2 process manager..."
sudo npm install -g pm2

# Create application directory
print_status "Setting up application directory..."
APP_DIR="/opt/cybersentinel-ai"
sudo mkdir -p $APP_DIR
sudo chown $USER:$USER $APP_DIR
cd $APP_DIR

# Clone or copy application files
if [ -d ".git" ]; then
    print_status "Updating existing application..."
    git pull origin main
else
    print_status "Setting up application files..."
    # If this is a fresh deployment, you would copy your files here
    # For now, we'll create the basic structure
    mkdir -p {logs,uploads,config}
fi

# Install application dependencies
print_status "Installing application dependencies..."
if [ -f "package.json" ]; then
    npm install --production
else
    print_error "package.json not found. Please ensure application files are properly deployed."
    exit 1
fi

# Create systemd service file
print_status "Creating systemd service..."
sudo tee /etc/systemd/system/cybersentinel-ai.service > /dev/null <<EOF
[Unit]
Description=CyberSentinel AI Security Testing Platform
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production
Environment=PORT=3000

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$APP_DIR

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx
print_status "Configuring Nginx..."
sudo tee /etc/nginx/sites-available/cybersentinel-ai > /dev/null <<EOF
server {
    listen 80;
    server_name _;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://api.openai.com https://generativelanguage.googleapis.com; font-src 'self' https: data:;" always;

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone \$binary_remote_addr zone=login:10m rate=1r/s;

    # Main application
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # API rate limiting
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Login rate limiting
    location /api/auth/ {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Static files caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        proxy_pass http://localhost:3000;
    }

    # Security - deny access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ \.(env|log|conf)$ {
        deny all;
    }
}
EOF

# Enable the site
sudo ln -sf /etc/nginx/sites-available/cybersentinel-ai /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test Nginx configuration
print_status "Testing Nginx configuration..."
sudo nginx -t

# Configure firewall
print_status "Configuring firewall..."
sudo ufw --force enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
sudo ufw allow 3000/tcp

# Configure fail2ban
print_status "Configuring fail2ban..."
sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
EOF

# Create log rotation configuration
print_status "Setting up log rotation..."
sudo tee /etc/logrotate.d/cybersentinel-ai > /dev/null <<EOF
$APP_DIR/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $USER $USER
    postrotate
        systemctl reload cybersentinel-ai
    endscript
}
EOF

# Set up monitoring script
print_status "Setting up monitoring..."
sudo tee /usr/local/bin/cybersentinel-monitor.sh > /dev/null <<EOF
#!/bin/bash
# CyberSentinel AI Health Check Script

APP_URL="http://localhost:3000/health"
LOG_FILE="/var/log/cybersentinel-monitor.log"

check_health() {
    response=\$(curl -s -o /dev/null -w "%{http_code}" \$APP_URL)
    if [ "\$response" = "200" ]; then
        echo "\$(date): Health check passed" >> \$LOG_FILE
        return 0
    else
        echo "\$(date): Health check failed (HTTP \$response)" >> \$LOG_FILE
        return 1
    fi
}

if ! check_health; then
    echo "\$(date): Restarting CyberSentinel AI service" >> \$LOG_FILE
    systemctl restart cybersentinel-ai
    sleep 10
    check_health
fi
EOF

sudo chmod +x /usr/local/bin/cybersentinel-monitor.sh

# Add cron job for monitoring
print_status "Setting up monitoring cron job..."
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/cybersentinel-monitor.sh") | crontab -

# Create environment file template
print_status "Creating environment configuration..."
if [ ! -f "$APP_DIR/.env" ]; then
    sudo tee $APP_DIR/.env > /dev/null <<EOF
# CyberSentinel AI Production Configuration
NODE_ENV=production
PORT=3000

# AI Provider Configuration
OPENAI_API_KEY=your_openai_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here

# Security Configuration
JWT_SECRET=$(openssl rand -base64 32)
ENCRYPTION_KEY=$(openssl rand -base64 32)

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# File Upload
MAX_FILE_SIZE=10485760
ALLOWED_FILE_TYPES=.json,.yaml,.yml,.har

# Logging
LOG_LEVEL=info
LOG_FILE=$APP_DIR/logs/cybersentinel.log

# Feature Flags
ENABLE_AI=true
ENABLE_RATE_LIMITING=true
ENABLE_LOGGING=true
ENABLE_METRICS=true

# Production Settings
DEBUG=false
VERBOSE_LOGGING=false
EOF
    sudo chown $USER:$USER $APP_DIR/.env
    print_warning "Please edit $APP_DIR/.env and add your API keys"
fi

# Set proper permissions
print_status "Setting up permissions..."
sudo chown -R $USER:$USER $APP_DIR
chmod -R 755 $APP_DIR
chmod 600 $APP_DIR/.env

# Start services
print_status "Starting services..."
sudo systemctl daemon-reload
sudo systemctl enable cybersentinel-ai
sudo systemctl start cybersentinel-ai
sudo systemctl restart nginx
sudo systemctl restart fail2ban

# Wait for service to start
print_status "Waiting for service to start..."
sleep 10

# Check service status
if systemctl is-active --quiet cybersentinel-ai; then
    print_success "CyberSentinel AI service is running"
else
    print_error "Failed to start CyberSentinel AI service"
    sudo systemctl status cybersentinel-ai
    exit 1
fi

# Test the application
print_status "Testing application..."
if curl -f http://localhost:3000/health > /dev/null 2>&1; then
    print_success "Application is responding correctly"
else
    print_warning "Application health check failed, but service is running"
fi

# Display final information
print_success "CyberSentinel AI deployment completed!"
echo ""
echo "📋 Deployment Summary:"
echo "====================="
echo "Application Directory: $APP_DIR"
echo "Service Status: $(systemctl is-active cybersentinel-ai)"
echo "Nginx Status: $(systemctl is-active nginx)"
echo "Application URL: http://$(curl -s ifconfig.me)"
echo "Health Check: http://$(curl -s ifconfig.me)/health"
echo ""
echo "🔧 Next Steps:"
echo "1. Edit $APP_DIR/.env and add your AI API keys"
echo "2. Configure SSL certificate: sudo certbot --nginx"
echo "3. Monitor logs: tail -f $APP_DIR/logs/cybersentinel.log"
echo "4. Check service status: sudo systemctl status cybersentinel-ai"
echo ""
echo "📊 Monitoring:"
echo "- Health check runs every 5 minutes"
echo "- Logs are rotated daily"
echo "- Fail2ban protects against brute force attacks"
echo "- Nginx provides rate limiting and security headers"
echo ""
echo "🛡️ Security Features Enabled:"
echo "- Firewall configured (UFW)"
echo "- Fail2ban protection"
echo "- Rate limiting"
echo "- Security headers"
echo "- Process isolation"
echo ""
print_success "Deployment completed successfully!"
