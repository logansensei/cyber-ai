#!/bin/bash

# CyberSentinel AI - AWS Deployment Script
# Quick deployment script for AWS EC2

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Check if running on AWS EC2
if ! curl -s http://169.254.169.254/latest/meta-data/instance-id > /dev/null 2>&1; then
    print_warning "This script is designed for AWS EC2. Continuing anyway..."
fi

# Get instance metadata
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)

print_status "Deploying CyberSentinel AI on AWS EC2"
print_status "Instance ID: $INSTANCE_ID"
print_status "Public IP: $PUBLIC_IP"
print_status "Region: $REGION"

# Update system
print_status "Updating system packages..."
sudo apt-get update -y
sudo apt-get upgrade -y

# Install Docker
print_status "Installing Docker..."
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
rm get-docker.sh

# Install Docker Compose
print_status "Installing Docker Compose..."
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Create application directory
print_status "Setting up application directory..."
APP_DIR="/opt/cybersentinel-ai"
sudo mkdir -p $APP_DIR
sudo chown $USER:$USER $APP_DIR
cd $APP_DIR

# Create necessary directories
mkdir -p {logs,uploads,config,nginx,ssl,monitoring/grafana/dashboards,monitoring/grafana/datasources}

# Create environment file
print_status "Creating environment configuration..."
cat > .env << EOF
# CyberSentinel AI Production Configuration
NODE_ENV=production
PORT=3000

# AI Provider Configuration (Add your keys here)
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
LOG_FILE=/app/logs/cybersentinel.log

# Feature Flags
ENABLE_AI=true
ENABLE_RATE_LIMITING=true
ENABLE_LOGGING=true
ENABLE_METRICS=true

# Production Settings
DEBUG=false
VERBOSE_LOGGING=false

# Monitoring
GRAFANA_PASSWORD=$(openssl rand -base64 12)
EOF

print_warning "Please edit $APP_DIR/.env and add your AI API keys before starting the application"

# Copy application files (assuming they're in the current directory)
if [ -f "../package.json" ]; then
    print_status "Copying application files..."
    cp -r ../* . 2>/dev/null || true
    cp -r ../.* . 2>/dev/null || true
else
    print_status "Downloading application files..."
    # If files are not present, you would download them here
    # wget https://github.com/your-repo/cybersentinel-ai/archive/main.zip
    # unzip main.zip
    # cp -r cybersentinel-ai-main/* .
fi

# Create Prometheus configuration
print_status "Setting up monitoring..."
cat > monitoring/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'cybersentinel-ai'
    static_configs:
      - targets: ['cybersentinel-ai:3000']
    metrics_path: '/metrics'
    scrape_interval: 5s
EOF

# Create Grafana datasource configuration
cat > monitoring/grafana/datasources/prometheus.yml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF

# Create systemd service for Docker Compose
print_status "Creating systemd service..."
sudo tee /etc/systemd/system/cybersentinel-ai.service > /dev/null << EOF
[Unit]
Description=CyberSentinel AI Security Testing Platform
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$APP_DIR
ExecStart=/usr/local/bin/docker-compose -f docker-compose.prod.yml up -d
ExecStop=/usr/local/bin/docker-compose -f docker-compose.prod.yml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

# Configure firewall
print_status "Configuring firewall..."
sudo ufw --force enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 3000/tcp
sudo ufw allow 3001/tcp  # Grafana
sudo ufw allow 9090/tcp  # Prometheus

# Start services
print_status "Starting services..."
sudo systemctl daemon-reload
sudo systemctl enable cybersentinel-ai

# Build and start containers
print_status "Building and starting containers..."
docker-compose -f docker-compose.prod.yml build
docker-compose -f docker-compose.prod.yml up -d

# Wait for services to start
print_status "Waiting for services to start..."
sleep 30

# Check service status
if docker-compose -f docker-compose.prod.yml ps | grep -q "Up"; then
    print_success "Services are running successfully"
else
    print_error "Some services failed to start"
    docker-compose -f docker-compose.prod.yml logs
    exit 1
fi

# Display final information
print_success "CyberSentinel AI deployment completed!"
echo ""
echo "📋 Deployment Summary:"
echo "====================="
echo "Application URL: http://$PUBLIC_IP"
echo "Health Check: http://$PUBLIC_IP/health"
echo "Grafana Dashboard: http://$PUBLIC_IP:3001 (admin/$(grep GRAFANA_PASSWORD .env | cut -d'=' -f2))"
echo "Prometheus Metrics: http://$PUBLIC_IP:9090"
echo ""
echo "🔧 Next Steps:"
echo "1. Edit $APP_DIR/.env and add your AI API keys"
echo "2. Restart services: sudo systemctl restart cybersentinel-ai"
echo "3. Configure SSL certificate (optional)"
echo "4. Set up domain name (optional)"
echo ""
echo "📊 Monitoring:"
echo "- Application logs: docker-compose -f docker-compose.prod.yml logs -f"
echo "- Service status: docker-compose -f docker-compose.prod.yml ps"
echo "- System status: sudo systemctl status cybersentinel-ai"
echo ""
echo "🛡️ Security Features:"
echo "- Nginx reverse proxy with rate limiting"
echo "- Security headers enabled"
echo "- Firewall configured"
echo "- Container isolation"
echo "- Health checks enabled"
echo ""
print_success "Deployment completed successfully!"
print_warning "Remember to add your AI API keys to the .env file!"
