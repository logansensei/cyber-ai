# 🚀 CyberSentinel AI - AWS EC2 Deployment Guide

## Overview

This guide will help you deploy CyberSentinel AI on AWS EC2 with production-ready security, monitoring, and scalability features.

## 📋 Prerequisites

- AWS Account with EC2 access
- Basic knowledge of AWS services
- SSH client (PuTTY, Terminal, etc.)
- Domain name (optional, for SSL)

## 🏗️ Architecture

```
Internet → CloudFront (Optional) → Application Load Balancer → EC2 Instance
                                                              ↓
                                                         Nginx (Reverse Proxy)
                                                              ↓
                                                         Node.js Application
                                                              ↓
                                                         PM2 Process Manager
```

## 🚀 Quick Deployment

### Step 1: Launch EC2 Instance

1. **Login to AWS Console**
   - Go to EC2 Dashboard
   - Click "Launch Instance"

2. **Choose AMI**
   - Select "Ubuntu Server 22.04 LTS" (Free tier eligible)
   - Choose t2.micro for testing or t3.medium for production

3. **Configure Instance**
   - Instance Type: t2.micro (free tier) or t3.medium (production)
   - Key Pair: Create new or select existing
   - Security Group: Create new with these rules:
     - SSH (22) - Your IP
     - HTTP (80) - 0.0.0.0/0
     - HTTPS (443) - 0.0.0.0/0
     - Custom TCP (3000) - 0.0.0.0/0

4. **Storage**
   - Root volume: 20 GB (gp3)
   - Add additional volume if needed

5. **Launch Instance**

### Step 2: Connect to Instance

```bash
# Replace with your key file and instance IP
ssh -i "your-key.pem" ubuntu@your-instance-ip
```

### Step 3: Deploy Application

```bash
# Download and run the deployment script
wget https://raw.githubusercontent.com/your-repo/cybersentinel-ai/main/deployment/aws-ec2-setup.sh
chmod +x aws-ec2-setup.sh
./aws-ec2-setup.sh
```

### Step 4: Configure Application

```bash
# Edit environment configuration
sudo nano /opt/cybersentinel-ai/.env

# Add your API keys
OPENAI_API_KEY=sk-your-openai-key-here
GEMINI_API_KEY=your-gemini-key-here

# Restart service
sudo systemctl restart cybersentinel-ai
```

### Step 5: Setup SSL (Optional but Recommended)

```bash
# Install SSL certificate
sudo certbot --nginx -d your-domain.com

# Test automatic renewal
sudo certbot renew --dry-run
```

## 🔧 Manual Deployment

If you prefer manual setup:

### 1. Update System

```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Install Dependencies

```bash
# Install Node.js 18 LTS
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PM2
sudo npm install -g pm2

# Install Nginx
sudo apt install -y nginx

# Install other dependencies
sudo apt install -y git curl wget unzip
```

### 3. Deploy Application

```bash
# Create application directory
sudo mkdir -p /opt/cybersentinel-ai
sudo chown $USER:$USER /opt/cybersentinel-ai
cd /opt/cybersentinel-ai

# Clone repository (replace with your repo)
git clone https://github.com/your-username/cybersentinel-ai.git .

# Install dependencies
npm install --production

# Create environment file
cp env.example .env
nano .env  # Edit with your configuration
```

### 4. Configure Nginx

```bash
# Create Nginx configuration
sudo nano /etc/nginx/sites-available/cybersentinel-ai
```

Add this configuration:

```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/cybersentinel-ai /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
```

### 5. Setup PM2

```bash
# Create PM2 ecosystem file
nano ecosystem.config.js
```

Add this configuration:

```javascript
module.exports = {
  apps: [{
    name: 'cybersentinel-ai',
    script: 'server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true
  }]
};
```

Start the application:

```bash
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

## 🔒 Security Configuration

### 1. Firewall Setup

```bash
# Configure UFW
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
```

### 2. Fail2Ban Setup

```bash
# Install and configure fail2ban
sudo apt install -y fail2ban

# Create jail configuration
sudo nano /etc/fail2ban/jail.local
```

Add this configuration:

```ini
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
```

Start fail2ban:

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 3. SSL Certificate

```bash
# Install certbot
sudo apt install -y certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d your-domain.com

# Test automatic renewal
sudo certbot renew --dry-run
```

## 📊 Monitoring and Logging

### 1. Application Monitoring

```bash
# Check application status
pm2 status
pm2 logs cybersentinel-ai

# Monitor system resources
htop
df -h
free -h
```

### 2. Log Management

```bash
# View application logs
tail -f /opt/cybersentinel-ai/logs/cybersentinel.log

# View Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# View system logs
sudo journalctl -u cybersentinel-ai -f
```

### 3. Health Checks

Create a health check script:

```bash
nano /usr/local/bin/health-check.sh
```

```bash
#!/bin/bash
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health)
if [ "$response" = "200" ]; then
    echo "Service is healthy"
    exit 0
else
    echo "Service is unhealthy (HTTP $response)"
    pm2 restart cybersentinel-ai
    exit 1
fi
```

Make it executable and add to cron:

```bash
chmod +x /usr/local/bin/health-check.sh
crontab -e
# Add: */5 * * * * /usr/local/bin/health-check.sh
```

## 🔄 Backup and Recovery

### 1. Application Backup

```bash
# Create backup script
nano /usr/local/bin/backup-cybersentinel.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/opt/backups/cybersentinel-ai"
DATE=$(date +%Y%m%d_%H%M%S)
APP_DIR="/opt/cybersentinel-ai"

mkdir -p $BACKUP_DIR

# Backup application files
tar -czf $BACKUP_DIR/cybersentinel-ai_$DATE.tar.gz -C $APP_DIR .

# Keep only last 7 days of backups
find $BACKUP_DIR -name "cybersentinel-ai_*.tar.gz" -mtime +7 -delete

echo "Backup completed: cybersentinel-ai_$DATE.tar.gz"
```

### 2. Database Backup (if using database)

```bash
# Add to backup script
pg_dump cybersentinel_ai > $BACKUP_DIR/database_$DATE.sql
```

## 📈 Scaling and Performance

### 1. Horizontal Scaling

For high traffic, consider:

- **Application Load Balancer** with multiple EC2 instances
- **Auto Scaling Group** for automatic scaling
- **RDS** for database (if using database)
- **ElastiCache** for caching
- **CloudFront** for CDN

### 2. Vertical Scaling

```bash
# Upgrade instance type
# Stop instance → Change instance type → Start instance
```

### 3. Performance Optimization

```bash
# Increase Node.js memory limit
export NODE_OPTIONS="--max-old-space-size=4096"

# Optimize PM2 configuration
pm2 start ecosystem.config.js --max-memory-restart 1G
```

## 🚨 Troubleshooting

### Common Issues

1. **Service won't start**
   ```bash
   sudo systemctl status cybersentinel-ai
   sudo journalctl -u cybersentinel-ai -f
   ```

2. **Port already in use**
   ```bash
   sudo netstat -tulpn | grep :3000
   sudo kill -9 <PID>
   ```

3. **Permission denied**
   ```bash
   sudo chown -R $USER:$USER /opt/cybersentinel-ai
   chmod -R 755 /opt/cybersentinel-ai
   ```

4. **Nginx configuration error**
   ```bash
   sudo nginx -t
   sudo systemctl reload nginx
   ```

### Log Locations

- Application logs: `/opt/cybersentinel-ai/logs/`
- Nginx logs: `/var/log/nginx/`
- System logs: `sudo journalctl -u cybersentinel-ai`
- PM2 logs: `pm2 logs cybersentinel-ai`

## 💰 Cost Optimization

### 1. Instance Types

- **t2.micro**: Free tier (1 vCPU, 1 GB RAM) - Testing only
- **t3.small**: $15-20/month (2 vCPU, 2 GB RAM) - Small production
- **t3.medium**: $30-40/month (2 vCPU, 4 GB RAM) - Medium production
- **t3.large**: $60-80/month (2 vCPU, 8 GB RAM) - Large production

### 2. Cost Saving Tips

- Use Spot Instances for non-critical workloads
- Enable CloudWatch detailed monitoring only when needed
- Use S3 for log storage instead of EBS
- Implement auto-scaling to scale down during low usage

## 🔐 Security Best Practices

1. **Regular Updates**
   ```bash
   sudo apt update && sudo apt upgrade -y
   npm audit fix
   ```

2. **Monitor Security**
   ```bash
   # Check for security updates
   sudo apt list --upgradable
   
   # Monitor failed login attempts
   sudo fail2ban-client status
   ```

3. **Backup Strategy**
   - Daily automated backups
   - Test restore procedures
   - Store backups in different AWS region

4. **Access Control**
   - Use IAM roles instead of access keys
   - Enable MFA for AWS console
   - Regular access review

## 📞 Support

- **Documentation**: [GitHub Wiki](https://github.com/cybersentinel-ai/cybersentinel-ai/wiki)
- **Issues**: [GitHub Issues](https://github.com/cybersentinel-ai/cybersentinel-ai/issues)
- **Community**: [Discord](https://discord.gg/cybersentinel-ai)

---

**CyberSentinel AI - Professional API Security Testing Platform**
*Deployed on AWS • Production Ready • Enterprise Grade*
