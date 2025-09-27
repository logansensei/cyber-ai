# 🚀 CyberSentinel AI - Deployment Guide

## Quick Start

### Option 1: One-Click AWS Deployment

```bash
# On your AWS EC2 instance (Ubuntu 22.04+)
wget https://raw.githubusercontent.com/your-repo/cybersentinel-ai/main/deployment/deploy-aws.sh
chmod +x deploy-aws.sh
./deploy-aws.sh
```

### Option 2: Manual AWS Deployment

```bash
# On your AWS EC2 instance
wget https://raw.githubusercontent.com/your-repo/cybersentinel-ai/main/deployment/aws-ec2-setup.sh
chmod +x aws-ec2-setup.sh
./aws-ec2-setup.sh
```

### Option 3: Docker Deployment

```bash
# Clone the repository
git clone https://github.com/your-repo/cybersentinel-ai.git
cd cybersentinel-ai

# Copy production configuration
cp deployment/docker-compose.prod.yml docker-compose.yml
cp deployment/nginx/nginx.conf nginx/

# Create environment file
cp env.example .env
# Edit .env with your API keys

# Start services
docker-compose up -d
```

## 📋 Prerequisites

### For AWS EC2:
- AWS Account with EC2 access
- EC2 instance running Ubuntu 22.04 LTS
- Security group allowing ports 22, 80, 443, 3000
- At least 2GB RAM and 20GB storage

### For Docker:
- Docker and Docker Compose installed
- At least 2GB RAM available
- Ports 80, 443, 3000, 3001, 9090 available

## 🔧 Configuration

### 1. Environment Variables

Create a `.env` file with your configuration:

```env
# Required: AI Provider API Keys
OPENAI_API_KEY=sk-your-openai-key-here
GEMINI_API_KEY=your-gemini-key-here

# Optional: Security Configuration
JWT_SECRET=your-jwt-secret
ENCRYPTION_KEY=your-encryption-key

# Optional: Feature Flags
ENABLE_AI=true
ENABLE_RATE_LIMITING=true
ENABLE_LOGGING=true
```

### 2. AI Provider Setup

#### OpenAI Setup:
1. Get API key from [OpenAI Platform](https://platform.openai.com/api-keys)
2. Add to `.env` file as `OPENAI_API_KEY`
3. Ensure you have sufficient credits

#### Google Gemini Setup:
1. Get API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Add to `.env` file as `GEMINI_API_KEY`
3. Enable the Gemini API in Google Cloud Console

## 🌐 Accessing the Application

After deployment, access the application at:

- **Main Application**: `http://your-server-ip`
- **Health Check**: `http://your-server-ip/health`
- **Grafana Dashboard**: `http://your-server-ip:3001` (admin/password)
- **Prometheus Metrics**: `http://your-server-ip:9090`

## 🔒 Security Features

### Automatic Security Configuration:
- ✅ Nginx reverse proxy with rate limiting
- ✅ Security headers (XSS, CSRF, etc.)
- ✅ Firewall configuration (UFW)
- ✅ Fail2ban protection
- ✅ SSL/TLS support
- ✅ Container isolation
- ✅ Health checks and monitoring

### Manual Security Steps:
1. **Change default passwords** in `.env` file
2. **Configure SSL certificate** for HTTPS
3. **Set up domain name** (optional)
4. **Configure monitoring alerts**

## 📊 Monitoring and Logs

### View Logs:
```bash
# Application logs
docker-compose logs -f cybersentinel-ai

# Nginx logs
docker-compose logs -f nginx

# All services
docker-compose logs -f
```

### Monitor Performance:
- **Grafana Dashboard**: `http://your-server-ip:3001`
- **Prometheus Metrics**: `http://your-server-ip:9090`
- **System Resources**: `htop`, `df -h`, `free -h`

### Health Checks:
```bash
# Check service status
docker-compose ps

# Test application health
curl http://your-server-ip/health

# Check system resources
docker stats
```

## 🔄 Maintenance

### Update Application:
```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose build
docker-compose up -d
```

### Backup Data:
```bash
# Backup application data
tar -czf backup-$(date +%Y%m%d).tar.gz uploads/ logs/ config/

# Backup database (if using)
docker-compose exec postgres pg_dump -U cybersentinel cybersentinel_ai > backup.sql
```

### Restore Data:
```bash
# Restore application data
tar -xzf backup-20231201.tar.gz

# Restore database (if using)
docker-compose exec -T postgres psql -U cybersentinel cybersentinel_ai < backup.sql
```

## 🚨 Troubleshooting

### Common Issues:

1. **Service won't start**
   ```bash
   # Check logs
   docker-compose logs cybersentinel-ai
   
   # Check configuration
   docker-compose config
   
   # Restart services
   docker-compose restart
   ```

2. **Port already in use**
   ```bash
   # Check what's using the port
   sudo netstat -tulpn | grep :3000
   
   # Kill the process
   sudo kill -9 <PID>
   ```

3. **Permission denied**
   ```bash
   # Fix permissions
   sudo chown -R $USER:$USER .
   chmod -R 755 .
   ```

4. **Out of memory**
   ```bash
   # Check memory usage
   free -h
   docker stats
   
   # Increase swap space
   sudo fallocate -l 2G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```

### Log Locations:
- Application logs: `./logs/`
- Nginx logs: `docker-compose logs nginx`
- System logs: `sudo journalctl -u docker`

## 📈 Scaling

### Horizontal Scaling:
1. **Load Balancer**: Use AWS ALB or CloudFlare
2. **Multiple Instances**: Deploy on multiple EC2 instances
3. **Auto Scaling**: Configure AWS Auto Scaling Group
4. **Database**: Use RDS for persistent data

### Vertical Scaling:
1. **Increase Instance Size**: Upgrade EC2 instance type
2. **Add Memory**: Increase RAM allocation
3. **Add CPU**: Increase CPU cores
4. **Add Storage**: Increase disk space

## 💰 Cost Optimization

### AWS Cost Saving Tips:
1. **Use Spot Instances** for non-critical workloads
2. **Enable Auto Scaling** to scale down during low usage
3. **Use S3** for log storage instead of EBS
4. **Monitor CloudWatch** costs
5. **Use Reserved Instances** for predictable workloads

### Resource Optimization:
1. **Monitor Resource Usage**: Use CloudWatch or Grafana
2. **Optimize Container Resources**: Adjust memory/CPU limits
3. **Use Compression**: Enable gzip compression
4. **Cache Static Files**: Use CloudFront or Nginx caching

## 🔐 Security Best Practices

1. **Regular Updates**:
   ```bash
   # Update system packages
   sudo apt update && sudo apt upgrade -y
   
   # Update Docker images
   docker-compose pull
   docker-compose up -d
   ```

2. **Monitor Security**:
   ```bash
   # Check for security updates
   sudo apt list --upgradable
   
   # Monitor failed login attempts
   sudo fail2ban-client status
   ```

3. **Backup Strategy**:
   - Daily automated backups
   - Test restore procedures
   - Store backups in different AWS region

4. **Access Control**:
   - Use IAM roles instead of access keys
   - Enable MFA for AWS console
   - Regular access review

## 📞 Support

- **Documentation**: [GitHub Wiki](https://github.com/cybersentinel-ai/cybersentinel-ai/wiki)
- **Issues**: [GitHub Issues](https://github.com/cybersentinel-ai/cybersentinel-ai/issues)
- **Community**: [Discord](https://discord.gg/cybersentinel-ai)
- **Email**: support@cybersentinel-ai.com

## 🎯 Next Steps

After successful deployment:

1. **Configure AI Providers**: Add your OpenAI/Gemini API keys
2. **Test the Application**: Upload an API specification and run tests
3. **Set up Monitoring**: Configure alerts and dashboards
4. **Configure SSL**: Set up HTTPS with Let's Encrypt
5. **Set up Domain**: Configure your domain name
6. **Backup Strategy**: Implement regular backups
7. **Security Review**: Conduct security assessment

---

**CyberSentinel AI - Professional API Security Testing Platform**
*Deployed on AWS • Production Ready • Enterprise Grade*
