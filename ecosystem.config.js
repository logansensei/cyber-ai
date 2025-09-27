module.exports = {
  apps: [{
    name: 'cybersentinel-ai',
    script: 'server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'development',
      PORT: 3000
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000,
      HOST: '0.0.0.0'
    },
    // Process management
    max_memory_restart: '1G',
    min_uptime: '10s',
    max_restarts: 10,
    restart_delay: 4000,
    
    // Logging
    log_file: './logs/combined.log',
    out_file: './logs/out.log',
    error_file: './logs/error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    
    // Advanced features
    watch: false,
    ignore_watch: ['node_modules', 'logs', 'uploads'],
    watch_options: {
      followSymlinks: false
    },
    
    // Health monitoring
    health_check_grace_period: 3000,
    health_check_interval: 30000,
    
    // Environment specific settings
    node_args: '--max-old-space-size=1024',
    
    // Kill timeout
    kill_timeout: 5000,
    
    // Auto restart on file changes (development only)
    watch: process.env.NODE_ENV === 'development' ? ['server.js', 'app.js'] : false,
    
    // Environment variables
    env_file: '.env'
  }],
  
  // Deployment configuration
  deploy: {
    production: {
      user: 'ubuntu',
      host: 'your-ec2-public-ip',
      ref: 'origin/main',
      repo: 'git@github.com:your-username/cybersentinel-ai.git',
      path: '/opt/cybersentinel-ai',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env production',
      'pre-setup': ''
    }
  }
};
