// ===== CORE APPLICATION STATE =====
const appState = {
    apiSpec: null,
    endpoints: [],
    scanRunning: false,
    findings: [],
    aiPayloads: [],
    scanProgress: 0,
    aiProvider: null,
    aiApiKey: null,
    aiConnected: false,
    totalPayloadsGenerated: 0,
    professionalTester: null,
    testResults: [],
    currentTestSession: null,
    selectedTests: [],
    currentTab: 'findings'
};

// ===== AI CONFIGURATION =====
const AI_CONFIGS = {
    openai: {
        endpoint: 'https://api.openai.com/v1/chat/completions',
        model: 'gpt-4',
        headers: (key) => ({
            'Authorization': `Bearer ${key}`,
            'Content-Type': 'application/json'
        })
    },
    gemini: {
        endpoint: (key) => `https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${key}`,
        headers: () => ({
            'Content-Type': 'application/json'
        })
    }
};

// ===== OWASP API TOP 10 TEST CASES =====
const OWASP_TESTS = [
    { id: 'api1', name: 'Broken Object Level Authorization (BOLA/IDOR)', category: 'Authorization' },
    { id: 'api2', name: 'Broken User Authentication', category: 'Authentication' },
    { id: 'api3', name: 'Excessive Data Exposure', category: 'Data Protection' },
    { id: 'api4', name: 'Lack of Resources & Rate Limiting', category: 'Resource Management' },
    { id: 'api5', name: 'Broken Function Level Authorization', category: 'Authorization' },
    { id: 'api6', name: 'Mass Assignment', category: 'Data Validation' },
    { id: 'api7', name: 'Security Misconfiguration', category: 'Configuration' },
    { id: 'api8', name: 'Injection', category: 'Input Validation' },
    { id: 'api9', name: 'Improper Assets Management', category: 'Asset Management' },
    { id: 'api10', name: 'Insufficient Logging & Monitoring', category: 'Monitoring' }
];

// ===== INITIALIZATION =====
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    
    // Initialize all advanced features
    initializeTheme();
    initializeMatrixEffect();
    initializeKeyboardShortcuts();
    initializePWA();
    initializeSearch();
    initializePerformanceMonitoring();
    initializeErrorTracking();
    
    populateTestOptions();
    updateUI();
    
    addConsoleLog('info', '[INIT] All systems initialized and ready');
});

function initializeApp() {
    console.log('🛡️ CyberSentinel AI - Initializing...');
    
    // Initialize status
    updateStatus('Ready', 'ready');
    
    // Initialize professional tester
    appState.professionalTester = {
        runComprehensiveTest: async (endpoints, options) => {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    endpoints: endpoints,
                    tests: options.selectedVulnerabilities.map(id => ({ id, name: id })),
                    aiProvider: appState.aiProvider,
                    aiApiKey: appState.aiApiKey,
                    options: options
                })
            });
            const result = await response.json();
            return result.testResults;
        }
    };
}

function setupEventListeners() {
    // AI Provider change
    document.getElementById('aiProvider').addEventListener('change', updateAIFields);
    
    // Auth type change
    document.getElementById('authType').addEventListener('change', updateAuthFields);
    
    // File upload
    document.getElementById('specFile').addEventListener('change', handleFileUpload);
    
    // Drag and drop
    const uploadArea = document.getElementById('uploadArea');
    uploadArea.addEventListener('dragover', handleDragOver);
    uploadArea.addEventListener('dragleave', handleDragLeave);
    uploadArea.addEventListener('drop', handleDrop);
    
    // Modal controls
    document.getElementById('settingsBtn').addEventListener('click', () => showModal('settingsModal'));
    document.getElementById('helpBtn').addEventListener('click', () => showModal('helpModal'));
    
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const tabName = e.target.getAttribute('onclick').match(/'([^']+)'/)[1];
            switchTab(tabName);
        });
    });
}

// ===== UI UPDATES =====
function updateUI() {
    updateStatus();
    updateProgress();
    updateResults();
}

function updateStatus(text = null, type = null) {
    const statusText = document.getElementById('statusText');
    const statusDot = document.getElementById('statusDot');
    const connectionBadge = document.getElementById('connectionBadge');
    
    if (text) {
        statusText.textContent = text;
    }
    
    if (type) {
        statusDot.className = `status-dot ${type}`;
    }
    
    if (connectionBadge) {
        if (appState.aiConnected) {
            connectionBadge.textContent = 'Connected';
            connectionBadge.className = 'card-badge secure';
        } else {
            connectionBadge.textContent = 'Not Connected';
            connectionBadge.className = 'card-badge';
        }
    }
}

function updateProgress() {
    const progressContainer = document.getElementById('progressContainer');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    
    if (appState.scanRunning) {
        progressContainer.style.display = 'block';
        progressFill.style.width = `${appState.scanProgress}%`;
        progressText.textContent = `${Math.round(appState.scanProgress)}%`;
    } else {
        progressContainer.style.display = 'none';
    }
}

function updateResults() {
    updateSummaryCards();
    updateFindingsList();
    updateAIInsights();
    updateRecommendations();
}

function updateSummaryCards() {
    const criticalCount = appState.findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = appState.findings.filter(f => f.severity === 'HIGH').length;
    const mediumCount = appState.findings.filter(f => f.severity === 'MEDIUM').length;
    const lowCount = appState.findings.filter(f => f.severity === 'LOW').length;
    
    document.getElementById('criticalCount').textContent = criticalCount;
    document.getElementById('highCount').textContent = highCount;
    document.getElementById('mediumCount').textContent = mediumCount;
    document.getElementById('lowCount').textContent = lowCount;
    
    // Show results section if there are findings
    const resultsSection = document.getElementById('resultsSection');
    if (appState.findings.length > 0 || appState.scanRunning) {
        resultsSection.style.display = 'block';
    }
}

function updateFindingsList() {
    const findingsList = document.getElementById('findingsList');
    findingsList.innerHTML = '';
    
    appState.findings.forEach(finding => {
        const findingElement = createFindingElement(finding);
        findingsList.appendChild(findingElement);
    });
}

function createFindingElement(finding) {
    const div = document.createElement('div');
    div.className = 'finding-item fade-in';
    
    // Create elements safely to prevent XSS
    const header = document.createElement('div');
    header.className = 'finding-header';
    
    const titleDiv = document.createElement('div');
    const title = document.createElement('div');
    title.className = 'finding-title';
    title.textContent = finding.type || 'Unknown';
    
    const details = document.createElement('div');
    details.className = 'finding-details';
    details.textContent = finding.description || 'No description available';
    
    const severity = document.createElement('div');
    severity.className = `finding-severity ${(finding.severity || 'low').toLowerCase()}`;
    severity.textContent = finding.severity || 'LOW';
    
    const endpoint = document.createElement('div');
    endpoint.className = 'finding-endpoint';
    endpoint.textContent = finding.endpoint || 'Unknown endpoint';
    
    const payload = document.createElement('div');
    payload.className = 'finding-payload';
    payload.textContent = finding.payload || 'No payload';
    
    const confidence = document.createElement('div');
    confidence.className = 'finding-confidence';
    confidence.textContent = `Confidence: ${finding.confidence || 0}%`;
    
    // Assemble elements
    titleDiv.appendChild(title);
    titleDiv.appendChild(details);
    header.appendChild(titleDiv);
    header.appendChild(severity);
    
    div.appendChild(header);
    div.appendChild(endpoint);
    div.appendChild(payload);
    div.appendChild(confidence);
    
    return div;
}

function updateAIInsights() {
    const aiInsights = document.getElementById('aiInsights');
    aiInsights.innerHTML = '';
    
    if (appState.currentTestSession && appState.currentTestSession.aiInsights) {
        appState.currentTestSession.aiInsights.forEach(insight => {
            const insightDiv = document.createElement('div');
            insightDiv.className = 'insight-item';
            
            const title = document.createElement('h4');
            title.textContent = insight.title || 'AI Insight';
            
            const description = document.createElement('p');
            description.textContent = insight.description || 'No description available';
            
            insightDiv.appendChild(title);
            insightDiv.appendChild(description);
            aiInsights.appendChild(insightDiv);
        });
    } else {
        const noInsights = document.createElement('p');
        noInsights.textContent = 'No AI insights available. Enable AI to get intelligent analysis.';
        aiInsights.appendChild(noInsights);
    }
}

function updateRecommendations() {
    const recommendations = document.getElementById('recommendations');
    recommendations.innerHTML = '';
    
    if (appState.currentTestSession && appState.currentTestSession.recommendations) {
        appState.currentTestSession.recommendations.forEach(rec => {
            const recDiv = document.createElement('div');
            recDiv.className = 'recommendation-item';
            
            const title = document.createElement('h4');
            title.textContent = rec.title || 'Recommendation';
            
            const description = document.createElement('p');
            description.textContent = rec.description || 'No description available';
            
            const actionsList = document.createElement('ul');
            if (rec.actions && Array.isArray(rec.actions)) {
                rec.actions.forEach(action => {
                    const li = document.createElement('li');
                    li.textContent = action;
                    actionsList.appendChild(li);
                });
            }
            
            recDiv.appendChild(title);
            recDiv.appendChild(description);
            recDiv.appendChild(actionsList);
            recommendations.appendChild(recDiv);
        });
    } else {
        const noRecs = document.createElement('p');
        noRecs.textContent = 'No recommendations available. Run a scan to get security recommendations.';
        recommendations.appendChild(noRecs);
    }
}

// ===== AI CONFIGURATION =====
function updateAIFields() {
    const provider = document.getElementById('aiProvider').value;
    const apiKeyCard = document.getElementById('apiKeyCard');
    
    appState.aiProvider = provider;
    
    if (provider === 'none') {
        apiKeyCard.style.display = 'none';
        appState.aiApiKey = null;
        appState.aiConnected = false;
    } else {
        apiKeyCard.style.display = 'block';
    }
    
    updateUI();
}

async function testAIConnection() {
    const provider = document.getElementById('aiProvider').value;
    const apiKey = document.getElementById('aiApiKey').value;
    
    if (!provider || provider === 'none') {
        addConsoleLog('warning', '[AI] No AI provider selected');
        return;
    }
    
    if (!apiKey) {
        addConsoleLog('error', '[AI] Please enter your API key');
        return;
    }
    
    // Validate API key format
    if (!validateInput(apiKey, 'apiKey')) {
        addConsoleLog('error', '[AI] Invalid API key format');
        return;
    }
    
    appState.aiProvider = sanitizeInput(provider);
    appState.aiApiKey = sanitizeInput(apiKey);
    
    updateStatus('Testing AI connection...', 'scanning');
    
    try {
        const response = await fetch('/api/test-ai-connection', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ provider, apiKey })
        });
        
        const result = await response.json();
        
        if (result.success) {
            appState.aiConnected = true;
            updateStatus('AI Connected', 'ready');
            addConsoleLog('success', '[AI] Connection successful');
        } else {
            appState.aiConnected = false;
            updateStatus('AI Connection Failed', 'error');
            addConsoleLog('error', `[AI] Connection failed: ${result.message}`);
        }
    } catch (error) {
        appState.aiConnected = false;
        updateStatus('AI Connection Error', 'error');
        addConsoleLog('error', `[AI] Connection error: ${error.message}`);
    }
    
    updateUI();
}

// ===== FILE UPLOAD =====
function handleFileUpload(event) {
    const file = event.target.files[0];
    if (file) {
        processFile(file);
    }
}

function handleDragOver(event) {
    event.preventDefault();
    event.currentTarget.classList.add('dragover');
}

function handleDragLeave(event) {
    event.preventDefault();
    event.currentTarget.classList.remove('dragover');
}

function handleDrop(event) {
    event.preventDefault();
    event.currentTarget.classList.remove('dragover');
    
    const files = event.dataTransfer.files;
    if (files.length > 0) {
        processFile(files[0]);
    }
}

async function processFile(file) {
    addConsoleLog('info', `[UPLOAD] Processing file: ${file.name}`);
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/api/parse-spec', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
            appState.apiSpec = result.spec;
            appState.endpoints = result.endpoints;
            
            displayEndpoints(result.endpoints);
            addConsoleLog('success', `[UPLOAD] Successfully parsed ${result.totalEndpoints} endpoints`);
        } else {
            addConsoleLog('error', `[UPLOAD] Failed to parse file: ${result.error}`);
        }
    } catch (error) {
        addConsoleLog('error', `[UPLOAD] Error processing file: ${error.message}`);
    }
}

function displayEndpoints(endpoints) {
    const endpointList = document.getElementById('endpointList');
    const specPreview = document.getElementById('specPreview');
    
    endpointList.innerHTML = '';
    
    endpoints.forEach(endpoint => {
        const endpointElement = document.createElement('div');
        endpointElement.className = 'endpoint-item';
        
        const methodDiv = document.createElement('div');
        methodDiv.className = `endpoint-method ${(endpoint.method || 'GET').toLowerCase()}`;
        methodDiv.textContent = endpoint.method || 'GET';
        
        const pathDiv = document.createElement('div');
        pathDiv.className = 'endpoint-path';
        pathDiv.textContent = endpoint.path || 'Unknown path';
        
        endpointElement.appendChild(methodDiv);
        endpointElement.appendChild(pathDiv);
        endpointList.appendChild(endpointElement);
    });
    
    specPreview.style.display = 'block';
}

function clearSpec() {
    appState.apiSpec = null;
    appState.endpoints = [];
    document.getElementById('specFile').value = '';
    document.getElementById('specPreview').style.display = 'none';
    addConsoleLog('info', '[UPLOAD] API specification cleared');
}

// ===== AUTHENTICATION =====
function updateAuthFields() {
    const authType = document.getElementById('authType').value;
    const authConfig = document.getElementById('authConfig');
    
    if (authType === 'none') {
        authConfig.style.display = 'none';
    } else {
        authConfig.style.display = 'block';
        
        const placeholder = getAuthPlaceholder(authType);
        document.getElementById('authConfigText').placeholder = placeholder;
    }
}

function getAuthPlaceholder(authType) {
    const placeholders = {
        'bearer': '{"Authorization": "Bearer your-token-here"}',
        'apikey': '{"X-API-Key": "your-api-key-here"}',
        'oauth2': '{"Authorization": "Bearer your-oauth-token-here"}',
        'basic': '{"Authorization": "Basic base64-encoded-credentials"}',
        'custom': '{"Custom-Header": "value"}'
    };
    
    return placeholders[authType] || '{"Header": "value"}';
}

// ===== TEST SELECTION =====
function populateTestOptions() {
    const testOptions = document.getElementById('testOptions');
    testOptions.innerHTML = '';
    
    OWASP_TESTS.forEach(test => {
        const optionElement = document.createElement('div');
        optionElement.className = 'test-option';
        
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.id = `test-${test.id}`;
        checkbox.value = test.id;
        checkbox.addEventListener('change', updateSelectedTests);
        
        const label = document.createElement('label');
        label.htmlFor = `test-${test.id}`;
        label.textContent = test.name;
        
        optionElement.appendChild(checkbox);
        optionElement.appendChild(label);
        testOptions.appendChild(optionElement);
    });
}

function updateSelectedTests() {
    const checkboxes = document.querySelectorAll('#testOptions input[type="checkbox"]:checked');
    appState.selectedTests = Array.from(checkboxes).map(cb => cb.value);
    
    addConsoleLog('info', `[CONFIG] ${appState.selectedTests.length} tests selected`);
}

// ===== SCANNING =====
async function startScan() {
    if (!appState.apiSpec) {
        addConsoleLog('error', '[ERROR] Please upload an API specification first');
        return;
    }
    
    if (appState.selectedTests.length === 0) {
        addConsoleLog('error', '[ERROR] Please select at least one test to run');
        return;
    }
    
    appState.scanRunning = true;
    appState.findings = [];
    appState.scanProgress = 0;
    
    // Update UI
    document.getElementById('startBtn').style.display = 'none';
    document.getElementById('stopBtn').style.display = 'inline-flex';
    updateStatus('Scanning...', 'scanning');
    updateUI();
    
    addConsoleLog('success', '[SCAN] Starting professional security scan...');
    addConsoleLog('info', `[CONFIG] ${appState.selectedTests.length} OWASP API Top 10 test modules selected`);
    
    try {
        // Simulate scan progress
        const progressInterval = setInterval(() => {
            if (appState.scanRunning && appState.scanProgress < 90) {
                appState.scanProgress += Math.random() * 10;
                updateProgress();
            }
        }, 1000);
        
        // Run professional scan
        const testResults = await appState.professionalTester.runComprehensiveTest(
            appState.endpoints,
            {
                selectedVulnerabilities: appState.selectedTests,
                maxConcurrent: parseInt(document.getElementById('maxConcurrent').value),
                delayBetweenRequests: parseInt(document.getElementById('requestDelay').value),
                timeout: parseInt(document.getElementById('timeout').value),
                enableAI: appState.aiConnected
            }
        );
        
        clearInterval(progressInterval);
        
        // Process results
        appState.testResults.push(testResults);
        appState.currentTestSession = testResults;
        appState.findings = testResults.vulnerabilities || [];
        appState.scanProgress = 100;
        
        addConsoleLog('success', '[SCAN] Security scan completed successfully');
        addConsoleLog('info', `[RESULTS] Found ${testResults.summary.vulnerabilitiesFound} vulnerabilities`);
        
        completeScan();
        
    } catch (error) {
        addConsoleLog('error', `[ERROR] Scan failed: ${error.message}`);
        completeScan();
    }
}

function stopScan() {
    appState.scanRunning = false;
    appState.scanProgress = 0;
    
    document.getElementById('startBtn').style.display = 'inline-flex';
    document.getElementById('stopBtn').style.display = 'none';
    updateStatus('Scan Stopped', 'error');
    updateUI();
    
    addConsoleLog('warning', '[SCAN] Scan stopped by user');
}

function completeScan() {
    appState.scanRunning = false;
    appState.scanProgress = 100;
    
    document.getElementById('startBtn').style.display = 'inline-flex';
    document.getElementById('stopBtn').style.display = 'none';
    updateStatus('Scan Complete', 'ready');
    updateUI();
}

// ===== RESULTS MANAGEMENT =====
function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[onclick="switchTab('${tabName}')"]`).classList.add('active');
    
    // Update tab panels
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    document.getElementById(`${tabName}Panel`).classList.add('active');
    
    appState.currentTab = tabName;
}

function exportResults() {
    if (appState.findings.length === 0) {
        addConsoleLog('warning', '[EXPORT] No results to export');
        return;
    }
    
    const exportData = {
        timestamp: new Date().toISOString(),
        summary: {
            totalFindings: appState.findings.length,
            critical: appState.findings.filter(f => f.severity === 'CRITICAL').length,
            high: appState.findings.filter(f => f.severity === 'HIGH').length,
            medium: appState.findings.filter(f => f.severity === 'MEDIUM').length,
            low: appState.findings.filter(f => f.severity === 'LOW').length
        },
        findings: appState.findings,
        aiInsights: appState.currentTestSession?.aiInsights || [],
        recommendations: appState.currentTestSession?.recommendations || []
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybersentinel-scan-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    addConsoleLog('success', '[EXPORT] Results exported successfully');
}

function clearResults() {
    appState.findings = [];
    appState.testResults = [];
    appState.currentTestSession = null;
    updateUI();
    addConsoleLog('info', '[RESULTS] Results cleared');
}

// ===== CONSOLE LOGGING =====
function addConsoleLog(type, message) {
    const consoleContent = document.getElementById('consoleContent');
    const timestamp = new Date().toLocaleTimeString();
    
    const logElement = document.createElement('div');
    logElement.className = `console-log ${type}`;
    
    const timeSpan = document.createElement('span');
    timeSpan.className = 'log-time';
    timeSpan.textContent = `[${timestamp}]`;
    
    const messageSpan = document.createElement('span');
    messageSpan.textContent = ` ${message}`;
    
    logElement.appendChild(timeSpan);
    logElement.appendChild(messageSpan);
    consoleContent.appendChild(logElement);
    consoleContent.scrollTop = consoleContent.scrollHeight;
    
    // Also log to browser console
    console[type === 'error' ? 'error' : type === 'warning' ? 'warn' : 'log'](message);
}

function clearConsole() {
    document.getElementById('consoleContent').innerHTML = '';
}

// ===== MODAL CONTROLS =====
function showModal(modalId) {
    document.getElementById(modalId).classList.add('active');
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

// ===== UTILITY FUNCTIONS =====
function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    return input
        .replace(/[<>]/g, '') // Remove potential HTML tags
        .replace(/javascript:/gi, '') // Remove javascript: protocol
        .replace(/on\w+=/gi, '') // Remove event handlers
        .trim();
}

function validateInput(input, type = 'text') {
    if (!input || typeof input !== 'string') return false;
    
    switch (type) {
        case 'email':
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
        case 'url':
            try {
                new URL(input);
                return true;
            } catch {
                return false;
            }
        case 'apiKey':
            return input.length >= 10 && /^[a-zA-Z0-9\-_]+$/.test(input);
        case 'number':
            return !isNaN(parseFloat(input)) && isFinite(input);
        default:
            return input.length > 0;
    }
}

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    if (!input) return;
    
    const button = input.nextElementSibling;
    const icon = button?.querySelector('i');
    
    if (input.type === 'password') {
        input.type = 'text';
        if (icon) icon.className = 'fas fa-eye-slash';
    } else {
        input.type = 'password';
        if (icon) icon.className = 'fas fa-eye';
    }
}

function showHelp() {
    showModal('helpModal');
}

function showAbout() {
    addConsoleLog('info', '[ABOUT] CyberSentinel AI v1.0.0 - Professional API Security Testing Platform');
}

// ===== MATRIX RAIN EFFECT =====
function initializeMatrixEffect() {
    try {
        const canvas = document.createElement('canvas');
        canvas.className = 'matrix-rain';
        canvas.id = 'matrix';
        canvas.style.position = 'fixed';
        canvas.style.top = '0';
        canvas.style.left = '0';
        canvas.style.zIndex = '-3';
        canvas.style.pointerEvents = 'none';
        document.body.appendChild(canvas);
        
        const ctx = canvas.getContext('2d');
        if (!ctx) {
            console.warn('Canvas context not available, skipping matrix effect');
            return;
        }
        
        let animationId;
        let isRunning = false;
        
        function resizeCanvas() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }
        
        function drawMatrix() {
            if (!isRunning) return;
            
            try {
                ctx.fillStyle = 'rgba(10, 10, 10, 0.04)';
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                
                ctx.fillStyle = '#00d4ff';
                ctx.font = '10px monospace';
                
                const matrix = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789@#$%^&*()*&^%+-/~{[|`]}";
                const matrixArray = matrix.split("");
                const fontSize = 10;
                const columns = Math.floor(canvas.width / fontSize);
                
                for (let i = 0; i < columns; i++) {
                    const text = matrixArray[Math.floor(Math.random() * matrixArray.length)];
                    const x = i * fontSize;
                    const y = (Math.random() * canvas.height) % canvas.height;
                    
                    ctx.fillText(text, x, y);
                }
                
                animationId = requestAnimationFrame(drawMatrix);
            } catch (error) {
                console.warn('Matrix effect error:', error);
                isRunning = false;
            }
        }
        
        function startEffect() {
            if (!isRunning) {
                isRunning = true;
                resizeCanvas();
                drawMatrix();
            }
        }
        
        function stopEffect() {
            isRunning = false;
            if (animationId) {
                cancelAnimationFrame(animationId);
            }
        }
        
        // Start effect
        startEffect();
        
        // Handle resize
        window.addEventListener('resize', () => {
            resizeCanvas();
        });
        
        // Handle visibility change to pause when tab is not visible
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                stopEffect();
            } else {
                startEffect();
            }
        });
        
        // Cleanup on page unload
        window.addEventListener('beforeunload', stopEffect);
        
    } catch (error) {
        console.warn('Failed to initialize matrix effect:', error);
    }
}

// ===== THEME MANAGEMENT =====
function initializeTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeUI(savedTheme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeUI(newTheme);
    
    addConsoleLog('info', `[THEME] Switched to ${newTheme} theme`);
}

function updateThemeUI(theme) {
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        const icon = themeToggle.querySelector('i');
        if (icon) {
            icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
    }
}

// ===== KEYBOARD SHORTCUTS =====
function initializeKeyboardShortcuts() {
    document.addEventListener('keydown', (event) => {
        // Only trigger if not in input fields
        if (event.target.tagName === 'INPUT' || event.target.tagName === 'TEXTAREA') {
            return;
        }
        
        if (event.ctrlKey || event.metaKey) {
            switch (event.key) {
                case 's':
                    event.preventDefault();
                    if (appState.endpoints.length > 0) {
                        startScan();
                    } else {
                        addConsoleLog('warning', '[SHORTCUT] No endpoints loaded. Upload API specification first.');
                    }
                    break;
                case 'e':
                    event.preventDefault();
                    if (appState.findings.length > 0) {
                        exportResults();
                    } else {
                        addConsoleLog('warning', '[SHORTCUT] No results to export. Run a scan first.');
                    }
                    break;
                case 'h':
                    event.preventDefault();
                    showHelp();
                    break;
                case 't':
                    event.preventDefault();
                    toggleTheme();
                    break;
                case 'c':
                    event.preventDefault();
                    clearResults();
                    break;
            }
        }
        
        // Function keys
        switch (event.key) {
            case 'F1':
                event.preventDefault();
                showHelp();
                break;
            case 'F5':
                event.preventDefault();
                if (appState.scanRunning) {
                    addConsoleLog('warning', '[SHORTCUT] Scan already running');
                } else if (appState.endpoints.length > 0) {
                    startScan();
                }
                break;
        }
    });
}

// ===== PROGRESSIVE WEB APP FEATURES =====
function initializePWA() {
    // Register service worker
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/sw.js')
            .then(registration => {
                console.log('Service Worker registered:', registration);
            })
            .catch(error => {
                console.log('Service Worker registration failed:', error);
            });
    }
    
    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission().then(permission => {
            if (permission === 'granted') {
                addConsoleLog('info', '[PWA] Notifications enabled');
            }
        });
    }
}

function showNotification(title, body, icon = '/icons/icon-192x192.png') {
    if (Notification.permission === 'granted') {
        new Notification(title, { body, icon });
    }
}

// ===== ADVANCED SEARCH AND FILTERING =====
function initializeSearch() {
    const searchInput = document.getElementById('searchInput');
    if (!searchInput) return;
    
    let searchTimeout;
    searchInput.addEventListener('input', (event) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            const query = event.target.value.toLowerCase().trim();
            if (query.length > 0) {
                performSearch(query);
            } else {
                clearSearch();
            }
        }, 300);
    });
}

function performSearch(query) {
    if (!appState.findings || appState.findings.length === 0) {
        addConsoleLog('warning', '[SEARCH] No findings to search');
        return;
    }
    
    const filteredFindings = appState.findings.filter(finding => 
        finding.type.toLowerCase().includes(query) ||
        finding.description.toLowerCase().includes(query) ||
        finding.endpoint.toLowerCase().includes(query) ||
        finding.payload.toLowerCase().includes(query)
    );
    
    displaySearchResults(filteredFindings, query);
}

function displaySearchResults(results, query) {
    const findingsList = document.getElementById('findingsList');
    if (!findingsList) return;
    
    findingsList.innerHTML = '';
    
    if (results.length === 0) {
        const noResults = document.createElement('div');
        noResults.className = 'no-results';
        noResults.innerHTML = `
            <div class="no-results-content">
                <i class="fas fa-search"></i>
                <h3>No results found</h3>
                <p>No findings match "${query}"</p>
            </div>
        `;
        findingsList.appendChild(noResults);
        return;
    }
    
    results.forEach(finding => {
        const findingElement = createFindingElement(finding);
        findingsList.appendChild(findingElement);
    });
    
    addConsoleLog('info', `[SEARCH] Found ${results.length} results for "${query}"`);
}

function clearSearch() {
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.value = '';
    }
    updateFindingsList();
}

// ===== PERFORMANCE MONITORING =====
function initializePerformanceMonitoring() {
    if ('performance' in window) {
        window.addEventListener('load', () => {
            const perfData = performance.getEntriesByType('navigation')[0];
            const loadTime = perfData.loadEventEnd - perfData.loadEventStart;
            
            addConsoleLog('info', `[PERFORMANCE] Page loaded in ${loadTime.toFixed(2)}ms`);
            
            // Monitor memory usage
            if ('memory' in performance) {
                const memory = performance.memory;
                const usedMB = (memory.usedJSHeapSize / 1048576).toFixed(2);
                const totalMB = (memory.totalJSHeapSize / 1048576).toFixed(2);
                addConsoleLog('info', `[PERFORMANCE] Memory usage: ${usedMB}MB / ${totalMB}MB`);
            }
        });
    }
}

// ===== ERROR TRACKING =====
function initializeErrorTracking() {
    window.addEventListener('error', (event) => {
        const errorData = {
            message: event.message,
            filename: event.filename,
            lineno: event.lineno,
            colno: event.colno,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            url: window.location.href
        };
        
        addConsoleLog('error', `[ERROR] ${event.message} at ${event.filename}:${event.lineno}`);
        
        // Send to server for tracking
        fetch('/api/track-error', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(errorData)
        }).catch(console.error);
    });
    
    window.addEventListener('unhandledrejection', (event) => {
        addConsoleLog('error', `[PROMISE REJECTION] ${event.reason}`);
        event.preventDefault();
    });
}

// ===== INITIALIZATION =====
console.log('🛡️ CyberSentinel AI - Professional API Security Testing Platform');
console.log('🚀 Initializing advanced security testing capabilities...');
