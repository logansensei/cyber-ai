/**
 * Professional API Security Testing Engine
 * Integrates AI-powered testing with comprehensive vulnerability detection
 */

const ResponseAnalyzer = require('../ai-engine/response-analyzer');
const PayloadGenerator = require('../ai-engine/payload-generator');
const { OWASP_API_TEST_CASES } = require('../test-cases/owasp-api-top10');

class ProfessionalTester {
  constructor(aiProvider = null, aiApiKey = null) {
    this.aiProvider = aiProvider;
    this.aiApiKey = aiApiKey;
    this.responseAnalyzer = new ResponseAnalyzer(aiProvider, aiApiKey);
    this.payloadGenerator = new PayloadGenerator(aiProvider, aiApiKey);
    this.testResults = [];
    this.vulnerabilityDatabase = new Map();
    this.initializeVulnerabilityDatabase();
  }

  initializeVulnerabilityDatabase() {
    // Initialize with OWASP API Top 10
    Object.entries(OWASP_API_TEST_CASES).forEach(([id, vuln]) => {
      this.vulnerabilityDatabase.set(id, {
        ...vuln,
        testCount: 0,
        successCount: 0,
        failureCount: 0,
        lastTested: null
      });
    });
  }

  async runComprehensiveTest(endpoints, options = {}) {
    const {
      selectedVulnerabilities = Object.keys(OWASP_API_TEST_CASES),
      maxConcurrent = 5,
      delayBetweenRequests = 100,
      timeout = 30000,
      retryAttempts = 3,
      enableAI = true
    } = options;

    const testResults = {
      summary: {
        totalEndpoints: endpoints.length,
        totalTests: 0,
        vulnerabilitiesFound: 0,
        criticalVulnerabilities: 0,
        highVulnerabilities: 0,
        mediumVulnerabilities: 0,
        lowVulnerabilities: 0,
        startTime: new Date().toISOString(),
        endTime: null,
        duration: 0
      },
      endpoints: [],
      vulnerabilities: [],
      recommendations: [],
      aiInsights: []
    };

    console.log(`🚀 Starting comprehensive security test on ${endpoints.length} endpoints`);
    console.log(`🎯 Testing ${selectedVulnerabilities.length} vulnerability types`);

    for (const endpoint of endpoints) {
      const endpointResults = await this.testEndpoint(endpoint, {
        selectedVulnerabilities,
        delayBetweenRequests,
        timeout,
        retryAttempts,
        enableAI
      });

      testResults.endpoints.push(endpointResults);
      testResults.vulnerabilities.push(...endpointResults.vulnerabilities);
      testResults.totalTests += endpointResults.totalTests;
    }

    // Generate AI insights if enabled
    if (enableAI && this.aiProvider && this.aiApiKey) {
      testResults.aiInsights = await this.generateAIInsights(testResults);
    }

    // Generate recommendations
    testResults.recommendations = this.generateRecommendations(testResults);

    // Update summary
    testResults.summary.endTime = new Date().toISOString();
    testResults.summary.duration = new Date(testResults.summary.endTime) - new Date(testResults.summary.startTime);
    testResults.summary.vulnerabilitiesFound = testResults.vulnerabilities.length;
    testResults.summary.criticalVulnerabilities = testResults.vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    testResults.summary.highVulnerabilities = testResults.vulnerabilities.filter(v => v.severity === 'HIGH').length;
    testResults.summary.mediumVulnerabilities = testResults.vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
    testResults.summary.lowVulnerabilities = testResults.vulnerabilities.filter(v => v.severity === 'LOW').length;

    this.testResults.push(testResults);
    return testResults;
  }

  async testEndpoint(endpoint, options = {}) {
    const {
      selectedVulnerabilities,
      delayBetweenRequests,
      timeout,
      retryAttempts,
      enableAI
    } = options;

    const endpointResults = {
      endpoint: endpoint,
      totalTests: 0,
      vulnerabilities: [],
      testCases: [],
      startTime: new Date().toISOString(),
      endTime: null,
      duration: 0
    };

    console.log(`🔍 Testing endpoint: ${endpoint.method} ${endpoint.path}`);

    for (const vulnId of selectedVulnerabilities) {
      const vulnerability = this.vulnerabilityDatabase.get(vulnId);
      if (!vulnerability) continue;

      const testCases = vulnerability.testCases || [];
      
      for (const testCase of testCases) {
        try {
          const testResult = await this.executeTestCase(endpoint, testCase, {
            timeout,
            retryAttempts,
            enableAI
          });

          endpointResults.testCases.push(testResult);
          endpointResults.totalTests++;

          if (testResult.vulnerabilityFound) {
            endpointResults.vulnerabilities.push(testResult.vulnerability);
          }

          // Add delay between requests
          if (delayBetweenRequests > 0) {
            await this.delay(delayBetweenRequests);
          }

        } catch (error) {
          console.error(`❌ Test case failed: ${testCase.name}`, error);
          endpointResults.testCases.push({
            testCase: testCase,
            success: false,
            error: error.message,
            vulnerabilityFound: false
          });
        }
      }
    }

    endpointResults.endTime = new Date().toISOString();
    endpointResults.duration = new Date(endpointResults.endTime) - new Date(endpointResults.startTime);

    return endpointResults;
  }

  async executeTestCase(endpoint, testCase, options = {}) {
    const { timeout, retryAttempts, enableAI } = options;
    
    const testResult = {
      testCase: testCase,
      success: false,
      vulnerabilityFound: false,
      vulnerability: null,
      response: null,
      statusCode: null,
      headers: null,
      executionTime: 0,
      attempts: 0,
      aiAnalysis: null
    };

    const startTime = Date.now();

    for (let attempt = 1; attempt <= retryAttempts; attempt++) {
      try {
        testResult.attempts = attempt;
        
        // Generate payloads
        const payloads = await this.generateTestPayloads(endpoint, testCase, enableAI);
        
        for (const payload of payloads) {
          const response = await this.sendRequest(endpoint, testCase, payload, timeout);
          
          testResult.response = response.body;
          testResult.statusCode = response.statusCode;
          testResult.headers = response.headers;
          testResult.success = true;

          // Analyze response for vulnerabilities
          if (enableAI && this.aiProvider && this.aiApiKey) {
            const analysis = await this.responseAnalyzer.analyzeResponse(
              endpoint.path,
              endpoint.method,
              payload,
              response.body,
              response.statusCode,
              response.headers
            );
            testResult.aiAnalysis = analysis;
          }

          // Check for vulnerability indicators
          const vulnerability = this.checkVulnerabilityIndicators(testCase, response, payload);
          if (vulnerability) {
            testResult.vulnerabilityFound = true;
            testResult.vulnerability = vulnerability;
            break;
          }
        }

        if (testResult.success) break;

      } catch (error) {
        console.error(`Attempt ${attempt} failed:`, error.message);
        if (attempt === retryAttempts) {
          testResult.error = error.message;
        }
      }
    }

    testResult.executionTime = Date.now() - startTime;
    return testResult;
  }

  async generateTestPayloads(endpoint, testCase, enableAI) {
    let payloads = [...(testCase.payloads || [])];

    // Generate AI-powered payloads if enabled
    if (enableAI && this.aiProvider && this.aiApiKey) {
      try {
        const aiPayloads = await this.payloadGenerator.generateOWASPPayloads(
          testCase.id.split('-')[0],
          endpoint.path,
          endpoint.method,
          { testCase: testCase }
        );
        payloads.push(...aiPayloads);
      } catch (error) {
        console.error('AI payload generation failed:', error);
      }
    }

    // Apply mutations
    const mutatedPayloads = this.applyPayloadMutations(payloads, testCase);
    payloads.push(...mutatedPayloads);

    return [...new Set(payloads)].slice(0, 20); // Limit to 20 payloads per test case
  }

  applyPayloadMutations(payloads, testCase) {
    const mutations = [];

    for (const payload of payloads) {
      // URL encoding
      mutations.push(encodeURIComponent(payload));
      
      // Double encoding
      mutations.push(encodeURIComponent(encodeURIComponent(payload)));
      
      // Unicode encoding
      if (payload.length < 100) {
        mutations.push(payload.replace(/</g, '\u003c').replace(/>/g, '\u003e'));
      }
      
      // Case variations
      mutations.push(payload.toUpperCase());
      mutations.push(payload.toLowerCase());
      
      // Quote variations
      mutations.push(payload.replace(/'/g, '"'));
      mutations.push(payload.replace(/"/g, "'"));
    }

    return mutations.slice(0, 10); // Limit mutations
  }

  async sendRequest(endpoint, testCase, payload, timeout) {
    const url = this.buildUrl(endpoint, payload);
    const options = this.buildRequestOptions(endpoint, testCase, payload, timeout);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      const body = await response.text();
      
      return {
        statusCode: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body: body
      };

    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  buildUrl(endpoint, payload) {
    let url = endpoint.server + endpoint.path;
    
    // Replace path parameters
    if (endpoint.path.includes('{')) {
      const pathParams = endpoint.path.match(/\{([^}]+)\}/g);
      if (pathParams) {
        pathParams.forEach(param => {
          const paramName = param.slice(1, -1);
          url = url.replace(param, payload);
        });
      }
    }

    // Add query parameters
    if (typeof payload === 'string' && payload.includes('?')) {
      url += payload;
    }

    return url;
  }

  buildRequestOptions(endpoint, testCase, payload, timeout) {
    const options = {
      method: testCase.method || endpoint.method,
      headers: {
        'User-Agent': 'CyberSentinel-AI/1.0',
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json'
      },
      timeout: timeout
    };

    // Add test case headers
    if (testCase.headers) {
      Object.entries(testCase.headers).forEach(([key, value]) => {
        if (typeof value === 'string' && value.includes('{payload}')) {
          options.headers[key] = value.replace('{payload}', payload);
        } else {
          options.headers[key] = value;
        }
      });
    }

    // Add request body for POST/PUT/PATCH
    if (['POST', 'PUT', 'PATCH'].includes(options.method)) {
      if (typeof payload === 'string' && payload.startsWith('{')) {
        try {
          options.body = payload;
        } catch (e) {
          options.body = JSON.stringify({ data: payload });
        }
      } else {
        options.body = JSON.stringify({ data: payload });
      }
    }

    return options;
  }

  checkVulnerabilityIndicators(testCase, response, payload) {
    const statusCode = response.statusCode;
    const body = response.body.toLowerCase();
    const headers = response.headers;

    // Check for SQL injection indicators
    if (this.checkSQLInjectionIndicators(body)) {
      return {
        type: 'SQL Injection',
        severity: 'CRITICAL',
        confidence: 90,
        description: 'SQL injection vulnerability detected based on response content',
        evidence: this.extractSQLEvidence(body),
        payload: payload,
        endpoint: `${testCase.method} ${testCase.endpoint || 'unknown'}`,
        timestamp: new Date().toISOString()
      };
    }

    // Check for XSS indicators
    if (this.checkXSSIndicators(body, payload)) {
      return {
        type: 'Cross-Site Scripting (XSS)',
        severity: 'MEDIUM',
        confidence: 80,
        description: 'XSS vulnerability detected - payload reflected in response',
        evidence: this.extractXSSEvidence(body, payload),
        payload: payload,
        endpoint: `${testCase.method} ${testCase.endpoint || 'unknown'}`,
        timestamp: new Date().toISOString()
      };
    }

    // Check for IDOR indicators
    if (this.checkIDORIndicators(statusCode, body)) {
      return {
        type: 'Broken Object Level Authorization (IDOR)',
        severity: 'HIGH',
        confidence: 85,
        description: 'IDOR vulnerability detected - unauthorized access to objects',
        evidence: this.extractIDOREvidence(statusCode, body),
        payload: payload,
        endpoint: `${testCase.method} ${testCase.endpoint || 'unknown'}`,
        timestamp: new Date().toISOString()
      };
    }

    // Check for information disclosure
    if (this.checkInformationDisclosureIndicators(body)) {
      return {
        type: 'Information Disclosure',
        severity: 'MEDIUM',
        confidence: 75,
        description: 'Sensitive information disclosed in response',
        evidence: this.extractInformationDisclosureEvidence(body),
        payload: payload,
        endpoint: `${testCase.method} ${testCase.endpoint || 'unknown'}`,
        timestamp: new Date().toISOString()
      };
    }

    return null;
  }

  checkSQLInjectionIndicators(body) {
    const sqlIndicators = [
      'mysql_fetch_array',
      'ora-01756',
      'microsoft ole db provider',
      'postgresql query failed',
      'warning: mysql_',
      'valid mysql result',
      'mysqlclient.mysqlexception',
      'unclosed quotation mark',
      'quoted string not properly terminated',
      'sql syntax error',
      'mysql server has gone away',
      'access denied for user',
      'table doesn\'t exist',
      'unknown column',
      'duplicate entry'
    ];

    return sqlIndicators.some(indicator => body.includes(indicator));
  }

  checkXSSIndicators(body, payload) {
    const xssIndicators = ['<script>', 'javascript:', 'onerror=', 'onload=', 'alert('];
    const payloadLower = payload.toLowerCase();
    
    return xssIndicators.some(indicator => 
      body.includes(indicator) && payloadLower.includes(indicator)
    );
  }

  checkIDORIndicators(statusCode, body) {
    return statusCode === 200 && (
      body.includes('access denied') ||
      body.includes('forbidden') ||
      body.includes('unauthorized') ||
      body.includes('permission denied')
    );
  }

  checkInformationDisclosureIndicators(body) {
    const disclosureIndicators = [
      'stack trace',
      'exception in thread',
      'error in',
      'warning:',
      'notice:',
      'fatal error',
      'internal server error',
      'database connection failed',
      'file not found',
      'permission denied',
      'apache tomcat',
      'microsoft iis',
      'nginx',
      'php version',
      'python version',
      'node.js version'
    ];

    return disclosureIndicators.some(indicator => body.includes(indicator));
  }

  extractSQLEvidence(body) {
    const sqlErrors = [
      'mysql_fetch_array', 'ora-01756', 'microsoft ole db provider',
      'postgresql query failed', 'sql syntax error', 'mysql server has gone away'
    ];
    
    return sqlErrors.find(error => body.includes(error)) || 'SQL error detected';
  }

  extractXSSEvidence(body, payload) {
    const xssIndicators = ['<script>', 'javascript:', 'onerror=', 'onload=', 'alert('];
    const found = xssIndicators.find(indicator => body.includes(indicator));
    return found ? `XSS indicator found: ${found}` : 'XSS payload reflected';
  }

  extractIDOREvidence(statusCode, body) {
    if (statusCode === 200) {
      return 'Unauthorized access to object (200 response)';
    }
    return `IDOR indicator: ${statusCode} status code`;
  }

  extractInformationDisclosureEvidence(body) {
    const disclosureIndicators = [
      'stack trace', 'exception in thread', 'error in', 'warning:',
      'fatal error', 'internal server error', 'database connection failed'
    ];
    
    return disclosureIndicators.find(indicator => body.includes(indicator)) || 'Sensitive information disclosed';
  }

  async generateAIInsights(testResults) {
    if (!this.aiProvider || !this.aiApiKey) {
      return [];
    }

    try {
      const prompt = this.buildAIInsightsPrompt(testResults);
      const aiResponse = await this.callAI(prompt);
      
      if (aiResponse) {
        return this.parseAIInsights(aiResponse);
      }
    } catch (error) {
      console.error('AI insights generation failed:', error);
    }

    return [];
  }

  buildAIInsightsPrompt(testResults) {
    const summary = testResults.summary;
    const vulnerabilities = testResults.vulnerabilities.slice(0, 10); // Limit to first 10

    return `Analyze these API security test results and provide professional insights:

Summary:
- Total Endpoints: ${summary.totalEndpoints}
- Total Tests: ${summary.totalTests}
- Vulnerabilities Found: ${summary.vulnerabilitiesFound}
- Critical: ${summary.criticalVulnerabilities}
- High: ${summary.highVulnerabilities}
- Medium: ${summary.mediumVulnerabilities}
- Low: ${summary.lowVulnerabilities}

Top Vulnerabilities:
${vulnerabilities.map(v => `- ${v.type} (${v.severity}): ${v.description}`).join('\n')}

Provide:
1. 3-5 key security insights
2. Risk assessment
3. Priority recommendations
4. Next steps for remediation

Format as JSON with insights, riskAssessment, recommendations, and nextSteps arrays.`;
  }

  async callAI(prompt) {
    if (this.aiProvider === 'openai') {
      return await this.callOpenAI(prompt);
    } else if (this.aiProvider === 'gemini') {
      return await this.callGemini(prompt);
    }
    return null;
  }

  async callOpenAI(prompt) {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.aiApiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: 'You are a cybersecurity expert providing professional security analysis and recommendations.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.7,
        max_tokens: 1000
      })
    });

    if (response.ok) {
      const data = await response.json();
      return data.choices[0].message.content;
    }
    return null;
  }

  async callGemini(prompt) {
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${this.aiApiKey}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        contents: [{
          parts: [{
            text: prompt
          }]
        }]
      })
    });

    if (response.ok) {
      const data = await response.json();
      return data.candidates[0].content.parts[0].text;
    }
    return null;
  }

  parseAIInsights(aiResponse) {
    try {
      const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }
    } catch (error) {
      console.error('Failed to parse AI insights:', error);
    }

    return {
      insights: ['AI analysis completed'],
      riskAssessment: 'Medium risk based on findings',
      recommendations: ['Review and remediate identified vulnerabilities'],
      nextSteps: ['Implement security controls and retest']
    };
  }

  generateRecommendations(testResults) {
    const recommendations = [];
    const vulnerabilities = testResults.vulnerabilities;

    // Group vulnerabilities by type
    const vulnTypes = {};
    vulnerabilities.forEach(vuln => {
      if (!vulnTypes[vuln.type]) {
        vulnTypes[vuln.type] = [];
      }
      vulnTypes[vuln.type].push(vuln);
    });

    // Generate recommendations for each vulnerability type
    Object.entries(vulnTypes).forEach(([type, vulns]) => {
      const count = vulns.length;
      const severity = vulns[0].severity;

      recommendations.push({
        type: type,
        count: count,
        severity: severity,
        priority: this.getPriority(severity),
        recommendation: this.getRecommendationForType(type),
        affectedEndpoints: vulns.map(v => v.endpoint)
      });
    });

    return recommendations.sort((a, b) => b.priority - a.priority);
  }

  getPriority(severity) {
    const priorities = {
      'CRITICAL': 5,
      'HIGH': 4,
      'MEDIUM': 3,
      'LOW': 2,
      'INFO': 1
    };
    return priorities[severity] || 1;
  }

  getRecommendationForType(type) {
    const recommendations = {
      'SQL Injection': 'Implement parameterized queries and input validation',
      'Cross-Site Scripting (XSS)': 'Sanitize and escape all user inputs',
      'Broken Object Level Authorization (IDOR)': 'Implement proper authorization checks',
      'Information Disclosure': 'Review error handling and remove sensitive information',
      'Authentication Bypass': 'Strengthen authentication mechanisms',
      'Mass Assignment': 'Use allowlists for mass assignment',
      'Security Misconfiguration': 'Review and harden security configurations'
    };
    return recommendations[type] || 'Review security best practices';
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Export test results
  exportResults(format = 'json') {
    if (format === 'json') {
      return JSON.stringify(this.testResults, null, 2);
    } else if (format === 'csv') {
      return this.exportToCSV();
    }
    return this.testResults;
  }

  exportToCSV() {
    const csv = [];
    csv.push('Endpoint,Method,Vulnerability,Severity,Confidence,Description,Payload,Timestamp');

    this.testResults.forEach(result => {
      result.vulnerabilities.forEach(vuln => {
        csv.push([
          vuln.endpoint,
          vuln.method || 'N/A',
          vuln.type,
          vuln.severity,
          vuln.confidence,
          vuln.description,
          vuln.payload,
          vuln.timestamp
        ].join(','));
      });
    });

    return csv.join('\n');
  }
}

module.exports = ProfessionalTester;
