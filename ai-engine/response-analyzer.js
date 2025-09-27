/**
 * AI-Driven Response Analysis Engine
 * Analyzes API responses to generate intelligent test cases
 */

class ResponseAnalyzer {
  constructor(aiProvider, apiKey) {
    this.aiProvider = aiProvider;
    this.apiKey = apiKey;
    this.responsePatterns = new Map();
    this.vulnerabilityIndicators = new Map();
    this.initializePatterns();
  }

  initializePatterns() {
    // Response patterns that indicate vulnerabilities
    this.vulnerabilityIndicators.set('sql_injection', [
      'mysql_fetch_array',
      'ORA-01756',
      'Microsoft OLE DB Provider for SQL Server',
      'PostgreSQL query failed',
      'Warning: mysql_',
      'valid MySQL result',
      'MySqlClient.MySqlException',
      'Unclosed quotation mark',
      'quoted string not properly terminated'
    ]);

    this.vulnerabilityIndicators.set('xss', [
      '<script>',
      'javascript:',
      'onerror=',
      'onload=',
      'alert(',
      'document.cookie',
      'window.location',
      'eval(',
      'innerHTML'
    ]);

    this.vulnerabilityIndicators.set('idor', [
      'Access denied',
      'Forbidden',
      'Unauthorized',
      'Permission denied',
      'Insufficient privileges',
      'Object not found',
      'Resource not accessible'
    ]);

    this.vulnerabilityIndicators.set('information_disclosure', [
      'Stack trace',
      'Exception in thread',
      'Error in',
      'Warning:',
      'Notice:',
      'Fatal error',
      'Internal server error',
      'Database connection failed',
      'File not found',
      'Permission denied'
    ]);

    this.vulnerabilityIndicators.set('authentication_bypass', [
      'Invalid token',
      'Token expired',
      'Authentication failed',
      'Login required',
      'Session expired',
      'Access token invalid',
      'Bearer token required'
    ]);

    this.vulnerabilityIndicators.set('rate_limiting', [
      'Rate limit exceeded',
      'Too many requests',
      'Quota exceeded',
      'Request limit reached',
      'Throttle limit exceeded',
      'API rate limit',
      '429 Too Many Requests'
    ]);
  }

  async analyzeResponse(endpoint, method, payload, response, statusCode, headers) {
    const analysis = {
      endpoint: endpoint,
      method: method,
      payload: payload,
      response: response,
      statusCode: statusCode,
      headers: headers,
      vulnerabilities: [],
      confidence: 0,
      recommendations: [],
      generatedTestCases: []
    };

    // Analyze response content
    const contentAnalysis = await this.analyzeContent(response, statusCode, headers);
    analysis.vulnerabilities.push(...contentAnalysis.vulnerabilities);
    analysis.confidence += contentAnalysis.confidence;

    // Analyze response patterns
    const patternAnalysis = await this.analyzePatterns(response, statusCode, headers);
    analysis.vulnerabilities.push(...patternAnalysis.vulnerabilities);
    analysis.confidence += patternAnalysis.confidence;

    // Generate AI-powered test cases based on response
    if (this.aiProvider && this.apiKey) {
      const aiAnalysis = await this.generateAITestCases(endpoint, method, payload, response, statusCode);
      analysis.generatedTestCases.push(...aiAnalysis.testCases);
      analysis.recommendations.push(...aiAnalysis.recommendations);
      analysis.confidence += aiAnalysis.confidence;
    }

    // Generate follow-up test cases
    const followUpTests = await this.generateFollowUpTests(endpoint, method, payload, response, statusCode);
    analysis.generatedTestCases.push(...followUpTests);

    return analysis;
  }

  async analyzeContent(response, statusCode, headers) {
    const vulnerabilities = [];
    let confidence = 0;

    // Check for SQL injection indicators
    if (this.checkVulnerabilityIndicators(response, 'sql_injection')) {
      vulnerabilities.push({
        type: 'SQL Injection',
        severity: 'CRITICAL',
        confidence: 85,
        description: 'Response contains SQL error messages indicating potential SQL injection vulnerability',
        evidence: this.extractEvidence(response, 'sql_injection')
      });
      confidence += 85;
    }

    // Check for XSS indicators
    if (this.checkVulnerabilityIndicators(response, 'xss')) {
      vulnerabilities.push({
        type: 'Cross-Site Scripting (XSS)',
        severity: 'MEDIUM',
        confidence: 75,
        description: 'Response contains XSS indicators or unsanitized user input',
        evidence: this.extractEvidence(response, 'xss')
      });
      confidence += 75;
    }

    // Check for information disclosure
    if (this.checkVulnerabilityIndicators(response, 'information_disclosure')) {
      vulnerabilities.push({
        type: 'Information Disclosure',
        severity: 'MEDIUM',
        confidence: 70,
        description: 'Response contains sensitive information or error details',
        evidence: this.extractEvidence(response, 'information_disclosure')
      });
      confidence += 70;
    }

    // Check status code patterns
    if (statusCode === 500) {
      vulnerabilities.push({
        type: 'Internal Server Error',
        severity: 'LOW',
        confidence: 60,
        description: 'Server returned 500 error, may indicate application errors',
        evidence: `Status Code: ${statusCode}`
      });
      confidence += 60;
    }

    if (statusCode === 401) {
      vulnerabilities.push({
        type: 'Authentication Required',
        severity: 'INFO',
        confidence: 50,
        description: 'Endpoint requires authentication',
        evidence: `Status Code: ${statusCode}`
      });
      confidence += 50;
    }

    if (statusCode === 403) {
      vulnerabilities.push({
        type: 'Access Forbidden',
        severity: 'INFO',
        confidence: 50,
        description: 'Access to endpoint is forbidden',
        evidence: `Status Code: ${statusCode}`
      });
      confidence += 50;
    }

    return { vulnerabilities, confidence };
  }

  async analyzePatterns(response, statusCode, headers) {
    const vulnerabilities = [];
    let confidence = 0;

    // Check for IDOR patterns
    if (this.checkVulnerabilityIndicators(response, 'idor')) {
      vulnerabilities.push({
        type: 'Broken Object Level Authorization (IDOR)',
        severity: 'HIGH',
        confidence: 80,
        description: 'Response indicates potential IDOR vulnerability',
        evidence: this.extractEvidence(response, 'idor')
      });
      confidence += 80;
    }

    // Check for authentication bypass patterns
    if (this.checkVulnerabilityIndicators(response, 'authentication_bypass')) {
      vulnerabilities.push({
        type: 'Authentication Bypass',
        severity: 'CRITICAL',
        confidence: 90,
        description: 'Response indicates potential authentication bypass',
        evidence: this.extractEvidence(response, 'authentication_bypass')
      });
      confidence += 90;
    }

    // Check for rate limiting patterns
    if (this.checkVulnerabilityIndicators(response, 'rate_limiting')) {
      vulnerabilities.push({
        type: 'Rate Limiting',
        severity: 'LOW',
        confidence: 60,
        description: 'Response indicates rate limiting is in place',
        evidence: this.extractEvidence(response, 'rate_limiting')
      });
      confidence += 60;
    }

    // Check response time patterns
    const responseTime = headers['x-response-time'] || headers['response-time'];
    if (responseTime && parseInt(responseTime) > 5000) {
      vulnerabilities.push({
        type: 'Slow Response Time',
        severity: 'LOW',
        confidence: 40,
        description: 'Response time is unusually slow, may indicate performance issues',
        evidence: `Response Time: ${responseTime}ms`
      });
      confidence += 40;
    }

    return { vulnerabilities, confidence };
  }

  async generateAITestCases(endpoint, method, payload, response, statusCode) {
    if (!this.aiProvider || !this.apiKey) {
      return { testCases: [], recommendations: [], confidence: 0 };
    }

    try {
      const prompt = this.buildAIPrompt(endpoint, method, payload, response, statusCode);
      const aiResponse = await this.callAI(prompt);
      
      if (aiResponse) {
        return this.parseAIResponse(aiResponse);
      }
    } catch (error) {
      console.error('AI test case generation failed:', error);
    }

    return { testCases: [], recommendations: [], confidence: 0 };
  }

  buildAIPrompt(endpoint, method, payload, response, statusCode) {
    return `As a security testing AI, analyze this API interaction and generate additional test cases:

Endpoint: ${method} ${endpoint}
Payload: ${payload}
Response Status: ${statusCode}
Response Content: ${response.substring(0, 500)}...

Based on this interaction, generate:
1. 3-5 additional test cases that could reveal vulnerabilities
2. Specific payloads for each test case
3. Expected responses that would indicate vulnerabilities
4. Recommendations for further testing

Focus on:
- OWASP API Security Top 10 vulnerabilities
- Response-based attack vectors
- Edge cases and boundary conditions
- Authentication and authorization bypasses
- Input validation weaknesses

Format your response as JSON with testCases array and recommendations array.`;
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
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: 'You are a security testing AI that generates test cases for API security testing. Always respond with valid JSON format.'
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
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${this.apiKey}`, {
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

  parseAIResponse(aiResponse) {
    try {
      // Try to extract JSON from the response
      const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return {
          testCases: parsed.testCases || [],
          recommendations: parsed.recommendations || [],
          confidence: 80
        };
      }
    } catch (error) {
      console.error('Failed to parse AI response:', error);
    }

    // Fallback: extract test cases from text
    const testCases = this.extractTestCasesFromText(aiResponse);
    const recommendations = this.extractRecommendationsFromText(aiResponse);

    return {
      testCases,
      recommendations,
      confidence: 60
    };
  }

  extractTestCasesFromText(text) {
    const testCases = [];
    const lines = text.split('\n');
    
    for (const line of lines) {
      if (line.includes('Test Case') || line.includes('Payload') || line.includes('Endpoint')) {
        testCases.push({
          name: line.trim(),
          description: 'AI-generated test case',
          payload: this.extractPayloadFromLine(line),
          method: 'GET',
          expectedResponse: 'Varies based on vulnerability type'
        });
      }
    }

    return testCases;
  }

  extractRecommendationsFromText(text) {
    const recommendations = [];
    const lines = text.split('\n');
    
    for (const line of lines) {
      if (line.includes('Recommendation') || line.includes('Suggestion') || line.includes('Consider')) {
        recommendations.push(line.trim());
      }
    }

    return recommendations;
  }

  extractPayloadFromLine(line) {
    // Extract payload from line (simple implementation)
    const payloadMatch = line.match(/["']([^"']+)["']/);
    return payloadMatch ? payloadMatch[1] : 'Generated payload';
  }

  async generateFollowUpTests(endpoint, method, payload, response, statusCode) {
    const followUpTests = [];

    // Generate tests based on response patterns
    if (statusCode === 200 && response.includes('admin')) {
      followUpTests.push({
        name: 'Admin Function Access Test',
        description: 'Test access to admin functions based on response content',
        payload: payload.replace('user', 'admin'),
        method: method,
        expectedResponse: 'Check for admin privilege escalation'
      });
    }

    if (statusCode === 401) {
      followUpTests.push({
        name: 'Authentication Bypass Test',
        description: 'Test various authentication bypass techniques',
        payload: '{"token":"admin"}',
        method: method,
        expectedResponse: 'Test for authentication bypass'
      });
    }

    if (statusCode === 403) {
      followUpTests.push({
        name: 'Authorization Bypass Test',
        description: 'Test authorization bypass techniques',
        payload: '{"role":"admin"}',
        method: method,
        expectedResponse: 'Test for authorization bypass'
      });
    }

    if (response.includes('error') || response.includes('exception')) {
      followUpTests.push({
        name: 'Error-based Testing',
        description: 'Test for error-based vulnerabilities',
        payload: payload + "' OR '1'='1",
        method: method,
        expectedResponse: 'Test for SQL injection or other error-based attacks'
      });
    }

    return followUpTests;
  }

  checkVulnerabilityIndicators(response, vulnerabilityType) {
    const indicators = this.vulnerabilityIndicators.get(vulnerabilityType);
    if (!indicators) return false;

    return indicators.some(indicator => 
      response.toLowerCase().includes(indicator.toLowerCase())
    );
  }

  extractEvidence(response, vulnerabilityType) {
    const indicators = this.vulnerabilityIndicators.get(vulnerabilityType);
    if (!indicators) return '';

    const foundIndicators = indicators.filter(indicator => 
      response.toLowerCase().includes(indicator.toLowerCase())
    );

    return foundIndicators.join(', ');
  }

  // Generate comprehensive test suite based on all responses
  async generateComprehensiveTestSuite(responses) {
    const testSuite = {
      name: 'AI-Generated Comprehensive Test Suite',
      description: 'Generated based on API response analysis',
      testCases: [],
      recommendations: [],
      confidence: 0
    };

    for (const response of responses) {
      const analysis = await this.analyzeResponse(
        response.endpoint,
        response.method,
        response.payload,
        response.response,
        response.statusCode,
        response.headers
      );

      testSuite.testCases.push(...analysis.generatedTestCases);
      testSuite.recommendations.push(...analysis.recommendations);
      testSuite.confidence += analysis.confidence;
    }

    // Calculate average confidence
    testSuite.confidence = testSuite.confidence / responses.length;

    // Remove duplicates
    testSuite.testCases = this.removeDuplicateTestCases(testSuite.testCases);
    testSuite.recommendations = [...new Set(testSuite.recommendations)];

    return testSuite;
  }

  removeDuplicateTestCases(testCases) {
    const seen = new Set();
    return testCases.filter(testCase => {
      const key = `${testCase.name}-${testCase.payload}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }
}

module.exports = ResponseAnalyzer;
