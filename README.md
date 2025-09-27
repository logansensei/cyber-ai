# 🛡️ CyberSentinel AI

**Advanced AI-Driven API Security Testing Platform**

CyberSentinel AI is a comprehensive, AI-powered security testing platform designed to identify vulnerabilities in REST APIs, GraphQL endpoints, and other web services. It combines traditional security testing methodologies with cutting-edge AI technology to provide intelligent payload generation and vulnerability analysis.

![CyberSentinel AI](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Node.js](https://img.shields.io/badge/node.js-16+-green.svg)
![AI Powered](https://img.shields.io/badge/AI-Powered-orange.svg)

## ✨ Features

### 🤖 AI-Powered Security Testing
- **Intelligent Payload Generation**: AI-driven creation of context-aware attack payloads
- **Multiple AI Providers**: Support for OpenAI GPT-4, Google Gemini, and local LLMs
- **Adaptive Testing**: AI learns from API responses to generate more effective payloads
- **Natural Language Analysis**: AI-powered vulnerability descriptions and remediation advice

### 🔍 Comprehensive Vulnerability Detection
- **OWASP API Security Top 10**: Complete coverage of the most critical API vulnerabilities
- **Advanced Injection Testing**: SQL, NoSQL, Command, and LDAP injection detection
- **Authentication Bypass**: JWT manipulation, session hijacking, and credential stuffing
- **Authorization Flaws**: IDOR, privilege escalation, and mass assignment vulnerabilities
- **Data Exposure**: Sensitive data leakage and excessive information disclosure

### 📊 Professional Reporting
- **Real-time Dashboard**: Live monitoring of scan progress and findings
- **Detailed Reports**: Comprehensive HTML and JSON report generation
- **Risk Assessment**: Severity classification and confidence scoring
- **Remediation Guidance**: AI-generated fix recommendations

### 🚀 Easy Integration
- **Multiple Input Formats**: OpenAPI 3.0, Swagger 2.0, Postman Collections, HAR files
- **RESTful API**: Full programmatic access to all functionality
- **Docker Support**: Containerized deployment for easy scaling
- **CI/CD Ready**: Seamless integration with existing development workflows

## 🚀 Quick Start

### Prerequisites

- Node.js 16+ 
- npm 8+ or yarn
- (Optional) OpenAI API key or Google Gemini API key for AI features

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/cybersentinel-ai/cybersentinel-ai.git
   cd cybersentinel-ai
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment**
   ```bash
   cp env.example .env
   # Edit .env with your API keys and configuration
   ```

4. **Start the application**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

5. **Access the web interface**
   Open your browser and navigate to `http://localhost:3000`

## 🔧 Configuration

### Environment Variables

Create a `.env` file based on `env.example`:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# AI Provider API Keys
OPENAI_API_KEY=your_openai_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here

# Security Configuration
JWT_SECRET=your_jwt_secret_here
ENCRYPTION_KEY=your_encryption_key_here

# Feature Flags
ENABLE_AI=true
ENABLE_RATE_LIMITING=true
```

### AI Provider Setup

#### OpenAI Integration
1. Get your API key from [OpenAI Platform](https://platform.openai.com/api-keys)
2. Add it to your `.env` file as `OPENAI_API_KEY`
3. Select "OpenAI GPT-4" in the AI Configuration panel

#### Google Gemini Integration
1. Get your API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Add it to your `.env` file as `GEMINI_API_KEY`
3. Select "Google Gemini" in the AI Configuration panel

## 📖 Usage

### Web Interface

1. **Upload API Specification**
   - Drag and drop your OpenAPI/Swagger file
   - Or browse and select from your file system
   - Supported formats: JSON, YAML, Postman Collections, HAR files

2. **Configure Authentication**
   - Set your target API base URL
   - Choose authentication method (Bearer token, API key, OAuth 2.0, etc.)
   - Enter your credentials

3. **Select Test Modules**
   - Choose from OWASP API Security Top 10 tests
   - Enable/disable specific vulnerability types
   - Configure AI model and payload generation strategy

4. **Run Security Scan**
   - Click "Start AI-Powered Security Scan"
   - Monitor real-time progress and findings
   - View detailed vulnerability reports

### API Usage

#### Parse API Specification
```bash
curl -X POST http://localhost:3000/api/parse-spec \
  -F "file=@api-spec.json"
```

#### Generate AI Payloads
```bash
curl -X POST http://localhost:3000/api/generate-payloads \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint": {"method": "GET", "path": "/api/users/{id}"},
    "test": {"id": "api1", "name": "BOLA/IDOR"},
    "provider": "openai",
    "apiKey": "your-api-key",
    "strategy": "contextual"
  }'
```

#### Run Security Scan
```bash
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "endpoints": [{"method": "GET", "path": "/api/users"}],
    "tests": [{"id": "api1", "name": "BOLA/IDOR"}],
    "aiProvider": "openai",
    "aiApiKey": "your-api-key"
  }'
```

## 🧪 Testing

### Run Test Suite
```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run specific test file
npm test -- --testNamePattern="API parsing"
```

### Test Categories
- **Unit Tests**: Individual function testing
- **Integration Tests**: API endpoint testing
- **AI Tests**: AI provider integration testing
- **Security Tests**: Vulnerability detection validation

## 🐳 Docker Deployment

### Build and Run
```bash
# Build the Docker image
docker build -t cybersentinel-ai .

# Run the container
docker run -p 3000:3000 \
  -e OPENAI_API_KEY=your_key_here \
  -e GEMINI_API_KEY=your_key_here \
  cybersentinel-ai
```

### Docker Compose
```yaml
version: '3.8'
services:
  cybersentinel-ai:
    build: .
    ports:
      - "3000:3000"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - GEMINI_API_KEY=${GEMINI_API_KEY}
    volumes:
      - ./uploads:/app/uploads
      - ./logs:/app/logs
```

## 📊 API Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/parse-spec` | Parse API specification |
| POST | `/api/generate-payloads` | Generate AI payloads |
| POST | `/api/test-ai-connection` | Test AI provider connection |
| POST | `/api/scan` | Run security scan |
| POST | `/api/generate-report` | Generate security report |

### Response Formats

All API responses follow this structure:
```json
{
  "success": true|false,
  "data": {...},
  "error": "Error message if applicable",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

## 🔒 Security Considerations

### Data Protection
- All uploaded files are processed locally and deleted after analysis
- API keys are encrypted in transit and at rest
- No sensitive data is logged or stored permanently

### Rate Limiting
- Built-in rate limiting to prevent abuse
- Configurable request limits per IP
- AI API call throttling to manage costs

### Input Validation
- Comprehensive input sanitization
- File type and size restrictions
- SQL injection protection

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/your-username/cybersentinel-ai.git
cd cybersentinel-ai

# Install dependencies
npm install

# Run in development mode
npm run dev

# Run tests
npm test

# Run linting
npm run lint

# Format code
npm run format
```

### Pull Request Process
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP](https://owasp.org/) for the API Security Top 10 guidelines
- [OpenAI](https://openai.com/) for AI capabilities
- [Google](https://ai.google.dev/) for Gemini AI integration
- The security research community for vulnerability patterns and payloads

## 📞 Support

- **Documentation**: [Wiki](https://github.com/cybersentinel-ai/cybersentinel-ai/wiki)
- **Issues**: [GitHub Issues](https://github.com/cybersentinel-ai/cybersentinel-ai/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cybersentinel-ai/cybersentinel-ai/discussions)
- **Email**: support@cybersentinel-ai.com

## 🗺️ Roadmap

### Version 1.1 (Q2 2024)
- [ ] GraphQL endpoint support
- [ ] Custom vulnerability rule engine
- [ ] Team collaboration features
- [ ] Advanced reporting templates

### Version 1.2 (Q3 2024)
- [ ] Machine learning model training
- [ ] Integration with popular CI/CD platforms
- [ ] Real-time vulnerability monitoring
- [ ] Compliance reporting (SOC2, PCI-DSS)

### Version 2.0 (Q4 2024)
- [ ] Multi-tenant architecture
- [ ] Advanced threat modeling
- [ ] Custom AI model training
- [ ] Enterprise SSO integration

---

**Made with ❤️ by the CyberSentinel AI Team**

*Empowering developers to build secure APIs with the power of AI*
