# AI Secure Refactoring Agent

An AI-powered security vulnerability detection and code refactoring agent using Google Gemini **with Function Calling capabilities**. The agent autonomously analyzes source code to identify security vulnerabilities based on OWASP Top 10 2021 and CWE standards, then proposes and applies secure fixes using an intelligent tool-calling workflow.

## 🚀 Key Feature: Real AI Agent with Function Calling

This agent uses **Gemini's function calling feature** to create a true autonomous agent that:
- Decides which tools to use based on the task
- Chains multiple tool calls together intelligently
- Maintains state across the analysis process
- Makes decisions about what to investigate further

### Available Agent Tools:
| Tool | Description |
|------|-------------|
| `detect_language` | Identifies programming language from code |
| `static_pattern_scan` | Regex-based vulnerability pattern detection |
| `lookup_owasp` | Retrieves OWASP Top 10 2021 information |
| `lookup_cwe` | Retrieves CWE vulnerability details |
| `analyze_code_section` | Deep analysis of specific code sections |
| `report_vulnerability` | Reports each found vulnerability |
| `submit_full_analysis` | Batch submit all vulnerabilities, attack vectors, and recommendations |
| `generate_fix` | Gets guidance for fixing vulnerabilities |
| `apply_security_fix` | Applies fixes to the code |
| `calculate_security_score` | Calculates overall security score |
| `report_attack_vector` | Reports potential attack vectors |
| `report_risk_area` | Reports code areas with security risks |
| `add_recommendation` | Adds security recommendations |
| `report_secure_pattern` | Reports secure coding patterns found |
| `finalize_scan` | Completes the scanning process |
| `finalize_refactor` | Completes the refactoring process |

## Features

- **Autonomous AI Agent**: Uses Gemini function calling to autonomously decide what tools to use
- **Vulnerability Detection**: Identifies security vulnerabilities using AI-driven analysis
- **OWASP/CWE Classification**: Maps detected vulnerabilities to OWASP Top 10 2021 and CWE identifiers
- **Secure Refactoring**: Automatically generates secure code fixes while maintaining functionality
- **Multi-Language Support**: Supports JavaScript, TypeScript, Python, Java, PHP, Go, Ruby, and C#
- **Web Interface**: User-friendly dashboard for code scanning and refactoring
- **REST API**: Programmatic access for integration with CI/CD pipelines
- **Security Posture Analysis**: Comprehensive security assessment with scoring

## Prerequisites

- **Node.js** 18.0.0 or higher
- **Google Gemini API Key** (get it from https://aistudio.google.com/app/apikey)
- **Docker** (optional, for containerized deployment)

## Quick Start

### Option 1: Run Locally

1. **Clone and navigate to the project:**
   ```bash
   cd secure-refactor-agent
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure environment:**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and add your Gemini API key:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

4. **Start the application:**
   ```bash
   npm start
   ```

5. **Access the web interface:**
   Open http://localhost:3000 in your browser

### Option 2: Run with Docker

1. **Configure environment:**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and add your Gemini API key.

2. **Build and run with Docker Compose:**
   ```bash
   docker-compose up -d
   ```

3. **Access the application:**
   Open http://localhost:3000 in your browser

4. **View logs:**
   ```bash
   docker-compose logs -f
   ```

5. **Stop the application:**
   ```bash
   docker-compose down
   ```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Your Google Gemini API key (required) | - |
| `PORT` | Server port | 3000 |
| `NODE_ENV` | Environment (development/production) | development |
| `GEMINI_MODEL` | Gemini model to use | gemini-2.0-flash |
| `RATE_LIMIT_WINDOW_MS` | Rate limit window in milliseconds | 900000 (15 min) |
| `RATE_LIMIT_MAX_REQUESTS` | Max requests per window | 100 |
| `MAX_CODE_LENGTH` | Maximum code length in characters | 50000 |
| `LOG_LEVEL` | Logging level (error/warn/info/debug) | info |

## API Endpoints

### Health Check
```
GET /api/health
```
Returns the server health status.

### Scan Code for Vulnerabilities
```
POST /api/scan
Content-Type: application/json

{
  "code": "// Your code here",
  "language": "javascript",  // optional, auto-detected
  "filename": "app.js"       // optional
}
```

### Scan File
```
POST /api/scan/file
Content-Type: multipart/form-data

file: <your-file>
```

### Refactor Single Vulnerability
```
POST /api/refactor
Content-Type: application/json

{
  "code": "// Your code",
  "vulnerability": { /* vulnerability object from scan */ },
  "language": "javascript"
}
```

### Refactor All Vulnerabilities
```
POST /api/refactor/all
Content-Type: application/json

{
  "scanId": "uuid-from-scan"
}
// OR
{
  "code": "// Your code",
  "vulnerabilities": [ /* array of vulnerabilities */ ]
}
```

### Security Posture Analysis
```
POST /api/analyze
Content-Type: application/json

{
  "code": "// Your code",
  "language": "javascript"
}
```

### Get Scan Result
```
GET /api/scan/:scanId
```

### Get OWASP Reference
```
GET /api/reference/owasp
```

### Get CWE Reference
```
GET /api/reference/cwe
```

### Get Supported Languages
```
GET /api/languages
```

## Usage Examples

### Using the Web Interface

1. Open http://localhost:3000
2. Paste your code in the input area or upload a file
3. Click "Scan for Vulnerabilities"
4. Review detected vulnerabilities
5. Click "Fix All" or fix individual vulnerabilities
6. Copy the secure refactored code

### Using cURL

**Scan code:**
```bash
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "code": "const password = \"admin123\"; db.query(\"SELECT * FROM users WHERE id = \" + userId);"
  }'
```

**Fix all vulnerabilities:**
```bash
curl -X POST http://localhost:3000/api/refactor/all \
  -H "Content-Type: application/json" \
  -d '{"scanId": "your-scan-id"}'
```

## Detected Vulnerability Types

The agent can detect and fix various vulnerability types including:

- **A01:2021** - Broken Access Control
- **A02:2021** - Cryptographic Failures (hardcoded secrets, weak crypto)
- **A03:2021** - Injection (SQL, Command, XSS, Code Injection)
- **A04:2021** - Insecure Design
- **A05:2021** - Security Misconfiguration
- **A06:2021** - Vulnerable Components
- **A07:2021** - Authentication Failures (hardcoded credentials)
- **A08:2021** - Software Integrity Failures (insecure deserialization)
- **A09:2021** - Logging Failures
- **A10:2021** - SSRF

## Project Structure

```
secure-refactor-agent/
├── src/
│   ├── agent/
│   │   ├── SecureRefactorAgent.js  # Core agent logic
│   │   └── prompts.js              # AI system prompts
│   ├── config/
│   │   └── index.js                # Configuration
│   ├── knowledge/
│   │   └── vulnerabilities.js      # OWASP/CWE knowledge base
│   ├── routes/
│   │   └── api.js                  # API endpoints
│   ├── utils/
│   │   └── logger.js               # Logging utility
│   └── index.js                    # Application entry point
├── public/
│   ├── css/
│   │   └── style.css               # Styles
│   ├── js/
│   │   └── app.js                  # Frontend application
│   └── index.html                  # Web interface
├── logs/                           # Log files (created at runtime)
├── .env.example                    # Environment template
├── Dockerfile                      # Docker image definition
├── docker-compose.yml              # Docker Compose configuration
├── package.json                    # Node.js dependencies
└── README.md                       # This file
```

## Security Considerations

- The agent processes code on the server side; ensure your deployment is secure
- API rate limiting is enabled by default to prevent abuse
- Do not expose the API publicly without proper authentication in production
- Audit logs are maintained for all operations
- The Docker container runs as a non-root user

## Troubleshooting

### Common Issues

**"GEMINI_API_KEY is required"**
- Ensure you have set the `GEMINI_API_KEY` in your `.env` file
- Get your API key from https://aistudio.google.com/app/apikey

**"Rate limit exceeded"**
- Wait for the rate limit window to reset (default: 15 minutes)
- Adjust `RATE_LIMIT_MAX_REQUESTS` if needed

**"Code exceeds maximum length"**
- The default limit is 50,000 characters
- Adjust `MAX_CODE_LENGTH` or split your code into smaller chunks

**Docker container fails to start**
- Check logs: `docker-compose logs`
- Ensure the `.env` file is properly configured
- Verify Docker has sufficient resources

## License

MIT License

## Author

Created for Assignment 6 - AI-assisted Software Development
