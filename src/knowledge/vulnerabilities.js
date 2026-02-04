/**
 * OWASP Top 10 2021 and CWE Vulnerability Knowledge Base
 * This module contains structured information about common vulnerabilities
 * that the AI agent uses as context for detection and remediation.
 */

export const OWASP_TOP_10_2021 = {
  'A01:2021': {
    name: 'Broken Access Control',
    description: 'Access control enforces policy such that users cannot act outside of their intended permissions.',
    cwes: ['CWE-22', 'CWE-23', 'CWE-35', 'CWE-59', 'CWE-200', 'CWE-201', 'CWE-219', 'CWE-264', 'CWE-275', 'CWE-276', 'CWE-284', 'CWE-285', 'CWE-352', 'CWE-359', 'CWE-377', 'CWE-402', 'CWE-425', 'CWE-441', 'CWE-497', 'CWE-538', 'CWE-540', 'CWE-548', 'CWE-552', 'CWE-566', 'CWE-601', 'CWE-639', 'CWE-651', 'CWE-668', 'CWE-706', 'CWE-862', 'CWE-863', 'CWE-913', 'CWE-922', 'CWE-1275'],
    mitigations: [
      'Implement proper access control mechanisms',
      'Deny by default except for public resources',
      'Implement access control once and reuse it throughout the application',
      'Minimize CORS usage',
      'Log access control failures and alert administrators',
      'Rate limit API access',
      'Invalidate sessions after logout',
    ],
  },
  'A02:2021': {
    name: 'Cryptographic Failures',
    description: 'Failures related to cryptography which often lead to exposure of sensitive data.',
    cwes: ['CWE-261', 'CWE-296', 'CWE-310', 'CWE-319', 'CWE-321', 'CWE-322', 'CWE-323', 'CWE-324', 'CWE-325', 'CWE-326', 'CWE-327', 'CWE-328', 'CWE-329', 'CWE-330', 'CWE-331', 'CWE-335', 'CWE-336', 'CWE-337', 'CWE-338', 'CWE-340', 'CWE-347', 'CWE-523', 'CWE-720', 'CWE-757', 'CWE-759', 'CWE-760', 'CWE-780', 'CWE-818', 'CWE-916'],
    mitigations: [
      'Classify data processed, stored, or transmitted by an application',
      'Encrypt all sensitive data at rest',
      'Ensure up-to-date and strong standard algorithms are used',
      'Disable caching for responses containing sensitive data',
      'Use authenticated encryption instead of just encryption',
      'Generate cryptographic keys using cryptographically secure random number generators',
    ],
  },
  'A03:2021': {
    name: 'Injection',
    description: 'User-supplied data is not validated, filtered, or sanitized by the application.',
    cwes: ['CWE-20', 'CWE-74', 'CWE-75', 'CWE-77', 'CWE-78', 'CWE-79', 'CWE-80', 'CWE-83', 'CWE-87', 'CWE-88', 'CWE-89', 'CWE-90', 'CWE-91', 'CWE-93', 'CWE-94', 'CWE-95', 'CWE-96', 'CWE-97', 'CWE-98', 'CWE-99', 'CWE-100', 'CWE-113', 'CWE-116', 'CWE-138', 'CWE-184', 'CWE-470', 'CWE-471', 'CWE-564', 'CWE-610', 'CWE-643', 'CWE-644', 'CWE-652', 'CWE-917'],
    mitigations: [
      'Use a safe API that avoids using the interpreter entirely',
      'Use positive or "allowlist" server-side input validation',
      'Escape special characters using specific escape syntax',
      'Use LIMIT and other SQL controls within queries',
      'Use parameterized queries or prepared statements',
    ],
  },
  'A04:2021': {
    name: 'Insecure Design',
    description: 'Risks related to design and architectural flaws.',
    cwes: ['CWE-73', 'CWE-183', 'CWE-209', 'CWE-213', 'CWE-235', 'CWE-256', 'CWE-257', 'CWE-266', 'CWE-269', 'CWE-280', 'CWE-311', 'CWE-312', 'CWE-313', 'CWE-316', 'CWE-419', 'CWE-430', 'CWE-434', 'CWE-444', 'CWE-451', 'CWE-472', 'CWE-501', 'CWE-522', 'CWE-525', 'CWE-539', 'CWE-579', 'CWE-598', 'CWE-602', 'CWE-642', 'CWE-646', 'CWE-650', 'CWE-653', 'CWE-656', 'CWE-657', 'CWE-799', 'CWE-807', 'CWE-840', 'CWE-841', 'CWE-927', 'CWE-1021', 'CWE-1173'],
    mitigations: [
      'Establish a secure development lifecycle with AppSec professionals',
      'Use threat modeling for critical authentication, access control, business logic, and key flows',
      'Integrate security language and controls into user stories',
      'Integrate plausibility checks at each tier',
      'Segregate tenant access properly at all tiers',
      'Limit resource consumption by user or service',
    ],
  },
  'A05:2021': {
    name: 'Security Misconfiguration',
    description: 'Missing appropriate security hardening across any part of the application stack.',
    cwes: ['CWE-2', 'CWE-11', 'CWE-13', 'CWE-15', 'CWE-16', 'CWE-260', 'CWE-315', 'CWE-520', 'CWE-526', 'CWE-537', 'CWE-541', 'CWE-547', 'CWE-611', 'CWE-614', 'CWE-756', 'CWE-776', 'CWE-942', 'CWE-1004', 'CWE-1032', 'CWE-1174'],
    mitigations: [
      'A repeatable hardening process',
      'Minimal platform without unnecessary features or components',
      'Review and update configurations as part of patch management',
      'Segmented application architecture',
      'Send security directives to clients via security headers',
      'Automated verification of configurations and settings in all environments',
    ],
  },
  'A06:2021': {
    name: 'Vulnerable and Outdated Components',
    description: 'Using components with known vulnerabilities.',
    cwes: ['CWE-1035', 'CWE-1104'],
    mitigations: [
      'Remove unused dependencies, unnecessary features, components, files, and documentation',
      'Continuously inventory versions of components and dependencies',
      'Monitor sources like CVE and NVD for vulnerabilities',
      'Only obtain components from official sources over secure links',
      'Monitor unmaintained libraries and components',
    ],
  },
  'A07:2021': {
    name: 'Identification and Authentication Failures',
    description: 'Confirmation of user identity, authentication, and session management.',
    cwes: ['CWE-255', 'CWE-259', 'CWE-287', 'CWE-288', 'CWE-290', 'CWE-294', 'CWE-295', 'CWE-297', 'CWE-300', 'CWE-302', 'CWE-304', 'CWE-306', 'CWE-307', 'CWE-346', 'CWE-384', 'CWE-521', 'CWE-613', 'CWE-620', 'CWE-640', 'CWE-798', 'CWE-940', 'CWE-1216'],
    mitigations: [
      'Implement multi-factor authentication',
      'Do not ship or deploy with default credentials',
      'Implement weak password checks',
      'Limit or increasingly delay failed login attempts',
      'Use a server-side, secure session manager',
      'Session IDs should not be in the URL',
    ],
  },
  'A08:2021': {
    name: 'Software and Data Integrity Failures',
    description: 'Code and infrastructure that does not protect against integrity violations.',
    cwes: ['CWE-345', 'CWE-353', 'CWE-426', 'CWE-494', 'CWE-502', 'CWE-565', 'CWE-784', 'CWE-829', 'CWE-830', 'CWE-913'],
    mitigations: [
      'Use digital signatures to verify software or data is from expected source',
      'Ensure libraries and dependencies are from trusted repositories',
      'Use a software supply chain security tool',
      'Ensure there is a review process for code and configuration changes',
      'Ensure CI/CD pipeline has proper segregation, configuration, and access control',
    ],
  },
  'A09:2021': {
    name: 'Security Logging and Monitoring Failures',
    description: 'Lack of logging, detection, monitoring, and active response.',
    cwes: ['CWE-117', 'CWE-223', 'CWE-532', 'CWE-778'],
    mitigations: [
      'Ensure all login, access control, and server-side input validation failures are logged',
      'Ensure logs are generated in a format easily consumed by log management solutions',
      'Ensure high-value transactions have an audit trail with integrity controls',
      'Establish or adopt an incident response and recovery plan',
    ],
  },
  'A10:2021': {
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'SSRF flaws occur when a web application is fetching a remote resource without validating the user-supplied URL.',
    cwes: ['CWE-918'],
    mitigations: [
      'Segment remote resource access in separate networks',
      'Enforce "deny by default" firewall policies',
      'Sanitize and validate all client-supplied input data',
      'Do not send raw responses to clients',
      'Disable HTTP redirections',
    ],
  },
};

export const CWE_DATABASE = {
  'CWE-22': {
    name: 'Path Traversal',
    description: 'The software uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences that can resolve to a location outside of that directory.',
    severity: 'High',
    patterns: [
      '../',
      '..\\',
      '%2e%2e%2f',
      '%2e%2e/',
      '..%2f',
      '%2e%2e%5c',
    ],
  },
  'CWE-78': {
    name: 'OS Command Injection',
    description: 'The software constructs all or part of an OS command using externally-influenced input but does not neutralize special elements.',
    severity: 'Critical',
    patterns: [
      'exec(', 'system(', 'shell_exec(', 'passthru(', 'popen(',
      'child_process', 'subprocess', 'os.system', 'os.popen',
    ],
  },
  'CWE-79': {
    name: 'Cross-site Scripting (XSS)',
    description: 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.',
    severity: 'High',
    patterns: [
      'innerHTML', 'outerHTML', 'document.write', 'eval(',
      'dangerouslySetInnerHTML', '.html(', 'v-html',
    ],
  },
  'CWE-89': {
    name: 'SQL Injection',
    description: 'The software constructs all or part of an SQL command using externally-influenced input without properly neutralizing special elements.',
    severity: 'Critical',
    patterns: [
      'SELECT.*FROM.*WHERE',
      'INSERT INTO',
      'UPDATE.*SET',
      'DELETE FROM',
      'string concatenation with SQL',
    ],
  },
  'CWE-94': {
    name: 'Code Injection',
    description: 'The software constructs all or part of a code segment using externally-influenced input without properly neutralizing special elements.',
    severity: 'Critical',
    patterns: [
      'eval(', 'exec(', 'Function(', 'setTimeout(.*,.*)',
      'setInterval(.*,.*)', 'new Function(',
    ],
  },
  'CWE-200': {
    name: 'Information Exposure',
    description: 'The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.',
    severity: 'Medium',
    patterns: [
      'console.log', 'print(', 'System.out.println',
      'stack trace', 'error message',
    ],
  },
  'CWE-259': {
    name: 'Hard-coded Password',
    description: 'The software contains a hard-coded password.',
    severity: 'High',
    patterns: [
      'password = "', "password = '", 'pwd = "', "pwd = '",
      'passwd', 'secret = "', "secret = '",
    ],
  },
  'CWE-311': {
    name: 'Missing Encryption',
    description: 'The software does not encrypt sensitive or critical information before storage or transmission.',
    severity: 'High',
    patterns: [
      'http://', 'plaintext', 'unencrypted',
    ],
  },
  'CWE-327': {
    name: 'Use of Broken Crypto Algorithm',
    description: 'The use of a broken or risky cryptographic algorithm.',
    severity: 'High',
    patterns: [
      'MD5', 'SHA1', 'DES', 'RC4', 'createCipher(',
    ],
  },
  'CWE-352': {
    name: 'Cross-Site Request Forgery (CSRF)',
    description: 'The web application does not verify that a request was intentionally provided by the user.',
    severity: 'High',
    patterns: [
      'missing CSRF token', 'no CSRF protection',
    ],
  },
  'CWE-502': {
    name: 'Deserialization of Untrusted Data',
    description: 'The application deserializes untrusted data without sufficient verification.',
    severity: 'Critical',
    patterns: [
      'pickle.loads', 'yaml.load(', 'unserialize(',
      'JSON.parse(', 'eval(JSON',
    ],
  },
  'CWE-601': {
    name: 'Open Redirect',
    description: 'A web application accepts user-controlled input that specifies a link to an external site.',
    severity: 'Medium',
    patterns: [
      'redirect(', 'location.href', 'window.location',
      'res.redirect(', 'header("Location:',
    ],
  },
  'CWE-611': {
    name: 'XXE (XML External Entity)',
    description: 'The software processes an XML document that can contain external entity references.',
    severity: 'High',
    patterns: [
      'XMLParser', 'parseXML', 'DocumentBuilder',
      '<!ENTITY', 'SYSTEM "',
    ],
  },
  'CWE-798': {
    name: 'Hard-coded Credentials',
    description: 'The software contains hard-coded credentials for authentication.',
    severity: 'Critical',
    patterns: [
      'api_key = "', "api_key = '", 'apiKey = "', "apiKey = '",
      'token = "', "token = '", 'secret_key = "', "secret_key = '",
    ],
  },
  'CWE-918': {
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'The web server receives a URL or similar request and retrieves the contents of this URL without proper validation.',
    severity: 'High',
    patterns: [
      'fetch(', 'axios(', 'request(', 'urllib', 'http.get(',
      'file_get_contents(', 'curl_exec(',
    ],
  },
};

export const VULNERABILITY_PATTERNS = {
  javascript: {
    'SQL Injection': [
      /query\s*\(\s*[`'"]\s*SELECT.*\+/gi,
      /query\s*\(\s*[`'"].*\$\{/gi,
      /execute\s*\(\s*[`'"]\s*(SELECT|INSERT|UPDATE|DELETE).*\+/gi,
    ],
    'XSS': [
      /\.innerHTML\s*=/gi,
      /\.outerHTML\s*=/gi,
      /document\.write\s*\(/gi,
      /dangerouslySetInnerHTML/gi,
      /\$\(.*\)\.html\s*\(/gi,
    ],
    'Command Injection': [
      /exec\s*\(\s*[`'"].*\+/gi,
      /spawn\s*\(\s*[`'"].*\+/gi,
      /child_process\.(exec|spawn)\s*\(/gi,
    ],
    'Hardcoded Secrets': [
      /password\s*[:=]\s*['"][^'"]+['"]/gi,
      /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/gi,
      /secret\s*[:=]\s*['"][^'"]+['"]/gi,
      /token\s*[:=]\s*['"][^'"]+['"]/gi,
    ],
    'Insecure Random': [
      /Math\.random\s*\(\s*\)/gi,
    ],
    'Eval Usage': [
      /eval\s*\(/gi,
      /new\s+Function\s*\(/gi,
      /setTimeout\s*\(\s*[`'"]/gi,
      /setInterval\s*\(\s*[`'"]/gi,
    ],
    'Prototype Pollution': [
      /\[.*\]\s*=\s*.*__proto__/gi,
      /Object\.assign\s*\(\s*\{\}/gi,
    ],
    'Path Traversal': [
      /\.\.\//gi,
      /\.\.%2f/gi,
    ],
  },
  python: {
    'SQL Injection': [
      /execute\s*\(\s*[f'"].*%s/gi,
      /execute\s*\(\s*f['"].*\{/gi,
      /cursor\.execute\s*\(.*\+/gi,
    ],
    'Command Injection': [
      /os\.system\s*\(/gi,
      /subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True/gi,
      /os\.popen\s*\(/gi,
    ],
    'Pickle Deserialization': [
      /pickle\.loads?\s*\(/gi,
      /cPickle\.loads?\s*\(/gi,
    ],
    'YAML Unsafe Load': [
      /yaml\.load\s*\([^,]*\)/gi,
      /yaml\.unsafe_load/gi,
    ],
    'Hardcoded Secrets': [
      /password\s*=\s*['"][^'"]+['"]/gi,
      /api_key\s*=\s*['"][^'"]+['"]/gi,
      /secret\s*=\s*['"][^'"]+['"]/gi,
    ],
    'Debug Mode': [
      /DEBUG\s*=\s*True/gi,
      /app\.run\s*\(.*debug\s*=\s*True/gi,
    ],
    'Weak Crypto': [
      /hashlib\.md5\s*\(/gi,
      /hashlib\.sha1\s*\(/gi,
    ],
  },
  java: {
    'SQL Injection': [
      /createStatement\s*\(\s*\)\.execute/gi,
      /Statement\s+.*=.*createStatement/gi,
      /executeQuery\s*\(\s*.*\+/gi,
    ],
    'XXE': [
      /DocumentBuilderFactory.*newInstance/gi,
      /SAXParserFactory.*newInstance/gi,
      /XMLInputFactory.*newInstance/gi,
    ],
    'Hardcoded Secrets': [
      /String\s+password\s*=\s*["'][^"']+["']/gi,
      /String\s+apiKey\s*=\s*["'][^"']+["']/gi,
    ],
    'Insecure Random': [
      /new\s+Random\s*\(\s*\)/gi,
      /Math\.random\s*\(\s*\)/gi,
    ],
    'Weak Crypto': [
      /getInstance\s*\(\s*["']DES["']/gi,
      /getInstance\s*\(\s*["']MD5["']/gi,
    ],
  },
  php: {
    'SQL Injection': [
      /mysql_query\s*\(/gi,
      /mysqli_query\s*\(.*\$/gi,
      /\$.*->query\s*\(.*\$/gi,
    ],
    'Command Injection': [
      /shell_exec\s*\(/gi,
      /exec\s*\(/gi,
      /system\s*\(/gi,
      /passthru\s*\(/gi,
    ],
    'File Inclusion': [
      /include\s*\(\s*\$/gi,
      /require\s*\(\s*\$/gi,
      /include_once\s*\(\s*\$/gi,
    ],
    'XSS': [
      /echo\s+\$/gi,
      /print\s+\$/gi,
    ],
    'Deserialization': [
      /unserialize\s*\(/gi,
    ],
  },
};

export default {
  OWASP_TOP_10_2021,
  CWE_DATABASE,
  VULNERABILITY_PATTERNS,
};
