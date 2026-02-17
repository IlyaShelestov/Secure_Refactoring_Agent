/**
 * AI Secure Refactoring Agent - Frontend Application
 */

// State
let currentScanId = null;
let currentVulnerabilities = [];
let currentCode = '';
let currentAnalysis = null;
let currentRefactoredCode = null;
let currentFixesSummary = null;

// DOM Elements
const codeInput = document.getElementById('code-input');
const languageSelect = document.getElementById('language-select');
const scanBtn = document.getElementById('scan-btn');
const clearBtn = document.getElementById('clear-btn');
const loadSampleBtn = document.getElementById('load-sample');
const fileUpload = document.getElementById('file-upload');
const resultsContainer = document.getElementById('results-container');
const vulnCount = document.getElementById('vuln-count');
const fixAllBtn = document.getElementById('fix-all-btn');
const summaryFooter = document.getElementById('summary-footer');
const scanSummary = document.getElementById('scan-summary');
const refactoredPanel = document.getElementById('refactored-panel');
const refactoredCode = document.getElementById('refactored-code');
const fixesSummary = document.getElementById('fixes-summary');
const copyRefactoredBtn = document.getElementById('copy-refactored');
const closeRefactoredBtn = document.getElementById('close-refactored');
const loadingOverlay = document.getElementById('loading-overlay');
const loadingText = document.getElementById('loading-text');
const toast = document.getElementById('toast');
const navBtns = document.querySelectorAll('.nav-btn');
const tabContents = document.querySelectorAll('.tab-content');

// Analysis panel elements
const analysisPanel = document.getElementById('analysis-panel');
const analysisContent = document.getElementById('analysis-content');
const downloadReportBtn = document.getElementById('download-report-btn');

// Reference tab elements
const owaspReference = document.getElementById('owasp-reference');

// Sample vulnerable code
const SAMPLE_CODE = `// Example vulnerable Node.js code
const express = require('express');
const mysql = require('mysql');
const app = express();

// Hardcoded credentials (CWE-798)
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'admin123',  // Hardcoded password
    database: 'users'
});

// SQL Injection vulnerability (CWE-89)
app.get('/user', (req, res) => {
    const userId = req.query.id;
    const query = "SELECT * FROM users WHERE id = " + userId;
    db.query(query, (err, results) => {
        res.json(results);
    });
});

// XSS vulnerability (CWE-79)
app.get('/search', (req, res) => {
    const searchTerm = req.query.q;
    res.send('<h1>Search results for: ' + searchTerm + '</h1>');
});

// Command Injection (CWE-78)
app.get('/ping', (req, res) => {
    const host = req.query.host;
    const exec = require('child_process').exec;
    exec('ping -c 4 ' + host, (error, stdout) => {
        res.send(stdout);
    });
});

// Path Traversal (CWE-22)
app.get('/file', (req, res) => {
    const filename = req.query.name;
    const fs = require('fs');
    fs.readFile('./uploads/' + filename, (err, data) => {
        res.send(data);
    });
});

// Insecure randomness (CWE-330)
app.get('/token', (req, res) => {
    const token = Math.random().toString(36).substring(7);
    res.json({ token: token });
});

// Eval usage (CWE-94)
app.post('/calculate', (req, res) => {
    const expression = req.body.expr;
    const result = eval(expression);
    res.json({ result: result });
});

app.listen(3000);
`;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializeNavigation();
    loadOwaspReference();
    setupEventListeners();
    setupLineNumbers();
});

// Setup line numbers for code editors
function setupLineNumbers() {
    setupLineNumbersForTextarea('code-input', 'line-numbers');
    setupLineNumbersForTextarea('analyze-code-input', 'analyze-line-numbers');
}

function setupLineNumbersForTextarea(textareaId, lineNumbersId) {
    const textarea = document.getElementById(textareaId);
    const lineNumbers = document.getElementById(lineNumbersId);
    
    if (!textarea || !lineNumbers) return;
    
    function updateLineNumbers() {
        const lines = textarea.value.split('\n').length;
        const lineNumbersHtml = [];
        for (let i = 1; i <= Math.max(lines, 20); i++) {
            lineNumbersHtml.push(`<span>${i}</span>`);
        }
        lineNumbers.innerHTML = lineNumbersHtml.join('');
    }
    
    function syncScroll() {
        lineNumbers.scrollTop = textarea.scrollTop;
    }
    
    textarea.addEventListener('input', updateLineNumbers);
    textarea.addEventListener('scroll', syncScroll);
    textarea.addEventListener('keydown', updateLineNumbers);
    
    // Initialize
    updateLineNumbers();
}

// Navigation
function initializeNavigation() {
    navBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.dataset.tab;
            
            navBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            tabContents.forEach(content => {
                content.classList.remove('active');
                if (content.id === `${targetTab}-tab`) {
                    content.classList.add('active');
                }
            });
        });
    });
}

// Event Listeners
function setupEventListeners() {
    scanBtn.addEventListener('click', handleScan);
    clearBtn.addEventListener('click', handleClear);
    loadSampleBtn.addEventListener('click', loadSample);
    fileUpload.addEventListener('change', handleFileUpload);
    fixAllBtn.addEventListener('click', handleFixAll);
    copyRefactoredBtn.addEventListener('click', copyRefactoredCode);
    closeRefactoredBtn.addEventListener('click', closeRefactoredPanel);
    downloadReportBtn.addEventListener('click', downloadReport);
}

// Load sample code
function loadSample() {
    codeInput.value = SAMPLE_CODE;
    showToast('Sample vulnerable code loaded', 'success');
}

// Handle file upload
function handleFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = (event) => {
        codeInput.value = event.target.result;
        showToast(`Loaded: ${file.name}`, 'success');
    };
    reader.readAsText(file);
}

// Handle scan
async function handleScan() {
    const code = codeInput.value.trim();
    if (!code) {
        showToast('Please enter code to scan', 'error');
        return;
    }
    
    currentCode = code;
    showLoading('Scanning code for vulnerabilities...');
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                code,
                language: languageSelect.value || undefined
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            currentScanId = result.scanId;
            currentVulnerabilities = result.vulnerabilities;
            displayResults(result);
            showToast(`Found ${result.vulnerabilities.length} vulnerabilities`, 
                result.vulnerabilities.length > 0 ? 'error' : 'success');
            
            // Use analysis data from scan if available, otherwise run separate analysis
            if (result.analysis && (result.analysis.attackVectors?.length > 0 || result.analysis.recommendations?.length > 0)) {
                currentAnalysis = result.analysis;
                displayAnalysis(result.analysis);
            } else {
                // Fallback to separate analysis if scan didn't provide it
                runSecurityAnalysis(code);
            }
        } else {
            showToast(result.error || 'Scan failed', 'error');
        }
    } catch (error) {
        console.error('Scan error:', error);
        showToast('Failed to connect to server', 'error');
    } finally {
        hideLoading();
    }
}

// Display scan results
function displayResults(result) {
    const { vulnerabilities, summary, language } = result;
    
    vulnCount.textContent = vulnerabilities.length;
    vulnCount.className = `badge ${getSeverityClass(summary.riskLevel)}`;
    fixAllBtn.disabled = vulnerabilities.length === 0;
    downloadReportBtn.disabled = vulnerabilities.length === 0;
    
    if (vulnerabilities.length === 0) {
        resultsContainer.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-check-circle" style="color: var(--success);"></i>
                <p>No vulnerabilities found!</p>
                <span>Your code appears to be secure. Detected language: ${language}</span>
            </div>
        `;
        summaryFooter.style.display = 'none';
        return;
    }
    
    // Display vulnerability cards
    resultsContainer.innerHTML = vulnerabilities.map((vuln, index) => `
        <div class="vuln-card" data-index="${index}">
            <div class="vuln-card-header" onclick="toggleVulnCard(${index})">
                <div class="vuln-card-title">
                    <h3>
                        <i class="fas fa-exclamation-triangle" style="color: var(--${getSeverityColor(vuln.severity)});"></i>
                        ${escapeHtml(vuln.type)}
                    </h3>
                    <span>Lines: ${vuln.lineNumbers?.join(', ') || 'N/A'} | ${vuln.owaspCategory || 'N/A'} | ${vuln.cweId || 'N/A'}</span>
                </div>
                <div class="vuln-card-badges">
                    <span class="badge ${getSeverityClass(vuln.severity)}">${vuln.severity}</span>
                    <span class="badge confidence-badge" title="Confidence">${getConfidencePercent(vuln.confidence)}%</span>
                </div>
            </div>
            <div class="vuln-card-body">
                <div class="vuln-detail">
                    <label>Description</label>
                    <p>${escapeHtml(vuln.description || 'No description available')}</p>
                </div>
                ${vuln.impact ? `
                <div class="vuln-detail">
                    <label>Impact</label>
                    <p>${escapeHtml(vuln.impact)}</p>
                </div>
                ` : ''}
                ${vuln.codeSnippet ? `
                <div class="vuln-detail">
                    <label>Vulnerable Code</label>
                    <div class="vuln-code">${escapeHtml(vuln.codeSnippet)}</div>
                </div>
                ` : ''}
                ${vuln.owaspInfo ? `
                <div class="vuln-detail">
                    <label>OWASP Information</label>
                    <p><strong>${vuln.owaspInfo.name}:</strong> ${escapeHtml(vuln.owaspInfo.description || '')}</p>
                </div>
                ` : ''}
                <div class="vuln-card-actions">
                    <button class="btn btn-success" onclick="handleFixSingle(${index})">
                        <i class="fas fa-wrench"></i> Fix This
                    </button>
                </div>
            </div>
        </div>
    `).join('');
    
    // Display summary
    summaryFooter.style.display = 'block';
    scanSummary.innerHTML = `
        <div class="summary-grid">
            <div class="summary-item">
                <div class="count" style="color: var(--danger);">${summary.severityBreakdown.Critical || 0}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-item">
                <div class="count" style="color: #f97316;">${summary.severityBreakdown.High || 0}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-item">
                <div class="count" style="color: var(--warning);">${summary.severityBreakdown.Medium || 0}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-item">
                <div class="count" style="color: var(--success);">${summary.severityBreakdown.Low || 0}</div>
                <div class="label">Low</div>
            </div>
        </div>
    `;
}

// Toggle vulnerability card expansion
function toggleVulnCard(index) {
    const card = document.querySelector(`.vuln-card[data-index="${index}"]`);
    card.classList.toggle('expanded');
}

// Make toggleVulnCard available globally
window.toggleVulnCard = toggleVulnCard;

// Handle fix single vulnerability
async function handleFixSingle(index) {
    const vulnerability = currentVulnerabilities[index];
    showLoading('Generating secure fix...');
    
    try {
        const response = await fetch('/api/refactor', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                code: currentCode,
                vulnerability,
                language: languageSelect.value || undefined
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            displayRefactoredCode(result);
            showToast('Secure fix generated!', 'success');
        } else {
            showToast(result.error || 'Fix generation failed', 'error');
        }
    } catch (error) {
        console.error('Fix error:', error);
        showToast('Failed to generate fix', 'error');
    } finally {
        hideLoading();
    }
}

// Make handleFixSingle available globally
window.handleFixSingle = handleFixSingle;

// Handle fix all vulnerabilities
async function handleFixAll() {
    if (currentVulnerabilities.length === 0) return;
    
    showLoading('Fixing all vulnerabilities...');
    
    try {
        const response = await fetch('/api/refactor/all', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                scanId: currentScanId
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            displayRefactoredCode(result);
            showToast(`Fixed ${result.vulnerabilitiesFixed} vulnerabilities!`, 'success');
        } else {
            showToast(result.error || 'Fix generation failed', 'error');
        }
    } catch (error) {
        console.error('Fix all error:', error);
        showToast('Failed to generate fixes', 'error');
    } finally {
        hideLoading();
    }
}

// Display refactored code
function displayRefactoredCode(result) {
    refactoredPanel.style.display = 'block';
    currentRefactoredCode = result.fixedCode || result.refactoredCode;
    refactoredCode.textContent = currentRefactoredCode;
    
    // Store fixes summary for download
    currentFixesSummary = {
        fixesSummary: result.fixesSummary || [],
        changes: result.changes || [],
        securityImprovements: result.securityImprovements || [],
        remainingRisks: result.remainingRisks || []
    };
    
    const summaryHtml = [];
    
    if (result.fixesSummary && result.fixesSummary.length > 0) {
        summaryHtml.push('<h4>Fixes Applied:</h4><ul>');
        result.fixesSummary.forEach(fix => {
            summaryHtml.push(`<li><strong>${escapeHtml(fix.vulnerabilityType || fix.type)}:</strong> ${escapeHtml(fix.fixApplied || fix.explanation)}</li>`);
        });
        summaryHtml.push('</ul>');
    }
    
    if (result.changes && result.changes.length > 0) {
        summaryHtml.push('<h4>Changes Made:</h4><ul>');
        result.changes.forEach(change => {
            summaryHtml.push(`<li>${escapeHtml(change.explanation)}</li>`);
        });
        summaryHtml.push('</ul>');
    }
    
    if (result.securityImprovements && result.securityImprovements.length > 0) {
        summaryHtml.push('<h4>Security Improvements:</h4><ul>');
        result.securityImprovements.forEach(improvement => {
            summaryHtml.push(`<li>${escapeHtml(improvement)}</li>`);
        });
        summaryHtml.push('</ul>');
    }
    
    if (result.remainingRisks && result.remainingRisks.length > 0) {
        summaryHtml.push('<h4 style="color: var(--warning);">Remaining Risks:</h4><ul>');
        result.remainingRisks.forEach(risk => {
            summaryHtml.push(`<li>${escapeHtml(risk)}</li>`);
        });
        summaryHtml.push('</ul>');
    }
    
    fixesSummary.innerHTML = summaryHtml.join('');
    
    // Scroll to refactored panel
    refactoredPanel.scrollIntoView({ behavior: 'smooth' });
}

// Copy refactored code
function copyRefactoredCode() {
    const code = refactoredCode.textContent;
    navigator.clipboard.writeText(code).then(() => {
        showToast('Code copied to clipboard!', 'success');
    }).catch(() => {
        showToast('Failed to copy code', 'error');
    });
}

// Close refactored panel
function closeRefactoredPanel() {
    refactoredPanel.style.display = 'none';
}

// Handle clear
function handleClear() {
    codeInput.value = '';
    currentScanId = null;
    currentVulnerabilities = [];
    currentCode = '';
    currentAnalysis = null;
    currentRefactoredCode = null;
    currentFixesSummary = null;
    vulnCount.textContent = '0';
    vulnCount.className = 'badge';
    fixAllBtn.disabled = true;
    downloadReportBtn.disabled = true;
    summaryFooter.style.display = 'none';
    refactoredPanel.style.display = 'none';
    analysisPanel.style.display = 'none';
    resultsContainer.innerHTML = `
        <div class="empty-state">
            <i class="fas fa-shield-alt"></i>
            <p>No scan results yet</p>
            <span>Paste code and click "Scan for Vulnerabilities"</span>
        </div>
    `;
    // Update line numbers
    const lineNumbers = document.getElementById('line-numbers');
    if (lineNumbers) {
        lineNumbers.innerHTML = '<span>1</span>';
    }
}

// Download security report as text file
function downloadReport() {
    if (currentVulnerabilities.length === 0) {
        showToast('No scan results to download', 'error');
        return;
    }
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    let report = '';
    
    // Header
    report += '='.repeat(60) + '\n';
    report += '           SECURITY SCAN REPORT\n';
    report += '           AI Secure Refactoring Agent\n';
    report += '='.repeat(60) + '\n\n';
    report += `Generated: ${new Date().toLocaleString()}\n`;
    report += `Scan ID: ${currentScanId}\n`;
    report += '\n';
    
    // Original Code
    report += '-'.repeat(60) + '\n';
    report += '                 SCANNED CODE\n';
    report += '-'.repeat(60) + '\n\n';
    report += currentCode + '\n\n';
    
    // Summary
    report += '-'.repeat(60) + '\n';
    report += '                    SUMMARY\n';
    report += '-'.repeat(60) + '\n\n';
    report += `Total Vulnerabilities Found: ${currentVulnerabilities.length}\n\n`;
    
    // Count by severity
    const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    currentVulnerabilities.forEach(v => {
        if (severityCounts[v.severity] !== undefined) {
            severityCounts[v.severity]++;
        }
    });
    
    report += 'Severity Breakdown:\n';
    report += `  - Critical: ${severityCounts.Critical}\n`;
    report += `  - High: ${severityCounts.High}\n`;
    report += `  - Medium: ${severityCounts.Medium}\n`;
    report += `  - Low: ${severityCounts.Low}\n\n`;
    
    // Vulnerabilities
    report += '-'.repeat(60) + '\n';
    report += '                VULNERABILITIES\n';
    report += '-'.repeat(60) + '\n\n';
    
    currentVulnerabilities.forEach((vuln, index) => {
        report += `[${index + 1}] ${vuln.type}\n`;
        report += `    Severity: ${vuln.severity} | Confidence: ${getConfidencePercent(vuln.confidence)}%\n`;
        report += `    OWASP: ${vuln.owaspCategory || 'N/A'} | CWE: ${vuln.cweId || 'N/A'}\n`;
        report += `    Lines: ${vuln.lineNumbers?.join(', ') || 'N/A'}\n`;
        report += `    Description: ${vuln.description || 'No description'}\n`;
        if (vuln.impact) {
            report += `    Impact: ${vuln.impact}\n`;
        }
        if (vuln.codeSnippet) {
            report += `    Code: ${vuln.codeSnippet.substring(0, 100)}...\n`;
        }
        report += '\n';
    });
    
    // Security Posture Analysis
    if (currentAnalysis) {
        report += '-'.repeat(60) + '\n';
        report += '           SECURITY POSTURE ANALYSIS\n';
        report += '-'.repeat(60) + '\n\n';
        
        const analysisScore = Math.max(0, Math.min(100, parseInt(currentAnalysis.securityScore) || 0));
        report += `Security Score: ${analysisScore}/100\n`;
        report += `Assessment: ${currentAnalysis.overallAssessment || 'Analysis complete'}\n\n`;
        
        if (currentAnalysis.riskAreas && currentAnalysis.riskAreas.length > 0) {
            report += 'Risk Areas:\n';
            currentAnalysis.riskAreas.forEach((risk, i) => {
                report += `  ${i + 1}. [${risk.priority || 'Medium'}] ${risk.location || 'Unknown'}: ${risk.risk || 'No description'}\n`;
            });
            report += '\n';
        }
        
        if (currentAnalysis.attackVectors && currentAnalysis.attackVectors.length > 0) {
            report += 'Potential Attack Vectors:\n';
            currentAnalysis.attackVectors.forEach((attack, i) => {
                report += `  ${i + 1}. ${attack.vector} (${attack.likelihood} likelihood)\n`;
                report += `     ${attack.description}\n`;
            });
            report += '\n';
        }
        
        if (currentAnalysis.recommendations && currentAnalysis.recommendations.length > 0) {
            report += 'Recommendations:\n';
            currentAnalysis.recommendations.forEach((rec, i) => {
                report += `  ${i + 1}. [${rec.priority}] ${rec.recommendation} (Effort: ${rec.effort})\n`;
            });
            report += '\n';
        }
        
        if (currentAnalysis.securePatterns && currentAnalysis.securePatterns.length > 0) {
            report += 'Secure Patterns Found:\n';
            currentAnalysis.securePatterns.forEach((pattern, i) => {
                report += `  + ${pattern}\n`;
            });
            report += '\n';
        }
    }
    
    // Code Fixes (if any)
    if (currentRefactoredCode) {
        report += '-'.repeat(60) + '\n';
        report += '              REFACTORED SECURE CODE\n';
        report += '-'.repeat(60) + '\n\n';
        
        if (currentFixesSummary) {
            if (currentFixesSummary.fixesSummary && currentFixesSummary.fixesSummary.length > 0) {
                report += 'Fixes Applied:\n';
                currentFixesSummary.fixesSummary.forEach((fix, i) => {
                    report += `  ${i + 1}. ${fix.vulnerabilityType || fix.type}: ${fix.fixApplied || fix.explanation}\n`;
                });
                report += '\n';
            }
            
            if (currentFixesSummary.changes && currentFixesSummary.changes.length > 0) {
                report += 'Changes Made:\n';
                currentFixesSummary.changes.forEach((change, i) => {
                    report += `  ${i + 1}. ${change.explanation}\n`;
                });
                report += '\n';
            }
            
            if (currentFixesSummary.securityImprovements && currentFixesSummary.securityImprovements.length > 0) {
                report += 'Security Improvements:\n';
                currentFixesSummary.securityImprovements.forEach((imp, i) => {
                    report += `  + ${imp}\n`;
                });
                report += '\n';
            }
            
            if (currentFixesSummary.remainingRisks && currentFixesSummary.remainingRisks.length > 0) {
                report += 'Remaining Risks:\n';
                currentFixesSummary.remainingRisks.forEach((risk, i) => {
                    report += `  ! ${risk}\n`;
                });
                report += '\n';
            }
        }
        
        report += 'Refactored Code:\n';
        report += '-'.repeat(40) + '\n';
        report += currentRefactoredCode + '\n';
        report += '-'.repeat(40) + '\n\n';
    }
    
    // Footer
    report += '='.repeat(60) + '\n';
    report += '                END OF REPORT\n';
    report += '='.repeat(60) + '\n';
    
    // Create and download file
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${timestamp}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Report downloaded!', 'success');
}

// Run security analysis in background after scan
async function runSecurityAnalysis(code) {
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code })
        });
        
        const result = await response.json();
        
        if (result.success) {
            currentAnalysis = result.analysis;
            displayAnalysis(result.analysis);
        }
    } catch (error) {
        console.error('Analysis error:', error);
    }
}

// Display analysis results
function displayAnalysis(analysis) {
    analysisPanel.style.display = 'block';
    
    // Ensure score is a valid number between 0-100
    const score = Math.max(0, Math.min(100, parseInt(analysis.securityScore) || 0));
    
    const scoreColor = score >= 70 ? 'var(--success)' : 
                      score >= 40 ? 'var(--warning)' : 'var(--danger)';
    
    analysisContent.innerHTML = `
        <div class="security-score">
            <div class="score-circle">
                <svg viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="45" fill="none" stroke="var(--border-color)" stroke-width="8"/>
                    <circle cx="50" cy="50" r="45" fill="none" stroke="${scoreColor}" stroke-width="8"
                        stroke-dasharray="${score * 2.83} 283"
                        transform="rotate(-90 50 50)"/>
                </svg>
                <div class="score-value" style="color: ${scoreColor};">${score}</div>
            </div>
            <div class="score-info">
                <h4>Security Score</h4>
                <p>${escapeHtml(analysis.overallAssessment || 'Analysis complete')}</p>
            </div>
        </div>
        
        ${analysis.riskAreas && analysis.riskAreas.length > 0 ? `
        <div class="analysis-section">
            <h3><i class="fas fa-exclamation-triangle"></i> Risk Areas</h3>
            <div class="risk-list">
                ${analysis.riskAreas.map(risk => `
                    <div class="risk-item ${risk.priority?.toLowerCase()}">
                        <div>
                            <strong>${escapeHtml(risk.location)}</strong>
                            <p>${escapeHtml(risk.risk)}</p>
                            <span class="badge ${getSeverityClass(risk.priority)}">${risk.priority}</span>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}
        
        ${analysis.attackVectors && analysis.attackVectors.length > 0 ? `
        <div class="analysis-section">
            <h3><i class="fas fa-crosshairs"></i> Potential Attack Vectors</h3>
            <div class="risk-list">
                ${analysis.attackVectors.map(attack => `
                    <div class="risk-item ${attack.likelihood?.toLowerCase()}">
                        <div>
                            <strong>${escapeHtml(attack.vector)}</strong>
                            <p>${escapeHtml(attack.description)}</p>
                            <span class="badge">${attack.likelihood} likelihood</span>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}
        
        ${analysis.recommendations && analysis.recommendations.length > 0 ? `
        <div class="analysis-section">
            <h3><i class="fas fa-lightbulb"></i> Recommendations</h3>
            <div class="recommendation-list">
                ${analysis.recommendations.map(rec => `
                    <div class="recommendation-item">
                        <div>
                            <strong>${escapeHtml(rec.recommendation)}</strong>
                            <p>Priority: ${rec.priority} | Effort: ${rec.effort}</p>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}
        
        ${analysis.securePatterns && analysis.securePatterns.length > 0 ? `
        <div class="analysis-section">
            <h3><i class="fas fa-check-circle" style="color: var(--success);"></i> Secure Patterns Found</h3>
            <ul>
                ${analysis.securePatterns.map(pattern => `<li>${escapeHtml(pattern)}</li>`).join('')}
            </ul>
        </div>
        ` : ''}
    `;
}

// Load OWASP reference
async function loadOwaspReference() {
    try {
        const response = await fetch('/api/reference/owasp');
        const owasp = await response.json();
        
        owaspReference.innerHTML = `
            <div class="owasp-grid">
                ${Object.entries(owasp).map(([id, data]) => `
                    <div class="owasp-item">
                        <h3>
                            <span>${id.split(':')[0]}</span>
                            ${escapeHtml(data.name)}
                        </h3>
                        <p>${escapeHtml(data.description)}</p>
                        <strong>Mitigations:</strong>
                        <ul>
                            ${data.mitigations.slice(0, 4).map(m => `<li>${escapeHtml(m)}</li>`).join('')}
                        </ul>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (error) {
        console.error('Failed to load OWASP reference:', error);
        owaspReference.innerHTML = '<p>Failed to load OWASP reference</p>';
    }
}

// Utility functions
function showLoading(text = 'Loading...') {
    loadingText.textContent = text;
    loadingOverlay.classList.add('active');
}

function hideLoading() {
    loadingOverlay.classList.remove('active');
}

function showToast(message, type = 'info') {
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function getSeverityClass(severity) {
    const s = (severity || '').toLowerCase();
    if (s === 'critical') return 'critical';
    if (s === 'high') return 'high';
    if (s === 'medium') return 'medium';
    return 'low';
}

function getSeverityColor(severity) {
    const s = (severity || '').toLowerCase();
    if (s === 'critical') return 'danger';
    if (s === 'high') return 'warning';
    if (s === 'medium') return 'warning';
    return 'success';
}

function getConfidencePercent(confidence) {
    if (typeof confidence === 'number') return confidence;
    const c = (confidence || 'medium').toLowerCase();
    if (c === 'high') return 95;
    if (c === 'medium') return 75;
    if (c === 'low') return 50;
    return 75;
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ---------------------------------------------------------------------------
// Scan History
// ---------------------------------------------------------------------------

const historyContainer = document.getElementById('history-container');
const historyCountBadge = document.getElementById('history-count');
const refreshHistoryBtn = document.getElementById('refresh-history-btn');
const clearHistoryBtn = document.getElementById('clear-history-btn');

// Load scan history from API
async function loadHistory() {
    try {
        const response = await fetch('/api/scans?limit=100');
        const data = await response.json();
        renderHistory(data.scans || [], data.total || 0);
    } catch (error) {
        console.error('Failed to load history:', error);
        historyContainer.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-exclamation-circle"></i>
                <p>Failed to load history</p>
                <span>${escapeHtml(error.message)}</span>
            </div>`;
    }
}

// Render history table
function renderHistory(scans, total) {
    historyCountBadge.textContent = total;

    if (scans.length === 0) {
        historyContainer.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-history"></i>
                <p>No scan history yet</p>
                <span>Completed scans will appear here</span>
            </div>`;
        return;
    }

    const rows = scans.map(scan => {
        const date = new Date(scan.timestamp).toLocaleString();
        const score = scan.securityScore ?? '—';
        const scoreClass = typeof scan.securityScore === 'number'
            ? (scan.securityScore >= 70 ? 'good' : scan.securityScore >= 40 ? 'medium' : 'poor')
            : '';
        const risk = scan.riskLevel || '—';

        return `
            <tr class="history-row" data-scan-id="${escapeHtml(scan.scanId)}">
                <td>${escapeHtml(date)}</td>
                <td>${escapeHtml(scan.language || 'Unknown')}</td>
                <td>${escapeHtml(scan.filename || '—')}</td>
                <td><span class="history-row-score ${scoreClass}">${score}</span></td>
                <td><span class="badge ${getSeverityClass(risk)}">${escapeHtml(risk)}</span></td>
                <td class="history-summary">${escapeHtml(scan.summary || '—')}</td>
            </tr>`;
    }).join('');

    historyContainer.innerHTML = `
        <table class="history-table">
            <thead>
                <tr>
                    <th>Date</th>
                    <th>Language</th>
                    <th>File</th>
                    <th>Score</th>
                    <th>Risk</th>
                    <th>Summary</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>`;

    // Attach click handlers (CSP-safe — no inline onclick)
    historyContainer.querySelectorAll('.history-row').forEach(row => {
        row.addEventListener('click', () => {
            viewHistoryScan(row.dataset.scanId);
        });
    });
}

// View a past scan — fetches full details and loads into main Scan tab
async function viewHistoryScan(scanId) {
    showLoading('Loading scan details...');
    try {
        const response = await fetch(`/api/scan/${encodeURIComponent(scanId)}`);
        const result = await response.json();

        if (result) {
            // Switch to scan tab
            navBtns.forEach(b => b.classList.remove('active'));
            document.querySelector('[data-tab="scan"]').classList.add('active');
            tabContents.forEach(c => c.classList.remove('active'));
            document.getElementById('scan-tab').classList.add('active');

            // Populate scan tab with historical data
            if (result.code) codeInput.value = result.code;
            if (result.language) languageSelect.value = result.language;
            currentScanId = scanId;
            currentVulnerabilities = result.vulnerabilities || [];
            currentCode = result.code || '';
            displayResults(result);

            if (result.analysis) {
                currentAnalysis = result.analysis;
                displayAnalysis(result.analysis);
            }
            showToast('Loaded scan from history', 'success');
        } else {
            showToast('Scan not found', 'error');
        }
    } catch (error) {
        console.error('Failed to load scan:', error);
        showToast('Failed to load scan details', 'error');
    } finally {
        hideLoading();
    }
}
window.viewHistoryScan = viewHistoryScan;

// Clear all scan history with confirmation
function confirmClearHistory() {
    const dialog = document.createElement('div');
    dialog.className = 'confirm-dialog';
    dialog.innerHTML = `
        <div class="confirm-dialog-box">
            <p><i class="fas fa-exclamation-triangle" style="color: var(--warning); margin-right: 0.5rem;"></i>
               Are you sure you want to clear all scan history? This cannot be undone.</p>
            <div class="btn-group">
                <button class="btn btn-secondary" id="cancel-clear">Cancel</button>
                <button class="btn btn-danger" id="confirm-clear">Clear All</button>
            </div>
        </div>`;
    document.body.appendChild(dialog);

    document.getElementById('cancel-clear').addEventListener('click', () => dialog.remove());
    document.getElementById('confirm-clear').addEventListener('click', async () => {
        dialog.remove();
        try {
            const response = await fetch('/api/scans', { method: 'DELETE' });
            const data = await response.json();
            if (data.success) {
                showToast(`Cleared ${data.removed} scans from history`, 'success');
                loadHistory();
            } else {
                showToast('Failed to clear history', 'error');
            }
        } catch (error) {
            console.error('Failed to clear history:', error);
            showToast('Failed to clear history', 'error');
        }
    });
}

// Auto-load history when History tab is shown
if (refreshHistoryBtn) refreshHistoryBtn.addEventListener('click', loadHistory);
if (clearHistoryBtn) clearHistoryBtn.addEventListener('click', confirmClearHistory);

// Load history when tab is activated
const originalNavHandler = navBtns.forEach.bind(navBtns);
navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        if (btn.dataset.tab === 'history') {
            loadHistory();
        }
    });
});
