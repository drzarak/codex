export interface VulnerabilityFinding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvssScore?: number;
  description: string;
  evidence: string[];
  impact: string;
  remediation: string;
  references: string[];
  tool: string;
  timestamp: Date;
}

export interface ScanResult {
  target: string;
  scanType: string;
  startTime: Date;
  endTime: Date;
  findings: VulnerabilityFinding[];
  toolsUsed: string[];
  metadata: Record<string, any>;
}

export interface BountySession {
  id: string;
  target: string;
  startTime: Date;
  scans: ScanResult[];
  improvements: string[];
  notes: string;
}

export class VulnerabilityAnalyzer {
  private static severityWeights = {
    critical: 10,
    high: 7,
    medium: 5,
    low: 3,
    info: 1
  };

  static calculateRiskScore(findings: VulnerabilityFinding[]): number {
    return findings.reduce((score, finding) => {
      return score + this.severityWeights[finding.severity];
    }, 0);
  }

  static categorizeFindings(findings: VulnerabilityFinding[]): Record<string, VulnerabilityFinding[]> {
    return findings.reduce((categories, finding) => {
      const category = this.getVulnerabilityCategory(finding);
      if (!categories[category]) {
        categories[category] = [];
      }
      categories[category].push(finding);
      return categories;
    }, {} as Record<string, VulnerabilityFinding[]>);
  }

  private static getVulnerabilityCategory(finding: VulnerabilityFinding): string {
    const title = finding.title.toLowerCase();
    
    if (title.includes('sql injection') || title.includes('sqli')) {
      return 'Injection Attacks';
    }
    if (title.includes('xss') || title.includes('cross-site scripting')) {
      return 'Cross-Site Scripting';
    }
    if (title.includes('csrf') || title.includes('cross-site request forgery')) {
      return 'CSRF';
    }
    if (title.includes('authentication') || title.includes('authorization')) {
      return 'Authentication & Authorization';
    }
    if (title.includes('directory traversal') || title.includes('path traversal')) {
      return 'Directory Traversal';
    }
    if (title.includes('information disclosure') || title.includes('sensitive data')) {
      return 'Information Disclosure';
    }
    if (title.includes('ssl') || title.includes('tls') || title.includes('certificate')) {
      return 'SSL/TLS Issues';
    }
    if (title.includes('misconfiguration') || title.includes('configuration')) {
      return 'Security Misconfiguration';
    }
    
    return 'Other';
  }

  static generateExecutiveSummary(scanResult: ScanResult): string {
    const findings = scanResult.findings;
    const riskScore = this.calculateRiskScore(findings);
    const categories = this.categorizeFindings(findings);
    
    let summary = `# Security Assessment Summary\n\n`;
    summary += `**Target**: ${scanResult.target}\n`;
    summary += `**Scan Type**: ${scanResult.scanType}\n`;
    summary += `**Assessment Period**: ${scanResult.startTime.toISOString()} - ${scanResult.endTime.toISOString()}\n`;
    summary += `**Risk Score**: ${riskScore}\n\n`;
    
    summary += `## Findings Overview\n`;
    summary += `- Total Vulnerabilities: ${findings.length}\n`;
    
    const severityCounts = findings.reduce((counts, finding) => {
      counts[finding.severity] = (counts[finding.severity] || 0) + 1;
      return counts;
    }, {} as Record<string, number>);
    
    Object.entries(severityCounts).forEach(([severity, count]) => {
      summary += `- ${severity.charAt(0).toUpperCase() + severity.slice(1)}: ${count}\n`;
    });
    
    summary += `\n## Vulnerability Categories\n`;
    Object.entries(categories).forEach(([category, categoryFindings]) => {
      summary += `- ${category}: ${categoryFindings.length} finding(s)\n`;
    });
    
    summary += `\n## Tools Used\n`;
    scanResult.toolsUsed.forEach(tool => {
      summary += `- ${tool}\n`;
    });
    
    return summary;
  }

  static generateDetailedReport(scanResult: ScanResult): string {
    let report = this.generateExecutiveSummary(scanResult);
    
    report += `\n\n# Detailed Findings\n\n`;
    
    const categories = this.categorizeFindings(scanResult.findings);
    
    Object.entries(categories).forEach(([category, findings]) => {
      report += `## ${category}\n\n`;
      
      findings.forEach((finding, index) => {
        report += `### ${index + 1}. ${finding.title}\n\n`;
        report += `**Severity**: ${finding.severity.toUpperCase()}\n`;
        if (finding.cvssScore) {
          report += `**CVSS Score**: ${finding.cvssScore}\n`;
        }
        report += `**Tool**: ${finding.tool}\n\n`;
        
        report += `**Description**:\n${finding.description}\n\n`;
        
        if (finding.evidence.length > 0) {
          report += `**Evidence**:\n`;
          finding.evidence.forEach(evidence => {
            report += `- ${evidence}\n`;
          });
          report += `\n`;
        }
        
        report += `**Impact**:\n${finding.impact}\n\n`;
        report += `**Remediation**:\n${finding.remediation}\n\n`;
        
        if (finding.references.length > 0) {
          report += `**References**:\n`;
          finding.references.forEach(ref => {
            report += `- ${ref}\n`;
          });
          report += `\n`;
        }
        
        report += `---\n\n`;
      });
    });
    
    return report;
  }
}

export class BountySessionManager {
  private sessions: Map<string, BountySession> = new Map();
  
  createSession(target: string): BountySession {
    const session: BountySession = {
      id: this.generateSessionId(),
      target,
      startTime: new Date(),
      scans: [],
      improvements: [],
      notes: ''
    };
    
    this.sessions.set(session.id, session);
    return session;
  }
  
  addScanResult(sessionId: string, scanResult: ScanResult): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.scans.push(scanResult);
    }
  }
  
  addImprovement(sessionId: string, improvement: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.improvements.push(improvement);
    }
  }
  
  getSession(sessionId: string): BountySession | undefined {
    return this.sessions.get(sessionId);
  }
  
  getAllSessions(): BountySession[] {
    return Array.from(this.sessions.values());
  }
  
  private generateSessionId(): string {
    return `bounty-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}