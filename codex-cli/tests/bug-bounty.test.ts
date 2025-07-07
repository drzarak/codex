import { describe, it, expect } from 'vitest';
import { VulnerabilityAnalyzer, BountySessionManager } from '../src/utils/bounty/analyzer';
import { SECURITY_TOOLS, getToolByName, getToolsByCategory } from '../src/utils/bounty/tools';
import { BOUNTY_INSTRUCTIONS } from '../src/utils/bounty/instructions';
import { VulnerabilityDatabase, CVSSCalculator, VULNERABILITY_PATTERNS } from '../src/utils/bounty/vulnerability-db';

describe('Bug Bounty Functionality', () => {
  describe('VulnerabilityAnalyzer', () => {
    it('should calculate risk scores correctly', () => {
      const findings = [
        {
          id: '1',
          title: 'SQL Injection',
          severity: 'critical' as const,
          description: 'Test',
          evidence: [],
          impact: 'High',
          remediation: 'Fix it',
          references: [],
          tool: 'sqlmap',
          timestamp: new Date()
        },
        {
          id: '2',
          title: 'XSS',
          severity: 'medium' as const,
          description: 'Test',
          evidence: [],
          impact: 'Medium',
          remediation: 'Fix it',
          references: [],
          tool: 'nikto',
          timestamp: new Date()
        }
      ];

      const riskScore = VulnerabilityAnalyzer.calculateRiskScore(findings);
      expect(riskScore).toBe(15); // 10 (critical) + 5 (medium)
    });

    it('should categorize vulnerabilities correctly', () => {
      const findings = [
        {
          id: '1',
          title: 'SQL Injection vulnerability found',
          severity: 'critical' as const,
          description: 'Test',
          evidence: [],
          impact: 'High',
          remediation: 'Fix it',
          references: [],
          tool: 'sqlmap',
          timestamp: new Date()
        },
        {
          id: '2',
          title: 'Cross-site scripting (XSS) detected',
          severity: 'medium' as const,
          description: 'Test',
          evidence: [],
          impact: 'Medium',
          remediation: 'Fix it',
          references: [],
          tool: 'nikto',
          timestamp: new Date()
        }
      ];

      const categories = VulnerabilityAnalyzer.categorizeFindings(findings);
      expect(categories['Injection Attacks']).toHaveLength(1);
      expect(categories['Cross-Site Scripting']).toHaveLength(1);
    });

    it('should generate executive summary', () => {
      const scanResult = {
        target: 'example.com',
        scanType: 'web application scan',
        startTime: new Date('2023-01-01'),
        endTime: new Date('2023-01-02'),
        findings: [
          {
            id: '1',
            title: 'SQL Injection',
            severity: 'critical' as const,
            description: 'Test',
            evidence: [],
            impact: 'High',
            remediation: 'Fix it',
            references: [],
            tool: 'sqlmap',
            timestamp: new Date()
          }
        ],
        toolsUsed: ['sqlmap', 'nikto'],
        metadata: {}
      };

      const summary = VulnerabilityAnalyzer.generateExecutiveSummary(scanResult);
      expect(summary).toContain('example.com');
      expect(summary).toContain('web application scan');
      expect(summary).toContain('Total Vulnerabilities: 1');
      expect(summary).toContain('sqlmap');
    });
  });

  describe('Security Tools', () => {
    it('should have required security tools defined', () => {
      expect(SECURITY_TOOLS.length).toBeGreaterThan(0);
      
      const requiredTools = ['nmap', 'gobuster', 'sqlmap', 'nikto'];
      for (const toolName of requiredTools) {
        const tool = getToolByName(toolName);
        expect(tool).toBeDefined();
        expect(tool?.name).toBe(toolName);
      }
    });

    it('should categorize tools correctly', () => {
      const scanningTools = getToolsByCategory('scanning');
      const reconTools = getToolsByCategory('reconnaissance');
      
      expect(scanningTools.length).toBeGreaterThan(0);
      expect(reconTools.length).toBeGreaterThan(0);
      
      expect(scanningTools.some(tool => tool.name === 'nmap')).toBe(true);
      expect(reconTools.some(tool => tool.name === 'gobuster')).toBe(true);
    });
  });

  describe('BountySessionManager', () => {
    it('should create and manage sessions', () => {
      const manager = new BountySessionManager();
      const session = manager.createSession('example.com');
      
      expect(session.target).toBe('example.com');
      expect(session.id).toBeDefined();
      expect(session.scans).toHaveLength(0);
      expect(session.improvements).toHaveLength(0);
      
      const retrieved = manager.getSession(session.id);
      expect(retrieved).toEqual(session);
    });

    it('should add scan results to sessions', () => {
      const manager = new BountySessionManager();
      const session = manager.createSession('example.com');
      
      const scanResult = {
        target: 'example.com',
        scanType: 'test scan',
        startTime: new Date(),
        endTime: new Date(),
        findings: [],
        toolsUsed: ['nmap'],
        metadata: {}
      };
      
      manager.addScanResult(session.id, scanResult);
      
      const retrieved = manager.getSession(session.id);
      expect(retrieved?.scans).toHaveLength(1);
      expect(retrieved?.scans[0]).toEqual(scanResult);
    });
  });

  describe('Bounty Instructions', () => {
    it('should contain essential security testing guidance', () => {
      expect(BOUNTY_INSTRUCTIONS).toContain('bug bounty');
      expect(BOUNTY_INSTRUCTIONS).toContain('vulnerability');
      expect(BOUNTY_INSTRUCTIONS).toContain('nmap');
      expect(BOUNTY_INSTRUCTIONS).toContain('ethical');
      expect(BOUNTY_INSTRUCTIONS).toContain('self-improvement');
    });
  });

  describe('Vulnerability Database', () => {
    it('should identify SQL injection vulnerabilities', () => {
      const pattern = VulnerabilityDatabase.identifyVulnerability(
        'SQL Injection found',
        'Union-based SQL injection vulnerability detected'
      );
      
      expect(pattern).toBeDefined();
      expect(pattern?.name).toBe('SQL Injection');
      expect(pattern?.cwe).toBe('CWE-89');
    });

    it('should identify XSS vulnerabilities', () => {
      const pattern = VulnerabilityDatabase.identifyVulnerability(
        'Cross-site scripting detected',
        'Reflected XSS vulnerability in search parameter'
      );
      
      expect(pattern).toBeDefined();
      expect(pattern?.name).toBe('Cross-Site Scripting (XSS)');
      expect(pattern?.cwe).toBe('CWE-79');
    });

    it('should enhance findings with CVSS scores', () => {
      const findings = [
        {
          title: 'SQL injection vulnerability',
          description: 'Union-based SQL injection',
          severity: 'high',
          remediation: 'Use prepared statements'
        }
      ];

      const enhanced = VulnerabilityDatabase.enhanceFindings(findings);
      expect(enhanced[0].cvssScore).toBeDefined();
      expect(enhanced[0].cwe).toBe('CWE-89');
      expect(enhanced[0].enhancedRemediation).toContain('parameterized');
    });
  });

  describe('CVSS Calculator', () => {
    it('should calculate CVSS scores correctly', () => {
      const metrics = {
        attackVector: 'network' as const,
        attackComplexity: 'low' as const,
        privilegesRequired: 'none' as const,
        userInteraction: 'none' as const,
        scope: 'unchanged' as const,
        confidentialityImpact: 'high' as const,
        integrityImpact: 'high' as const,
        availabilityImpact: 'high' as const
      };

      const score = CVSSCalculator.calculateScore(metrics);
      expect(score).toBeGreaterThan(8.0); // Should be critical
      expect(score).toBeLessThanOrEqual(10.0);
    });

    it('should return correct severity ratings', () => {
      expect(CVSSCalculator.getSeverityRating(9.5)).toBe('critical');
      expect(CVSSCalculator.getSeverityRating(7.5)).toBe('high');
      expect(CVSSCalculator.getSeverityRating(5.0)).toBe('medium');
      expect(CVSSCalculator.getSeverityRating(2.0)).toBe('low');
      expect(CVSSCalculator.getSeverityRating(0.0)).toBe('info');
    });
  });

  describe('Vulnerability Patterns', () => {
    it('should have comprehensive vulnerability patterns', () => {
      expect(VULNERABILITY_PATTERNS.length).toBeGreaterThan(5);
      
      const patternNames = VULNERABILITY_PATTERNS.map(p => p.name);
      expect(patternNames).toContain('SQL Injection');
      expect(patternNames).toContain('Cross-Site Scripting (XSS)');
      expect(patternNames).toContain('Remote Code Execution');
    });

    it('should have valid CWE identifiers', () => {
      for (const pattern of VULNERABILITY_PATTERNS) {
        expect(pattern.cwe).toMatch(/^CWE-\d+$/);
      }
    });
  });
});