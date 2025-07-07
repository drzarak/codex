import { AgentLoop } from "../agent/agent-loop";
import { getBountyPrompt } from "./instructions";
import { VulnerabilityAnalyzer, BountySessionManager, ScanResult } from "./analyzer";
import { SECURITY_TOOLS, checkToolAvailability, generateToolInstallScript } from "./tools";
import { createGeminiClient, GeminiClient } from "./gemini-client";
import { VulnerabilityDatabase } from "./vulnerability-db";
import { AppConfig } from "../config";

export class BountyAgent extends AgentLoop {
  private sessionManager: BountySessionManager;
  private geminiClient?: GeminiClient;
  private currentTarget?: string;
  private currentScanType?: string;

  constructor(
    model: string,
    instructions: string,
    config: AppConfig,
    onItem: any,
    onLoading: any,
    getCommandConfirmation: any,
    onLastResponseId: any,
    approvalPolicy: any
  ) {
    // Override instructions with bounty-specific prompts
    const bountyInstructions = instructions + "\n\n" + getBountyPrompt("", "");
    
    super(
      model,
      bountyInstructions,
      config,
      onItem,
      onLoading,
      getCommandConfirmation,
      onLastResponseId,
      approvalPolicy
    );
    
    this.sessionManager = new BountySessionManager();
    
    // Initialize Gemini client if using Gemini AI provider
    if (config.aiProvider === 'gemini' && config.geminiApiKey) {
      try {
        this.geminiClient = createGeminiClient(config.geminiApiKey);
      } catch (error) {
        console.warn("Failed to initialize Gemini client:", error);
      }
    }
  }

  async startBountySession(target: string, scanType: string): Promise<void> {
    this.currentTarget = target;
    this.currentScanType = scanType;
    
    const session = this.sessionManager.createSession(target);
    console.log(`Started bug bounty session: ${session.id}`);
    
    // Check and install required tools
    await this.ensureToolsAvailability();
    
    // Start the assessment with AI guidance
    const prompt = getBountyPrompt(target, scanType);
    
    await this.run([{
      type: "message",
      role: "user",
      content: [{
        type: "input_text",
        text: prompt
      }]
    }]);
  }

  private async ensureToolsAvailability(): Promise<void> {
    const requiredTools = this.getRequiredToolsForScanType(this.currentScanType || "");
    const missingTools: string[] = [];
    
    for (const toolName of requiredTools) {
      const isAvailable = await checkToolAvailability(toolName);
      if (!isAvailable) {
        missingTools.push(toolName);
      }
    }
    
    if (missingTools.length > 0) {
      console.log(`Missing tools detected: ${missingTools.join(", ")}`);
      console.log("Generating installation script...");
      
      const installScript = generateToolInstallScript(missingTools);
      
      // Save installation script
      const fs = await import('fs');
      const scriptPath = '/tmp/install-bounty-tools.sh';
      fs.writeFileSync(scriptPath, installScript);
      
      console.log(`Installation script saved to: ${scriptPath}`);
      console.log("Please review and run the script to install missing tools.");
    }
  }

  private getRequiredToolsForScanType(scanType: string): string[] {
    const type = scanType.toLowerCase();
    
    if (type.includes("web") || type.includes("application")) {
      return ["gobuster", "nikto", "sqlmap", "dirb", "whatweb", "curl"];
    }
    
    if (type.includes("network") || type.includes("enumeration")) {
      return ["nmap", "masscan", "dig"];
    }
    
    if (type.includes("subdomain") || type.includes("reconnaissance")) {
      return ["subfinder", "amass", "httpx", "dig"];
    }
    
    if (type.includes("comprehensive") || type.includes("full")) {
      return ["nmap", "gobuster", "nikto", "sqlmap", "subfinder", "nuclei", "httpx"];
    }
    
    // Default tools for general assessment
    return ["nmap", "gobuster", "nikto", "curl"];
  }

  async analyzeScanResults(results: string, toolUsed: string): Promise<ScanResult> {
    const scanResult: ScanResult = {
      target: this.currentTarget || "",
      scanType: this.currentScanType || "",
      startTime: new Date(),
      endTime: new Date(),
      findings: [],
      toolsUsed: [toolUsed],
      metadata: { rawOutput: results }
    };

    // Use AI to analyze results and extract vulnerabilities
    const analysisPrompt = `
Analyze the following security scan results and extract vulnerabilities:

Tool Used: ${toolUsed}
Target: ${this.currentTarget}
Raw Output:
${results}

Please identify any potential security vulnerabilities and format them as JSON with the following structure:
{
  "vulnerabilities": [
    {
      "title": "Vulnerability Title",
      "severity": "critical|high|medium|low|info",
      "description": "Detailed description",
      "evidence": ["evidence1", "evidence2"],
      "impact": "Impact description",
      "remediation": "How to fix",
      "references": ["url1", "url2"]
    }
  ]
}
`;

    try {
      // Use Gemini or OpenAI for analysis
      const analysis = await this.performAIAnalysis(analysisPrompt);
      
      // Parse the analysis and extract vulnerabilities
      let vulnerabilities = this.parseVulnerabilityAnalysis(analysis);
      
      // Enhance findings with vulnerability database
      vulnerabilities = VulnerabilityDatabase.enhanceFindings(vulnerabilities);
      
      scanResult.findings = vulnerabilities.map((vuln, index) => ({
        id: `${toolUsed}-${Date.now()}-${index}`,
        title: vuln.title,
        severity: vuln.severity,
        cvssScore: vuln.cvssScore,
        description: vuln.description,
        evidence: vuln.evidence,
        impact: vuln.impact,
        remediation: vuln.enhancedRemediation || vuln.remediation,
        references: vuln.references,
        tool: toolUsed,
        timestamp: new Date()
      }));
      
    } catch (error) {
      console.error("Failed to analyze scan results:", error);
    }

    return scanResult;
  }

  private async performAIAnalysis(prompt: string): Promise<string> {
    if (this.geminiClient) {
      try {
        const response = await this.geminiClient.generateContent({
          contents: [{
            role: 'user',
            parts: [{ text: prompt }]
          }]
        });
        
        return response.candidates[0]?.content?.parts[0]?.text || "";
      } catch (error) {
        console.warn("Gemini analysis failed, falling back to OpenAI:", error);
      }
    }
    
    // Fallback to OpenAI or return empty analysis
    return "";
  }

  private parseVulnerabilityAnalysis(analysis: string): any[] {
    try {
      // Try to extract JSON from the analysis
      const jsonMatch = analysis.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return parsed.vulnerabilities || [];
      }
    } catch (error) {
      console.warn("Failed to parse vulnerability analysis:", error);
    }
    
    return [];
  }

  async generateImprovementSuggestions(scanResults: ScanResult[]): Promise<string[]> {
    const improvements: string[] = [];
    
    if (scanResults.length === 0) {
      return ["No scan results available for analysis"];
    }
    
    // Analyze patterns in scan results
    const allFindings = scanResults.flatMap(result => result.findings);
    const toolsUsed = [...new Set(scanResults.flatMap(result => result.toolsUsed))];
    const categories = VulnerabilityAnalyzer.categorizeFindings(allFindings);
    
    // Suggest additional tools based on findings
    if (Object.keys(categories).includes("Injection Attacks") && !toolsUsed.includes("sqlmap")) {
      improvements.push("Consider using sqlmap for more comprehensive SQL injection testing");
    }
    
    if (Object.keys(categories).includes("Cross-Site Scripting") && !toolsUsed.includes("nuclei")) {
      improvements.push("Use nuclei with XSS templates for better XSS detection");
    }
    
    if (!toolsUsed.includes("subfinder") && this.currentTarget?.includes(".")) {
      improvements.push("Add subdomain enumeration with subfinder to expand attack surface");
    }
    
    // Suggest scanning improvements based on results
    if (allFindings.length === 0) {
      improvements.push("No vulnerabilities found - consider adjusting scan parameters or trying additional tools");
      improvements.push("Review target scope - ensure proper permissions and accessible endpoints");
    }
    
    if (allFindings.filter(f => f.severity === 'critical' || f.severity === 'high').length === 0) {
      improvements.push("No high-severity issues found - consider deeper testing with manual techniques");
    }
    
    return improvements;
  }

  async generateComprehensiveReport(sessionId: string): Promise<string> {
    const session = this.sessionManager.getSession(sessionId);
    if (!session) {
      return "Session not found";
    }
    
    let report = `# Bug Bounty Assessment Report\n\n`;
    report += `**Session ID**: ${session.id}\n`;
    report += `**Target**: ${session.target}\n`;
    report += `**Start Time**: ${session.startTime.toISOString()}\n`;
    report += `**Total Scans**: ${session.scans.length}\n\n`;
    
    // Add scan summaries
    session.scans.forEach((scan, index) => {
      report += `## Scan ${index + 1}: ${scan.scanType}\n`;
      report += VulnerabilityAnalyzer.generateDetailedReport(scan);
      report += `\n\n`;
    });
    
    // Add improvements
    if (session.improvements.length > 0) {
      report += `## Recommendations for Future Assessments\n\n`;
      session.improvements.forEach(improvement => {
        report += `- ${improvement}\n`;
      });
    }
    
    return report;
  }
}