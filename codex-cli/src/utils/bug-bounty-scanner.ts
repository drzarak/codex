import { spawn } from "child_process";
import { writeFileSync, readFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { CONFIG_DIR } from "./config.js";
import { 
  addScan, 
  updateScanStatus, 
  addVulnerability, 
  getTarget,
  type Target,
  type Scan,
  type Vulnerability 
} from "./database.js";

const TOOLS_DIR = join(CONFIG_DIR, "tools");
const RESULTS_DIR = join(CONFIG_DIR, "results");

// Ensure directories exist
[TOOLS_DIR, RESULTS_DIR].forEach(dir => {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
});

export class BugBountyScanner {
  private runningScans = new Map<number, any>();

  constructor() {
    this.ensureToolsInstalled();
  }

  private async ensureToolsInstalled(): Promise<void> {
    console.log("🔧 Checking and installing bug bounty tools...");
    
    const tools = [
      {
        name: "amass",
        check: "amass --help",
        install: "go install -v github.com/owasp-amass/amass/v4/...@master"
      },
      {
        name: "nuclei",
        check: "nuclei --help",
        install: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
      },
      {
        name: "subfinder",
        check: "subfinder --help", 
        install: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
      },
      {
        name: "httpx",
        check: "httpx --help",
        install: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
      },
      {
        name: "nmap",
        check: "nmap --help",
        install: "apt-get install -y nmap"
      },
      {
        name: "sqlmap",
        check: "sqlmap --help",
        install: "apt-get install -y sqlmap"
      }
    ];

    for (const tool of tools) {
      try {
        await this.runCommand(tool.check.split(" "), { timeout: 5000 });
        console.log(`✅ ${tool.name} is available`);
      } catch {
        console.log(`📦 Installing ${tool.name}...`);
        try {
          await this.runCommand(tool.install.split(" "), { timeout: 300000 });
          console.log(`✅ ${tool.name} installed successfully`);
        } catch (error) {
          console.log(`❌ Failed to install ${tool.name}:`, error);
        }
      }
    }
  }

  private runCommand(cmd: string[], options: { timeout?: number; cwd?: string } = {}): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    return new Promise((resolve, reject) => {
      const child = spawn(cmd[0], cmd.slice(1), {
        cwd: options.cwd || process.cwd(),
        stdio: ["ignore", "pipe", "pipe"]
      });

      let stdout = "";
      let stderr = "";

      child.stdout?.on("data", (data) => {
        stdout += data.toString();
      });

      child.stderr?.on("data", (data) => {
        stderr += data.toString();
      });

      const timeout = options.timeout ? setTimeout(() => {
        child.kill("SIGTERM");
        reject(new Error("Command timeout"));
      }, options.timeout) : null;

      child.on("exit", (code) => {
        if (timeout) clearTimeout(timeout);
        resolve({
          stdout,
          stderr,
          exitCode: code || 0
        });
      });

      child.on("error", (error) => {
        if (timeout) clearTimeout(timeout);
        reject(error);
      });
    });
  }

  public async startComprehensiveScan(targetId: number): Promise<void> {
    const target = getTarget(targetId);
    if (!target) {
      throw new Error(`Target ${targetId} not found`);
    }

    console.log(`🚀 Starting comprehensive scan for ${target.domain}`);

    // Chain of scans: subdomain -> port -> web crawl -> vulnerability scan
    await this.subdomainEnumeration(targetId);
    await this.portScan(targetId);
    await this.webCrawl(targetId);
    await this.vulnerabilityScan(targetId);
  }

  public async subdomainEnumeration(targetId: number): Promise<void> {
    const target = getTarget(targetId);
    if (!target) return;

    const scanId = addScan({
      target_id: targetId,
      scan_type: "subdomain_enum",
      command: `subfinder -d ${target.domain} && amass enum -d ${target.domain}`
    });

    updateScanStatus(scanId, "running");

    try {
      const resultFile = join(RESULTS_DIR, `subdomains_${targetId}_${Date.now()}.txt`);
      
      // Run Subfinder
      console.log(`🔍 Running Subfinder on ${target.domain}`);
      const subfinderResult = await this.runCommand([
        "subfinder", "-d", target.domain, "-o", resultFile
      ], { timeout: 300000 });

      // Run Amass (if available)
      try {
        console.log(`🔍 Running Amass on ${target.domain}`);
        const amassResult = await this.runCommand([
          "amass", "enum", "-d", target.domain, "-o", resultFile + ".amass"
        ], { timeout: 600000 });
        
        // Combine results
        if (existsSync(resultFile + ".amass")) {
          const amassSubdomains = readFileSync(resultFile + ".amass", "utf8");
          writeFileSync(resultFile, `${readFileSync(resultFile, "utf8")}\n${amassSubdomains}`);
        }
      } catch (error) {
        console.log("Amass not available or failed, continuing with Subfinder results");
      }

      // Parse and store results
      const subdomains = existsSync(resultFile) 
        ? readFileSync(resultFile, "utf8").split("\n").filter(Boolean)
        : [];

      updateScanStatus(scanId, "completed", {
        subdomains_found: subdomains.length,
        subdomains: subdomains,
        result_file: resultFile
      });

      console.log(`✅ Found ${subdomains.length} subdomains for ${target.domain}`);

    } catch (error) {
      updateScanStatus(scanId, "failed", { error: String(error) });
      console.error(`❌ Subdomain enumeration failed for ${target.domain}:`, error);
    }
  }

  public async portScan(targetId: number): Promise<void> {
    const target = getTarget(targetId);
    if (!target) return;

    const scanId = addScan({
      target_id: targetId,
      scan_type: "port_scan", 
      command: `nmap -sS -sV -O -T4 ${target.domain}`
    });

    updateScanStatus(scanId, "running");

    try {
      console.log(`🔌 Running Nmap port scan on ${target.domain}`);
      
      const nmapResult = await this.runCommand([
        "nmap", "-sS", "-sV", "-O", "-T4", 
        "--open", "-oN", join(RESULTS_DIR, `portscan_${targetId}_${Date.now()}.txt`),
        target.domain
      ], { timeout: 1800000 }); // 30 minutes

      // Parse Nmap output for open ports
      const openPorts = this.parseNmapOutput(nmapResult.stdout);

      updateScanStatus(scanId, "completed", {
        open_ports: openPorts,
        nmap_output: nmapResult.stdout
      });

      // Check for potential vulnerabilities based on open ports
      this.analyzeOpenPorts(targetId, openPorts);

      console.log(`✅ Port scan completed for ${target.domain}, found ${openPorts.length} open ports`);

    } catch (error) {
      updateScanStatus(scanId, "failed", { error: String(error) });
      console.error(`❌ Port scan failed for ${target.domain}:`, error);
    }
  }

  public async webCrawl(targetId: number): Promise<void> {
    const target = getTarget(targetId);
    if (!target) return;

    const scanId = addScan({
      target_id: targetId,
      scan_type: "web_crawl",
      command: `httpx -l subdomains.txt -status-code -title -tech-detect`
    });

    updateScanStatus(scanId, "running");

    try {
      console.log(`🕷️ Running web crawl on ${target.domain}`);

      // First, run httpx to find live hosts
      const httpxResult = await this.runCommand([
        "httpx", "-u", target.domain, "-status-code", "-title", 
        "-tech-detect", "-json", "-o", join(RESULTS_DIR, `httpx_${targetId}_${Date.now()}.json`)
      ], { timeout: 600000 });

      const resultData = {
        httpx_output: httpxResult.stdout,
        discovered_technologies: this.parseHttpxOutput(httpxResult.stdout)
      };

      updateScanStatus(scanId, "completed", resultData);

      console.log(`✅ Web crawl completed for ${target.domain}`);

    } catch (error) {
      updateScanStatus(scanId, "failed", { error: String(error) });
      console.error(`❌ Web crawl failed for ${target.domain}:`, error);
    }
  }

  public async vulnerabilityScan(targetId: number): Promise<void> {
    const target = getTarget(targetId);
    if (!target) return;

    const scanId = addScan({
      target_id: targetId,
      scan_type: "vulnerability_scan",
      command: `nuclei -u ${target.domain} -es info`
    });

    updateScanStatus(scanId, "running");

    try {
      console.log(`🛡️ Running Nuclei vulnerability scan on ${target.domain}`);

      const nucleiResult = await this.runCommand([
        "nuclei", "-u", target.domain, "-es", "info", "-json",
        "-o", join(RESULTS_DIR, `nuclei_${targetId}_${Date.now()}.json`)
      ], { timeout: 1800000 }); // 30 minutes

      // Parse Nuclei output and store vulnerabilities
      const vulnerabilities = this.parseNucleiOutput(nucleiResult.stdout, targetId);

      updateScanStatus(scanId, "completed", {
        vulnerabilities_found: vulnerabilities.length,
        nuclei_output: nucleiResult.stdout
      });

      console.log(`✅ Vulnerability scan completed for ${target.domain}, found ${vulnerabilities.length} issues`);

    } catch (error) {
      updateScanStatus(scanId, "failed", { error: String(error) });
      console.error(`❌ Vulnerability scan failed for ${target.domain}:`, error);
    }
  }

  public async sqlInjectionTest(targetId: number, url: string): Promise<void> {
    const scanId = addScan({
      target_id: targetId,
      scan_type: "sql_injection",
      command: `sqlmap -u "${url}" --batch --risk=3 --level=5`
    });

    updateScanStatus(scanId, "running");

    try {
      console.log(`💉 Running SQLMap on ${url}`);

      const sqlmapResult = await this.runCommand([
        "sqlmap", "-u", url, "--batch", "--risk=3", "--level=5",
        "--output-dir", join(RESULTS_DIR, `sqlmap_${targetId}_${Date.now()}`)
      ], { timeout: 1800000 });

      // Parse SQLMap output for vulnerabilities
      if (sqlmapResult.stdout.includes("identified the following injection point")) {
        addVulnerability({
          target_id: targetId,
          scan_id: scanId,
          vuln_type: "sql_injection",
          severity: "high",
          title: "SQL Injection Vulnerability",
          description: "SQLMap identified potential SQL injection vulnerability",
          url: url,
          proof_of_concept: sqlmapResult.stdout,
          cwe_id: "CWE-89"
        });
      }

      updateScanStatus(scanId, "completed", {
        sqlmap_output: sqlmapResult.stdout
      });

    } catch (error) {
      updateScanStatus(scanId, "failed", { error: String(error) });
      console.error(`❌ SQL injection test failed for ${url}:`, error);
    }
  }

  private parseNmapOutput(output: string): Array<{ port: number; service: string; version?: string }> {
    const ports: Array<{ port: number; service: string; version?: string }> = [];
    const lines = output.split("\n");
    
    for (const line of lines) {
      const portMatch = line.match(/^(\d+)\/tcp\s+open\s+(\w+)(?:\s+(.+))?/);
      if (portMatch) {
        ports.push({
          port: parseInt(portMatch[1]),
          service: portMatch[2],
          version: portMatch[3]?.trim()
        });
      }
    }
    
    return ports;
  }

  private parseHttpxOutput(output: string): string[] {
    const technologies: string[] = [];
    const lines = output.split("\n");
    
    for (const line of lines) {
      try {
        const json = JSON.parse(line);
        if (json.tech && Array.isArray(json.tech)) {
          technologies.push(...json.tech);
        }
      } catch {
        // Skip invalid JSON lines
      }
    }
    
    return [...new Set(technologies)]; // Remove duplicates
  }

  private parseNucleiOutput(output: string, targetId: number): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const lines = output.split("\n");
    
    for (const line of lines) {
      try {
        const json = JSON.parse(line);
        if (json.info) {
          const vuln: Vulnerability = {
            target_id: targetId,
            vuln_type: json.info.classification?.cwe_id || json.type || "unknown",
            severity: this.mapNucleiSeverity(json.info.severity),
            title: json.info.name,
            description: json.info.description,
            url: json.matched_at,
            cwe_id: json.info.classification?.cwe_id,
            proof_of_concept: JSON.stringify(json, null, 2)
          };
          
          vulnerabilities.push(vuln);
          addVulnerability(vuln);
        }
      } catch {
        // Skip invalid JSON lines
      }
    }
    
    return vulnerabilities;
  }

  private mapNucleiSeverity(severity: string): "critical" | "high" | "medium" | "low" | "info" {
    const severityMap: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
      "critical": "critical",
      "high": "high", 
      "medium": "medium",
      "low": "low",
      "info": "info",
      "unknown": "info"
    };
    
    return severityMap[severity?.toLowerCase()] || "info";
  }

  private analyzeOpenPorts(targetId: number, openPorts: Array<{ port: number; service: string; version?: string }>): void {
    for (const portInfo of openPorts) {
      // Check for potentially dangerous services
      if (this.isDangerousService(portInfo)) {
        addVulnerability({
          target_id: targetId,
          vuln_type: "exposed_service",
          severity: this.getServiceSeverity(portInfo.service),
          title: `Exposed ${portInfo.service} Service`,
          description: `Potentially dangerous service ${portInfo.service} detected on port ${portInfo.port}`,
          url: `port:${portInfo.port}`,
          proof_of_concept: `Service: ${portInfo.service}, Version: ${portInfo.version || "Unknown"}`,
          cwe_id: "CWE-200"
        });
      }
    }
  }

  private isDangerousService(portInfo: { port: number; service: string; version?: string }): boolean {
    const dangerousServices = [
      "telnet", "ftp", "ssh", "rlogin", "mysql", "postgresql", 
      "redis", "mongodb", "elasticsearch", "rdp", "vnc", "smb"
    ];
    
    return dangerousServices.includes(portInfo.service.toLowerCase()) ||
           portInfo.port === 22 || // SSH
           portInfo.port === 3389 || // RDP
           portInfo.port === 5900; // VNC
  }

  private getServiceSeverity(service: string): "critical" | "high" | "medium" | "low" | "info" {
    const criticalServices = ["telnet", "ftp", "rlogin"];
    const highServices = ["ssh", "rdp", "vnc", "mysql", "postgresql"];
    
    if (criticalServices.includes(service.toLowerCase())) return "critical";
    if (highServices.includes(service.toLowerCase())) return "high";
    return "medium";
  }

  public async stopScan(scanId: number): Promise<void> {
    const process = this.runningScans.get(scanId);
    if (process) {
      process.kill("SIGTERM");
      this.runningScans.delete(scanId);
      updateScanStatus(scanId, "failed", { error: "Scan stopped by user" });
    }
  }

  public getRunningScans(): number[] {
    return Array.from(this.runningScans.keys());
  }
}