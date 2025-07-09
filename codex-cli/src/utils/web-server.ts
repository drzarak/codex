import express from "express";
import { createServer } from "http";
import { WebSocketServer } from "ws";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { 
  getTargets, 
  addTarget, 
  updateTarget, 
  getTarget,
  getScansForTarget,
  addScan,
  updateScanStatus,
  getVulnerabilities,
  addVulnerability,
  type Target,
  type Scan,
  type Vulnerability
} from "./database.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export class BugBountyWebServer {
  private app = express();
  private server = createServer(this.app);
  private wss = new WebSocketServer({ server: this.server });
  private clients = new Set<any>();

  constructor(private port = 222) {
    this.setupMiddleware();
    this.setupRoutes();
    this.setupWebSocket();
  }

  private setupMiddleware(): void {
    this.app.use(express.json());
    this.app.use(express.static(join(__dirname, "../../../web")));
  }

  private setupRoutes(): void {
    // Serve main dashboard
    this.app.get("/", (req, res) => {
      res.send(this.getIndexHTML());
    });

    // API Routes
    
    // Targets
    this.app.get("/api/targets", (req, res) => {
      try {
        const targets = getTargets();
        res.json(targets);
      } catch (error) {
        res.status(500).json({ error: "Failed to fetch targets" });
      }
    });

    this.app.post("/api/targets", (req, res) => {
      try {
        const target: Target = req.body;
        const id = addTarget(target);
        this.broadcast({ type: "target_added", target: { ...target, id } });
        res.json({ id, message: "Target added successfully" });
      } catch (error) {
        res.status(500).json({ error: "Failed to add target" });
      }
    });

    this.app.put("/api/targets/:id", (req, res) => {
      try {
        const id = parseInt(req.params.id);
        const updates = req.body;
        updateTarget(id, updates);
        const target = getTarget(id);
        this.broadcast({ type: "target_updated", target });
        res.json({ message: "Target updated successfully" });
      } catch (error) {
        res.status(500).json({ error: "Failed to update target" });
      }
    });

    // Scans
    this.app.get("/api/targets/:id/scans", (req, res) => {
      try {
        const targetId = parseInt(req.params.id);
        const scans = getScansForTarget(targetId);
        res.json(scans);
      } catch (error) {
        res.status(500).json({ error: "Failed to fetch scans" });
      }
    });

    this.app.post("/api/targets/:id/scans", (req, res) => {
      try {
        const targetId = parseInt(req.params.id);
        const scan: Scan = { ...req.body, target_id: targetId };
        const scanId = addScan(scan);
        this.broadcast({ 
          type: "scan_added", 
          scan: { ...scan, id: scanId } 
        });
        res.json({ id: scanId, message: "Scan added successfully" });
      } catch (error) {
        res.status(500).json({ error: "Failed to add scan" });
      }
    });

    this.app.put("/api/scans/:id/status", (req, res) => {
      try {
        const id = parseInt(req.params.id);
        const { status, result_data } = req.body;
        updateScanStatus(id, status, result_data);
        this.broadcast({ 
          type: "scan_updated", 
          scan_id: id, 
          status, 
          result_data 
        });
        res.json({ message: "Scan status updated successfully" });
      } catch (error) {
        res.status(500).json({ error: "Failed to update scan status" });
      }
    });

    // Vulnerabilities
    this.app.get("/api/vulnerabilities", (req, res) => {
      try {
        const targetId = req.query.target_id ? parseInt(req.query.target_id as string) : undefined;
        const vulnerabilities = getVulnerabilities(targetId);
        res.json(vulnerabilities);
      } catch (error) {
        res.status(500).json({ error: "Failed to fetch vulnerabilities" });
      }
    });

    this.app.post("/api/vulnerabilities", (req, res) => {
      try {
        const vuln: Vulnerability = req.body;
        const id = addVulnerability(vuln);
        this.broadcast({ 
          type: "vulnerability_found", 
          vulnerability: { ...vuln, id } 
        });
        res.json({ id, message: "Vulnerability added successfully" });
      } catch (error) {
        res.status(500).json({ error: "Failed to add vulnerability" });
      }
    });

    // System status
    this.app.get("/api/status", (req, res) => {
      res.json({
        status: "running",
        timestamp: new Date().toISOString(),
        targets_count: getTargets().length,
        vulnerabilities_count: getVulnerabilities().length,
      });
    });
  }

  private setupWebSocket(): void {
    this.wss.on("connection", (ws) => {
      this.clients.add(ws);
      console.log("New WebSocket client connected");

      ws.on("close", () => {
        this.clients.delete(ws);
        console.log("WebSocket client disconnected");
      });

      ws.on("message", (data) => {
        try {
          const message = JSON.parse(data.toString());
          this.handleWebSocketMessage(ws, message);
        } catch (error) {
          console.error("Invalid WebSocket message:", error);
        }
      });

      // Send initial data
      ws.send(JSON.stringify({
        type: "init",
        targets: getTargets(),
        vulnerabilities: getVulnerabilities(),
      }));
    });
  }

  private handleWebSocketMessage(ws: any, message: any): void {
    switch (message.type) {
      case "ping":
        ws.send(JSON.stringify({ type: "pong" }));
        break;
      case "get_targets":
        ws.send(JSON.stringify({
          type: "targets",
          data: getTargets(),
        }));
        break;
      // Add more message handlers as needed
    }
  }

  private broadcast(message: any): void {
    const data = JSON.stringify(message);
    this.clients.forEach((client) => {
      if (client.readyState === 1) { // WebSocket.OPEN
        client.send(data);
      }
    });
  }

  private getIndexHTML(): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Bug Bounty Hunter</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #fff;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            padding: 30px;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }
        
        .header h1 {
            font-size: 3rem;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #ff6b6b, #feca57);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .header p {
            font-size: 1.2rem;
            opacity: 0.8;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 40px;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.1);
            padding: 25px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .card h2 {
            margin-bottom: 20px;
            color: #feca57;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .stat-card {
            background: rgba(0, 0, 0, 0.3);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            color: #ff6b6b;
        }
        
        .stat-label {
            opacity: 0.8;
            margin-top: 5px;
        }
        
        .btn {
            background: linear-gradient(45deg, #ff6b6b, #feca57);
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            color: white;
            font-size: 1rem;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .input-group {
            margin-bottom: 15px;
        }
        
        .input-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        
        .input-group input, .input-group textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid rgba(255, 255, 255, 0.3);
            border-radius: 5px;
            background: rgba(0, 0, 0, 0.2);
            color: white;
        }
        
        .input-group input::placeholder, .input-group textarea::placeholder {
            color: rgba(255, 255, 255, 0.6);
        }
        
        .log {
            background: rgba(0, 0, 0, 0.5);
            padding: 20px;
            border-radius: 10px;
            font-family: monospace;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .log-entry {
            margin-bottom: 10px;
            padding: 5px;
            border-left: 3px solid #feca57;
            padding-left: 10px;
        }
        
        .severity-critical { color: #e74c3c; }
        .severity-high { color: #f39c12; }
        .severity-medium { color: #f1c40f; }
        .severity-low { color: #2ecc71; }
        .severity-info { color: #3498db; }
        
        .hidden { display: none; }
        
        .tabs {
            display: flex;
            margin-bottom: 20px;
        }
        
        .tab {
            padding: 10px 20px;
            background: rgba(0, 0, 0, 0.3);
            border: none;
            color: white;
            cursor: pointer;
            border-radius: 5px 5px 0 0;
            margin-right: 5px;
        }
        
        .tab.active {
            background: rgba(255, 255, 255, 0.1);
        }
        
        .tab-content {
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 0 10px 10px 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AI Bug Bounty Hunter</h1>
            <p>Comprehensive AI-powered security testing platform</p>
        </div>
        
        <div class="stats" id="stats">
            <div class="stat-card">
                <div class="stat-number" id="targets-count">0</div>
                <div class="stat-label">Active Targets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="scans-count">0</div>
                <div class="stat-label">Running Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="vulns-count">0</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="critical-count">0</div>
                <div class="stat-label">Critical Issues</div>
            </div>
        </div>
        
        <div class="dashboard">
            <div class="card">
                <h2>Add New Target</h2>
                <form id="add-target-form">
                    <div class="input-group">
                        <label for="domain">Domain/URL:</label>
                        <input type="text" id="domain" name="domain" placeholder="example.com" required>
                    </div>
                    <div class="input-group">
                        <label for="description">Description:</label>
                        <textarea id="description" name="description" placeholder="Target description..."></textarea>
                    </div>
                    <div class="input-group">
                        <label for="api-keys">API Keys (JSON):</label>
                        <textarea id="api-keys" name="api_keys" placeholder='{"shodan": "key", "censys": "key"}'></textarea>
                    </div>
                    <button type="submit" class="btn">Add Target</button>
                </form>
            </div>
            
            <div class="card">
                <h2>Quick Actions</h2>
                <button class="btn" onclick="startFullScan()" style="margin: 10px;">Start Full Scan</button>
                <button class="btn" onclick="crawlTarget()" style="margin: 10px;">Web Crawl</button>
                <button class="btn" onclick="subdomainEnum()" style="margin: 10px;">Subdomain Enum</button>
                <button class="btn" onclick="portScan()" style="margin: 10px;">Port Scan</button>
                <button class="btn" onclick="vulnScan()" style="margin: 10px;">Vulnerability Scan</button>
            </div>
        </div>
        
        <div class="card">
            <div class="tabs">
                <button class="tab active" onclick="showTab('targets')">Targets</button>
                <button class="tab" onclick="showTab('scans')">Scans</button>
                <button class="tab" onclick="showTab('vulnerabilities')">Vulnerabilities</button>
                <button class="tab" onclick="showTab('logs')">Live Logs</button>
            </div>
            
            <div id="targets-tab" class="tab-content">
                <h2>Targets</h2>
                <div id="targets-list"></div>
            </div>
            
            <div id="scans-tab" class="tab-content hidden">
                <h2>Active Scans</h2>
                <div id="scans-list"></div>
            </div>
            
            <div id="vulnerabilities-tab" class="tab-content hidden">
                <h2>Discovered Vulnerabilities</h2>
                <div id="vulnerabilities-list"></div>
            </div>
            
            <div id="logs-tab" class="tab-content hidden">
                <h2>Live Activity Logs</h2>
                <div class="log" id="activity-log"></div>
            </div>
        </div>
    </div>

    <script>
        let ws;
        let targets = [];
        let vulnerabilities = [];
        let scans = [];

        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(\`\${protocol}//\${window.location.host}\`);
            
            ws.onopen = function() {
                console.log('Connected to WebSocket');
                addLogEntry('Connected to AI Bug Bounty Hunter');
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                handleWebSocketMessage(data);
            };
            
            ws.onclose = function() {
                console.log('WebSocket connection closed');
                addLogEntry('Connection lost - attempting to reconnect...');
                setTimeout(connectWebSocket, 5000);
            };
        }

        function handleWebSocketMessage(data) {
            switch(data.type) {
                case 'init':
                    targets = data.targets || [];
                    vulnerabilities = data.vulnerabilities || [];
                    updateUI();
                    break;
                case 'target_added':
                    targets.push(data.target);
                    updateUI();
                    addLogEntry(\`New target added: \${data.target.domain}\`);
                    break;
                case 'vulnerability_found':
                    vulnerabilities.push(data.vulnerability);
                    updateUI();
                    addLogEntry(\`🔍 \${data.vulnerability.severity.toUpperCase()} vulnerability found: \${data.vulnerability.title}\`, data.vulnerability.severity);
                    break;
                case 'scan_added':
                    addLogEntry(\`🚀 Started \${data.scan.scan_type} scan\`);
                    break;
                case 'scan_updated':
                    addLogEntry(\`📊 Scan \${data.scan_id} status: \${data.status}\`);
                    break;
            }
        }

        function updateUI() {
            updateStats();
            updateTargetsList();
            updateVulnerabilitiesList();
        }

        function updateStats() {
            document.getElementById('targets-count').textContent = targets.length;
            document.getElementById('vulns-count').textContent = vulnerabilities.length;
            
            const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical').length;
            document.getElementById('critical-count').textContent = criticalVulns;
        }

        function updateTargetsList() {
            const container = document.getElementById('targets-list');
            container.innerHTML = targets.map(target => \`
                <div class="card" style="margin-bottom: 15px;">
                    <h3>\${target.domain}</h3>
                    <p>\${target.description || 'No description'}</p>
                    <p><strong>Status:</strong> \${target.status}</p>
                    <p><strong>Added:</strong> \${new Date(target.created_at).toLocaleString()}</p>
                </div>
            \`).join('');
        }

        function updateVulnerabilitiesList() {
            const container = document.getElementById('vulnerabilities-list');
            container.innerHTML = vulnerabilities.map(vuln => \`
                <div class="card severity-\${vuln.severity}" style="margin-bottom: 15px;">
                    <h3>\${vuln.title}</h3>
                    <p><strong>Severity:</strong> <span class="severity-\${vuln.severity}">\${vuln.severity.toUpperCase()}</span></p>
                    <p><strong>Type:</strong> \${vuln.vuln_type}</p>
                    <p><strong>URL:</strong> \${vuln.url || 'N/A'}</p>
                    <p>\${vuln.description || 'No description'}</p>
                    \${vuln.cwe_id ? \`<p><strong>CWE:</strong> \${vuln.cwe_id}</p>\` : ''}
                    <p><strong>Discovered:</strong> \${new Date(vuln.discovered_at).toLocaleString()}</p>
                </div>
            \`).join('');
        }

        function addLogEntry(message, severity = 'info') {
            const logContainer = document.getElementById('activity-log');
            const entry = document.createElement('div');
            entry.className = \`log-entry severity-\${severity}\`;
            entry.innerHTML = \`[\${new Date().toLocaleTimeString()}] \${message}\`;
            logContainer.appendChild(entry);
            logContainer.scrollTop = logContainer.scrollHeight;
        }

        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.add('hidden');
            });
            
            // Remove active class from all tab buttons
            document.querySelectorAll('.tab').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(\`\${tabName}-tab\`).classList.remove('hidden');
            event.target.classList.add('active');
        }

        // Form submission
        document.getElementById('add-target-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const targetData = {
                domain: formData.get('domain'),
                description: formData.get('description'),
                api_keys: formData.get('api_keys') ? JSON.parse(formData.get('api_keys')) : {}
            };
            
            try {
                const response = await fetch('/api/targets', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(targetData)
                });
                
                if (response.ok) {
                    e.target.reset();
                    addLogEntry(\`Target \${targetData.domain} added successfully\`);
                } else {
                    addLogEntry('Failed to add target', 'critical');
                }
            } catch (error) {
                addLogEntry(\`Error adding target: \${error.message}\`, 'critical');
            }
        });

        // Quick action functions
        async function startFullScan() {
            if (targets.length === 0) {
                addLogEntry('No targets available for scanning', 'medium');
                return;
            }
            addLogEntry('🚀 Starting full comprehensive scan on all targets...');
            // Implementation would trigger actual scans
        }

        function crawlTarget() {
            addLogEntry('🕷️ Web crawling initiated...');
        }

        function subdomainEnum() {
            addLogEntry('🔍 Subdomain enumeration started...');
        }

        function portScan() {
            addLogEntry('🔌 Port scanning initiated...');
        }

        function vulnScan() {
            addLogEntry('🛡️ Vulnerability scanning started...');
        }

        // Initialize
        connectWebSocket();
        
        // Auto-refresh data every 30 seconds
        setInterval(async () => {
            try {
                const response = await fetch('/api/targets');
                if (response.ok) {
                    targets = await response.json();
                    const vulnResponse = await fetch('/api/vulnerabilities');
                    if (vulnResponse.ok) {
                        vulnerabilities = await vulnResponse.json();
                    }
                    updateUI();
                }
            } catch (error) {
                console.error('Failed to refresh data:', error);
            }
        }, 30000);
    </script>
</body>
</html>
    `;
  }

  public start(): Promise<void> {
    return new Promise((resolve) => {
      this.server.listen(this.port, () => {
        console.log(`🚀 AI Bug Bounty Hunter web interface running on http://localhost:${this.port}`);
        resolve();
      });
    });
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      this.server.close(() => {
        console.log("Web server stopped");
        resolve();
      });
    });
  }

  public getPort(): number {
    return this.port;
  }
}