import { chromium, Browser, Page, BrowserContext } from "playwright";
import { writeFileSync, readFileSync, existsSync } from "fs";
import { join } from "path";
import { CONFIG_DIR } from "./config.js";
import { updateTarget, getTarget } from "./database.js";

const BROWSER_DATA_DIR = join(CONFIG_DIR, "browser_data");
const PROXY_LOG_FILE = join(CONFIG_DIR, "proxy_traffic.json");

export interface ProxyLogEntry {
  timestamp: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  response_status?: number;
  response_headers?: Record<string, string>;
  response_body?: string;
}

export class BrowserAutomationService {
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;
  private proxyLogs: ProxyLogEntry[] = [];

  constructor() {
    this.ensureBrowserDataDir();
    this.loadExistingProxyLogs();
  }

  private ensureBrowserDataDir(): void {
    if (!existsSync(BROWSER_DATA_DIR)) {
      require("fs").mkdirSync(BROWSER_DATA_DIR, { recursive: true });
    }
  }

  private loadExistingProxyLogs(): void {
    if (existsSync(PROXY_LOG_FILE)) {
      try {
        const data = readFileSync(PROXY_LOG_FILE, "utf8");
        this.proxyLogs = JSON.parse(data);
      } catch (error) {
        console.error("Failed to load existing proxy logs:", error);
        this.proxyLogs = [];
      }
    }
  }

  private saveProxyLogs(): void {
    try {
      writeFileSync(PROXY_LOG_FILE, JSON.stringify(this.proxyLogs, null, 2));
    } catch (error) {
      console.error("Failed to save proxy logs:", error);
    }
  }

  public async initializeBrowser(): Promise<void> {
    if (this.browser) {
      await this.closeBrowser();
    }

    console.log("🌐 Initializing browser for authentication and proxy logging...");

    this.browser = await chromium.launch({
      headless: false, // Keep visible for user interaction
      args: [
        "--disable-web-security",
        "--disable-features=VizDisplayCompositor",
        "--ignore-certificate-errors",
        "--proxy-server=http://localhost:8080"
      ]
    });

    this.context = await this.browser.newContext({
      userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 BugBountyHunter/1.0",
      viewport: { width: 1920, height: 1080 },
      acceptDownloads: true,
      recordVideo: {
        dir: join(BROWSER_DATA_DIR, "recordings"),
        size: { width: 1920, height: 1080 }
      }
    });

    // Set up request/response interception for proxy logging
    await this.setupProxyLogging();
  }

  private async setupProxyLogging(): Promise<void> {
    if (!this.context) return;

    // Intercept requests
    await this.context.route("**/*", async (route) => {
      const request = route.request();
      
      const logEntry: ProxyLogEntry = {
        timestamp: new Date().toISOString(),
        method: request.method(),
        url: request.url(),
        headers: request.headers(),
        body: request.postData() || undefined
      };

      // Continue with the request and capture response
      const response = await route.continue();
      
      // Note: Due to Playwright limitations, we can't easily capture response body
      // For full proxy functionality, consider integrating with mitmproxy or similar
      
      this.proxyLogs.push(logEntry);
      this.saveProxyLogs();
      
      console.log(`📡 Logged request: ${request.method()} ${request.url()}`);
    });
  }

  public async navigateAndLogin(targetId: number, loginUrl: string): Promise<{ success: boolean; cookies: any[]; error?: string }> {
    if (!this.context) {
      await this.initializeBrowser();
    }

    try {
      const page = await this.context!.newPage();
      
      console.log(`🔐 Navigating to login page: ${loginUrl}`);
      await page.goto(loginUrl, { waitUntil: "networkidle" });

      // Take screenshot of login page
      await page.screenshot({ 
        path: join(BROWSER_DATA_DIR, `login_${targetId}_${Date.now()}.png`),
        fullPage: true
      });

      console.log("🖱️  Browser is ready for manual login. Please log in manually...");
      console.log("Press Enter in this terminal once you have completed login.");

      // Wait for user to complete login manually
      await this.waitForUserInput();

      // Extract cookies after login
      const cookies = await this.context!.cookies();
      
      // Take screenshot after login
      await page.screenshot({ 
        path: join(BROWSER_DATA_DIR, `post_login_${targetId}_${Date.now()}.png`),
        fullPage: true
      });

      // Save cookies to target
      const target = getTarget(targetId);
      if (target) {
        const authCookies = cookies.reduce((acc, cookie) => {
          acc[cookie.name] = cookie.value;
          return acc;
        }, {} as Record<string, string>);

        updateTarget(targetId, { auth_cookies: authCookies });
        console.log(`✅ Saved ${cookies.length} authentication cookies for target`);
      }

      await page.close();

      return { success: true, cookies };

    } catch (error) {
      console.error("❌ Login automation failed:", error);
      return { success: false, cookies: [], error: String(error) };
    }
  }

  private waitForUserInput(): Promise<void> {
    return new Promise((resolve) => {
      process.stdin.once("data", () => {
        resolve();
      });
    });
  }

  public async crawlWebApp(targetId: number, startUrl: string, maxDepth = 3): Promise<{ urls: string[]; apis: any[]; forms: any[] }> {
    if (!this.context) {
      await this.initializeBrowser();
    }

    const crawledUrls = new Set<string>();
    const discoveredApis: any[] = [];
    const discoveredForms: any[] = [];
    const urlsToVisit = [{ url: startUrl, depth: 0 }];

    console.log(`🕷️ Starting web app crawl from ${startUrl}`);

    try {
      while (urlsToVisit.length > 0) {
        const { url, depth } = urlsToVisit.shift()!;
        
        if (crawledUrls.has(url) || depth > maxDepth) {
          continue;
        }

        crawledUrls.add(url);
        console.log(`📖 Crawling: ${url} (depth: ${depth})`);

        const page = await this.context!.newPage();
        
        try {
          await page.goto(url, { waitUntil: "networkidle", timeout: 30000 });

          // Extract all links for further crawling
          const links = await page.$$eval("a[href]", (elements) =>
            elements.map((el) => (el as HTMLAnchorElement).href)
          );

          // Add new links to crawl queue
          for (const link of links) {
            if (this.isSameDomain(link, startUrl) && !crawledUrls.has(link)) {
              urlsToVisit.push({ url: link, depth: depth + 1 });
            }
          }

          // Extract forms for potential testing
          const forms = await page.$$eval("form", (elements) =>
            elements.map((form) => {
              const inputs = Array.from(form.querySelectorAll("input, textarea, select")).map((input) => ({
                type: input.getAttribute("type") || "text",
                name: input.getAttribute("name") || "",
                id: input.getAttribute("id") || "",
                required: input.hasAttribute("required")
              }));

              return {
                action: form.getAttribute("action") || "",
                method: form.getAttribute("method") || "GET",
                inputs: inputs
              };
            })
          );

          discoveredForms.push(...forms.map(form => ({ ...form, url })));

          // Look for API endpoints in JavaScript
          const apiEndpoints = await page.evaluate(() => {
            const endpoints: string[] = [];
            const scripts = Array.from(document.querySelectorAll("script"));
            
            for (const script of scripts) {
              const content = script.innerHTML;
              // Look for common API patterns
              const apiMatches = content.match(/['"]\/api\/[^'"]*['"]/g) || [];
              const fetchMatches = content.match(/fetch\s*\(\s*['"][^'"]*['"]/g) || [];
              
              endpoints.push(...apiMatches.map(m => m.slice(1, -1)));
              endpoints.push(...fetchMatches.map(m => m.match(/['"]([^'"]*)['"]/)?.[1] || ""));
            }
            
            return endpoints.filter(Boolean);
          });

          discoveredApis.push(...apiEndpoints.map(endpoint => ({ endpoint, discoveredAt: url })));

          await page.close();

        } catch (error) {
          console.error(`❌ Failed to crawl ${url}:`, error);
          await page.close();
        }
      }

      console.log(`✅ Crawl completed: ${crawledUrls.size} URLs, ${discoveredApis.length} APIs, ${discoveredForms.length} forms`);

      return {
        urls: Array.from(crawledUrls),
        apis: discoveredApis,
        forms: discoveredForms
      };

    } catch (error) {
      console.error("❌ Web app crawl failed:", error);
      return { urls: [], apis: [], forms: [] };
    }
  }

  private isSameDomain(url: string, baseUrl: string): boolean {
    try {
      const urlObj = new URL(url);
      const baseUrlObj = new URL(baseUrl);
      return urlObj.hostname === baseUrlObj.hostname;
    } catch {
      return false;
    }
  }

  public async testForIDOR(targetId: number, urls: string[]): Promise<void> {
    console.log(`🔍 Testing for IDOR vulnerabilities on ${urls.length} URLs`);
    
    if (!this.context) {
      await this.initializeBrowser();
    }

    for (const url of urls) {
      if (this.hasNumericId(url)) {
        await this.testIDORVariations(targetId, url);
      }
    }
  }

  private hasNumericId(url: string): boolean {
    return /\/\d+(?:\/|$|\?)/.test(url);
  }

  private async testIDORVariations(targetId: number, originalUrl: string): Promise<void> {
    const page = await this.context!.newPage();
    
    try {
      // Get original response
      const originalResponse = await page.goto(originalUrl);
      const originalContent = await page.content();
      const originalStatus = originalResponse?.status();

      // Test with different ID values
      const testIds = ["1", "2", "999", "0", "-1", "admin", "test"];
      
      for (const testId of testIds) {
        const modifiedUrl = originalUrl.replace(/\/\d+/, `/${testId}`);
        
        if (modifiedUrl !== originalUrl) {
          try {
            const response = await page.goto(modifiedUrl);
            const content = await page.content();
            const status = response?.status();

            // Potential IDOR if we get successful response with different content
            if (status === 200 && content !== originalContent && content.length > 100) {
              const { addVulnerability } = await import("./database.js");
              addVulnerability({
                target_id: targetId,
                vuln_type: "idor",
                severity: "high",
                title: "Potential IDOR Vulnerability",
                description: `Access to different resource by changing ID parameter`,
                url: modifiedUrl,
                proof_of_concept: `Original URL: ${originalUrl}\nModified URL: ${modifiedUrl}\nBoth returned different valid content`,
                cwe_id: "CWE-639"
              });

              console.log(`🚨 Potential IDOR found: ${modifiedUrl}`);
            }
          } catch (error) {
            // Ignore navigation errors
          }
        }
      }

    } catch (error) {
      console.error(`❌ IDOR testing failed for ${originalUrl}:`, error);
    } finally {
      await page.close();
    }
  }

  public getProxyLogs(): ProxyLogEntry[] {
    return this.proxyLogs;
  }

  public clearProxyLogs(): void {
    this.proxyLogs = [];
    this.saveProxyLogs();
  }

  public async closeBrowser(): Promise<void> {
    if (this.context) {
      await this.context.close();
      this.context = null;
    }
    
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
    
    console.log("🔒 Browser closed");
  }

  public async takeScreenshot(targetId: number, url: string): Promise<string> {
    if (!this.context) {
      await this.initializeBrowser();
    }

    const page = await this.context!.newPage();
    const screenshotPath = join(BROWSER_DATA_DIR, `screenshot_${targetId}_${Date.now()}.png`);
    
    try {
      await page.goto(url, { waitUntil: "networkidle" });
      await page.screenshot({ path: screenshotPath, fullPage: true });
      await page.close();
      
      console.log(`📸 Screenshot saved: ${screenshotPath}`);
      return screenshotPath;
    } catch (error) {
      await page.close();
      throw error;
    }
  }

  public async extractAPIsFromTraffic(): Promise<Array<{ method: string; endpoint: string; parameters: any }>> {
    const apis: Array<{ method: string; endpoint: string; parameters: any }> = [];
    
    for (const log of this.proxyLogs) {
      if (this.looksLikeAPI(log.url)) {
        const urlObj = new URL(log.url);
        
        apis.push({
          method: log.method,
          endpoint: urlObj.pathname,
          parameters: {
            query: Object.fromEntries(urlObj.searchParams),
            body: log.body ? this.tryParseJSON(log.body) : null,
            headers: log.headers
          }
        });
      }
    }

    // Remove duplicates
    const uniqueApis = apis.filter((api, index, self) => 
      index === self.findIndex(a => a.method === api.method && a.endpoint === api.endpoint)
    );

    return uniqueApis;
  }

  private looksLikeAPI(url: string): boolean {
    const apiIndicators = ["/api/", "/v1/", "/v2/", ".json", "/rest/", "/graphql"];
    return apiIndicators.some(indicator => url.includes(indicator)) ||
           url.match(/\/[a-zA-Z]+\/\d+/) !== null; // REST-like patterns
  }

  private tryParseJSON(str: string): any {
    try {
      return JSON.parse(str);
    } catch {
      return str;
    }
  }
}