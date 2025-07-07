# Codex Bug Bounty Mode

This document provides examples and workflows for using Codex in bug bounty/pentesting mode.

## Getting Started

### Basic Usage

```bash
# Web application assessment
codex --bounty example.com "web application scan"

# Network enumeration
codex --bounty 192.168.1.0/24 "network enumeration"

# Subdomain discovery
codex --bounty example.com "subdomain discovery"

# Using Google Gemini instead of OpenAI
codex --bounty --ai-provider gemini target.com "comprehensive scan"
```

### API Key Setup

For OpenAI (default):
```bash
export OPENAI_API_KEY="your-openai-api-key"
```

For Google Gemini:
```bash
export GEMINI_API_KEY="your-gemini-api-key"
```

## Workflow Examples

### 1. Web Application Security Assessment

```bash
codex --bounty webapp.example.com "web application security assessment"
```

The AI agent will:
1. Install required tools (gobuster, nikto, sqlmap, etc.)
2. Perform initial reconnaissance
3. Directory enumeration
4. Vulnerability scanning
5. SQL injection testing
6. Generate comprehensive report

### 2. Network Penetration Testing

```bash
codex --bounty 10.0.0.0/24 "network penetration test"
```

The AI agent will:
1. Install network scanning tools (nmap, masscan)
2. Host discovery
3. Port scanning
4. Service enumeration
5. Vulnerability identification
6. Report generation with remediation

### 3. Subdomain Enumeration and Analysis

```bash
codex --bounty bigcorp.com "subdomain enumeration and security analysis"
```

The AI agent will:
1. Install subdomain discovery tools (subfinder, amass)
2. Discover subdomains
3. Probe for live hosts
4. Technology detection
5. Vulnerability scanning of discovered assets

## Self-Improvement Features

The AI agent continuously improves by:

- **Learning from scan results**: Analyzes findings to improve future scans
- **Tool optimization**: Adjusts parameters based on target responses
- **False positive reduction**: Learns to filter out noise
- **Coverage improvement**: Identifies gaps in testing methodology
- **Technique evolution**: Adapts scanning strategies based on target type

## Ethical Guidelines

⚠️ **Important**: Only use this tool on systems you own or have explicit permission to test.

1. **Get Permission**: Always obtain written authorization before testing
2. **Scope Limits**: Stay within defined scope boundaries
3. **Rate Limiting**: Avoid overwhelming target systems
4. **Responsible Disclosure**: Report findings through proper channels
5. **Documentation**: Keep detailed logs of all activities

## Security Tools Integrated

- **nmap**: Network discovery and security auditing
- **masscan**: High-speed port scanner
- **gobuster**: Directory/file enumeration
- **sqlmap**: SQL injection testing
- **nikto**: Web vulnerability scanner
- **nuclei**: Vulnerability scanner with templates
- **subfinder**: Subdomain discovery
- **amass**: Attack surface mapping
- **httpx**: HTTP toolkit
- **ffuf**: Fast web fuzzer
- **dirb**: Web content scanner
- **wpscan**: WordPress security scanner
- **whatweb**: Web application fingerprinting

## Advanced Features

### Custom Tool Integration

The AI can install and configure additional security tools as needed for specific assessments.

### Multi-Target Campaigns

```bash
# Analyze multiple targets
codex --bounty "target1.com target2.com target3.com" "multi-target assessment"
```

### Report Generation

Automated generation of:
- Executive summaries
- Technical findings
- CVSS scoring
- Remediation recommendations
- Evidence collection

### Integration with Bug Bounty Platforms

The AI agent understands common bug bounty workflows and can format findings for popular platforms like HackerOne, Bugcrowd, and Synack.

## Troubleshooting

### Tool Installation Issues

If tools fail to install:
1. Check internet connectivity
2. Verify package manager (apt/yum) is available
3. Ensure sufficient disk space
4. Run with appropriate permissions

### API Rate Limits

If you encounter rate limits:
1. Implement delays between requests
2. Use different API keys for parallel scans
3. Consider switching AI providers

### False Positives

The AI learns to reduce false positives over time, but you can help by:
1. Reviewing and correcting findings
2. Providing feedback on accuracy
3. Updating target-specific configurations

## Contributing

To improve the bug bounty automation:
1. Report issues with specific tools
2. Suggest new security tools to integrate
3. Share effective scanning methodologies
4. Contribute to prompt engineering