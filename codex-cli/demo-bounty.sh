#!/bin/bash

# Bug Bounty Automation Demo Script
# This script demonstrates the new bug bounty features in Codex CLI

echo "🔍 Codex Bug Bounty Automation Tool Demo"
echo "========================================"
echo

# Show help for bounty mode
echo "📋 Available Options:"
echo "---------------------"
node dist/cli.js --help | grep -A 20 "Bug Bounty examples"
echo

# Show security tools integration
echo "🛠️  Integrated Security Tools:"
echo "------------------------------"
echo "✓ nmap - Network discovery and security auditing"
echo "✓ masscan - High-speed port scanner" 
echo "✓ gobuster - Directory/file enumeration"
echo "✓ sqlmap - SQL injection testing"
echo "✓ nikto - Web vulnerability scanner"
echo "✓ nuclei - Vulnerability scanner with templates"
echo "✓ subfinder - Subdomain discovery"
echo "✓ amass - Attack surface mapping"
echo "✓ httpx - HTTP toolkit"
echo "✓ ffuf - Fast web fuzzer"
echo "✓ dirb - Web content scanner"
echo "✓ wpscan - WordPress security scanner"
echo "✓ whatweb - Web application fingerprinting"
echo "✓ dig - DNS lookup tool"
echo "✓ curl - HTTP client for testing"
echo

# Show AI providers
echo "🤖 AI Provider Support:"
echo "-----------------------"
echo "✓ OpenAI (default) - Set OPENAI_API_KEY"
echo "✓ Google Gemini - Set GEMINI_API_KEY and use --ai-provider gemini"
echo

# Example usage commands  
echo "📝 Example Usage Commands:"
echo "--------------------------"
echo
echo "# Web application security assessment:"
echo "codex --bounty example.com \"web application scan\""
echo
echo "# Network enumeration with AI analysis:"
echo "codex --bounty 192.168.1.0/24 \"network enumeration\""
echo
echo "# Subdomain discovery and analysis:"
echo "codex --bounty bigcorp.com \"subdomain discovery\""
echo
echo "# Using Google Gemini AI instead of OpenAI:"
echo "codex --bounty --ai-provider gemini target.com \"comprehensive scan\""
echo
echo "# Multi-target assessment:"
echo "codex --bounty \"target1.com target2.com\" \"multi-target assessment\""
echo

echo "⚠️  Ethical Usage Reminders:"
echo "----------------------------"
echo "• Only test systems you own or have explicit permission to test"
echo "• Follow responsible disclosure practices"
echo "• Respect rate limits and avoid DoS conditions"
echo "• Document all findings with proper evidence"
echo "• Stay within defined scope boundaries"
echo

echo "🔧 Self-Improvement Features:"
echo "-----------------------------"
echo "✓ Learns from scan results to improve future assessments"
echo "✓ Automatically adjusts tool parameters based on target responses"
echo "✓ Reduces false positives through AI analysis"
echo "✓ Suggests additional tools based on discovered vulnerabilities"
echo "✓ Optimizes scanning strategies for different target types"
echo "✓ Generates comprehensive reports with CVSS scoring"
echo

echo "📊 Vulnerability Analysis:"
echo "-------------------------"
echo "✓ Automatic CVSS score calculation"
echo "✓ CWE mapping for discovered vulnerabilities"
echo "✓ Severity categorization (Critical/High/Medium/Low/Info)"
echo "✓ Evidence collection and remediation recommendations"
echo "✓ Executive summary generation"
echo "✓ Integration with bug bounty platform workflows"
echo

echo "🚀 Ready to start bug bounty hunting with AI-powered automation!"
echo "Set your API key and run: codex --bounty <target> \"<scan-type>\""