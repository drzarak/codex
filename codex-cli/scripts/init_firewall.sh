#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, and pipeline failures
IFS=$'\n\t'       # Stricter word splitting

echo "Configuring network access for bug bounty operations..."

# Flush existing restrictive rules and delete existing ipsets
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
ipset destroy allowed-domains 2>/dev/null || true

# Set permissive default policies to allow all network traffic
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Allow all inbound and outbound traffic (removing network jail)
iptables -A INPUT -j ACCEPT
iptables -A OUTPUT -j ACCEPT
iptables -A FORWARD -j ACCEPT

echo "Network configuration complete - full internet access enabled"
echo "Verifying network access..."

# Verify general internet access
if curl --connect-timeout 5 https://example.com >/dev/null 2>&1; then
    echo "SUCCESS: Full internet access confirmed - can reach https://example.com"
else
    echo "WARNING: Unable to reach https://example.com - check network connectivity"
fi

# Verify OpenAI API access is still working
if curl --connect-timeout 5 https://api.openai.com >/dev/null 2>&1; then
    echo "SUCCESS: OpenAI API access confirmed"
else
    echo "WARNING: Unable to reach OpenAI API - check connectivity"
fi

# Verify access to common bug bounty tool services
for service in "github.com" "shodan.io" "crt.sh"; do
    if curl --connect-timeout 5 "https://$service" >/dev/null 2>&1; then
        echo "SUCCESS: $service is accessible"
    else
        echo "WARNING: Unable to reach $service"
    fi
done

echo "Bug bounty network configuration complete"
