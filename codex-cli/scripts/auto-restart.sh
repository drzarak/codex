#!/bin/bash
set -euo pipefail

echo "🔄 Setting up auto-restart for AI Bug Bounty Hunter..."

# Create systemd service for Docker auto-restart
cat > /etc/systemd/system/bugbounty-hunter.service << 'EOF'
[Unit]
Description=AI Bug Bounty Hunter Docker Container
Wants=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/docker run --name bugbounty-hunter -d \
  --restart=unless-stopped \
  -p 222:222 \
  -e OPENAI_API_KEY=${OPENAI_API_KEY} \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v /opt/bugbounty-data:/home/node/.codex \
  codex:latest
ExecStop=/usr/bin/docker stop bugbounty-hunter
ExecStopPost=/usr/bin/docker rm -f bugbounty-hunter

[Install]
WantedBy=multi-user.target
EOF

# Create data directory for persistence
mkdir -p /opt/bugbounty-data
chown -R 1000:1000 /opt/bugbounty-data

# Enable the service
systemctl enable bugbounty-hunter.service

echo "✅ Auto-restart service configured"
echo "📋 To manage the service:"
echo "   Start:   sudo systemctl start bugbounty-hunter"
echo "   Stop:    sudo systemctl stop bugbounty-hunter"
echo "   Status:  sudo systemctl status bugbounty-hunter"
echo "   Logs:    sudo journalctl -u bugbounty-hunter -f"
echo ""
echo "🌐 Web interface will be available at http://localhost:222"
echo "💾 Data will persist in /opt/bugbounty-data"