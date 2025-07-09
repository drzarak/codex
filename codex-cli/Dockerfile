FROM node:20

ARG TZ
ENV TZ="$TZ"

# Install bug bounty tools and dependencies
RUN apt update && apt install -y \
  aggregate \
  curl \
  dnsutils \
  fzf \
  gh \
  git \
  gnupg2 \
  golang-go \
  iproute2 \
  ipset \
  iptables \
  jq \
  less \
  man-db \
  nmap \
  procps \
  python3 \
  python3-pip \
  sqlmap \
  sudo \
  unzip \
  ripgrep \
  wget \
  zsh

# Install Go-based bug bounty tools
ENV GOPATH=/opt/go
ENV PATH=$PATH:/opt/go/bin:/usr/local/go/bin
RUN mkdir -p /opt/go && \
  go install -v github.com/owasp-amass/amass/v4/...@master && \
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
  go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Install Python-based security tools
RUN pip3 install \
  dirsearch \
  whatweb \
  xsstrike \
  commix

# Install Playwright dependencies for browser automation
RUN npx playwright install --with-deps chromium

# Ensure default node user has access to /usr/local/share and Go tools
RUN mkdir -p /usr/local/share/npm-global && \
  chown -R node:node /usr/local/share && \
  chown -R node:node /opt/go

ARG USERNAME=node

# Set up non-root user
USER node

# Install global packages
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH=$PATH:/usr/local/share/npm-global/bin:/opt/go/bin

# Install codex
COPY dist/codex.tgz codex.tgz
RUN npm install -g codex.tgz

# Copy and set up network configuration script (now allows full access)
COPY scripts/init_firewall.sh /usr/local/bin/
USER root
RUN chmod +x /usr/local/bin/init_firewall.sh && \
  echo "node ALL=(root) NOPASSWD: /usr/local/bin/init_firewall.sh" > /etc/sudoers.d/node-firewall && \
  chmod 0440 /etc/sudoers.d/node-firewall

# Set up auto-restart capability
COPY scripts/auto-restart.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/auto-restart.sh && \
  echo "node ALL=(root) NOPASSWD: /usr/local/bin/auto-restart.sh" >> /etc/sudoers.d/node-firewall

USER node

# Create necessary directories for bug bounty operations
RUN mkdir -p /home/node/.codex/tools /home/node/.codex/results /home/node/.codex/browser_data

# Expose port 3222 for web interface
EXPOSE 3222

# Default command starts the bug bounty web server
CMD ["codex", "bugbounty", "server"]
