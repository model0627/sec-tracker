#!/bin/bash

# Security Tracker Agent Installation Script
# For Ubuntu/Debian systems

set -e

AGENT_USER="sec-tracker"
AGENT_GROUP="sec-tracker"
CONFIG_DIR="/etc/sec-tracker"
LOG_DIR="/var/log/sec-tracker"
LIB_DIR="/var/lib/sec-tracker"
BIN_PATH="/usr/local/bin/sec-tracker"
SERVICE_FILE="/etc/systemd/system/sec-tracker.service"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
fi

# Check if Ubuntu/Debian
if ! command -v apt-get &> /dev/null; then
    error "This installer is designed for Ubuntu/Debian systems"
fi

log "Starting Security Tracker Agent installation..."

# Create user and group
if ! getent group "$AGENT_GROUP" > /dev/null 2>&1; then
    log "Creating group: $AGENT_GROUP"
    groupadd --system "$AGENT_GROUP"
fi

if ! getent passwd "$AGENT_USER" > /dev/null 2>&1; then
    log "Creating user: $AGENT_USER"
    useradd --system --gid "$AGENT_GROUP" --home-dir /var/lib/sec-tracker \
            --shell /bin/false --comment "Security Tracker Agent" "$AGENT_USER"
fi

# Create directories
log "Creating directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$LIB_DIR"
mkdir -p "$CONFIG_DIR/certs"

# Set ownership and permissions
chown -R "$AGENT_USER:$AGENT_GROUP" "$CONFIG_DIR"
chown -R "$AGENT_USER:$AGENT_GROUP" "$LOG_DIR"
chown -R "$AGENT_USER:$AGENT_GROUP" "$LIB_DIR"

chmod 755 "$CONFIG_DIR"
chmod 750 "$LOG_DIR"
chmod 750 "$LIB_DIR"
chmod 700 "$CONFIG_DIR/certs"

# Install dependencies
log "Installing dependencies..."
apt-get update
apt-get install -y curl wget ca-certificates

# Check if Go binary exists
if [ ! -f "./sec-tracker" ]; then
    error "sec-tracker binary not found. Please build the project first with 'go build'"
fi

# Copy binary
log "Installing binary..."
cp "./sec-tracker" "$BIN_PATH"
chmod 755 "$BIN_PATH"

# Copy configuration
if [ ! -f "$CONFIG_DIR/config.json" ]; then
    log "Installing default configuration..."
    cp "./config.json" "$CONFIG_DIR/config.json"
    chown "$AGENT_USER:$AGENT_GROUP" "$CONFIG_DIR/config.json"
    chmod 640 "$CONFIG_DIR/config.json"
    
    warn "Please edit $CONFIG_DIR/config.json with your server details and API key"
else
    warn "Configuration file already exists at $CONFIG_DIR/config.json"
fi

# Install systemd service
log "Installing systemd service..."
cp "./scripts/sec-tracker.service" "$SERVICE_FILE"
systemctl daemon-reload

# Create log rotation
log "Setting up log rotation..."
cat > /etc/logrotate.d/sec-tracker << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $AGENT_USER $AGENT_GROUP
    postrotate
        systemctl reload sec-tracker
    endscript
}
EOF

# Create AppArmor profile (if AppArmor is installed)
if command -v aa-status &> /dev/null; then
    log "Creating AppArmor profile..."
    cat > "/etc/apparmor.d/usr.local.bin.sec-tracker" << 'EOF'
#include <tunables/global>

/usr/local/bin/sec-tracker {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/ssl_certs>

  capability net_admin,
  capability sys_ptrace,
  capability dac_read_search,

  /usr/local/bin/sec-tracker r,
  /etc/sec-tracker/** r,
  /var/log/sec-tracker/** rw,
  /var/lib/sec-tracker/** rw,
  
  /proc/*/stat r,
  /proc/*/status r,
  /proc/*/comm r,
  /proc/meminfo r,
  /proc/cpuinfo r,
  /proc/loadavg r,
  /proc/uptime r,
  /proc/version r,
  /proc/net/tcp r,
  /proc/net/udp r,
  
  /sys/class/net/*/statistics/* r,
  
  /var/log/auth.log r,
  /var/log/syslog r,
  
  network inet stream,
  network inet dgram,
}
EOF
    apparmor_parser -r /etc/apparmor.d/usr.local.bin.sec-tracker || warn "Failed to load AppArmor profile"
fi

# Enable and start service
log "Enabling service..."
systemctl enable sec-tracker

log "Installation completed successfully!"
echo
echo "Next steps:"
echo "1. Edit the configuration file: $CONFIG_DIR/config.json"
echo "2. Update the server URL and API key"
echo "3. Configure the agent ID and monitoring paths"
echo "4. Start the service: systemctl start sec-tracker"
echo "5. Check status: systemctl status sec-tracker"
echo "6. View logs: journalctl -u sec-tracker -f"
echo
warn "Remember to configure your firewall to allow outbound HTTPS connections" 