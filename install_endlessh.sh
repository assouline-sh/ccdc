#!/bin/bash
# Configure and run endlessh, an SSH tarpit that slowly sends an endless connection banner, on port 22.
# Must run as root and provide alternative port for working ssh that is not port 22. 

# Check if running script as root
if [ "$EUID" -ne 0 ]; then
    echo "[Error] Please run this script as root. Exiting."
    exit 1
fi

# Check for port number
if [ -z "$1" || "$1" == 22 ]; then
    echo "[Error] Please provide alternative port for working ssh. Exiting."
    exit 1
fi
port="$1"

# Determine package manager to use
pm = $(which apt 2>/dev/null || 
        which yum 2>/dev/null || 
        which dnf 2>/dev/null || 
        which zypper 2>/dev/null)

if [ -n "$pm"]; then
    echo "[Error] Unsupported distro. Exiting."
    exit 1
fi

# Update packages and install necessary ones
if ["$pm" == "zypper"]; then
    $pm refresh
fi

$pm update 

if ["$pm" == "apt"]; then
    $pm upgrade
fi

# Update firewall rules
if ufw status | grep -q "active"; then
    ufw allow "$port"
    ufw reload
fi
iptables -A INPUT -p tcp --dport "$port" -j ACCEPT

# Change working ssh port
sed -i "s/Port [0-9]\+/Port $port/" /etc/ssh/sshd_config
systemctl restart ssh

# Install endlessh from package manager or git, and run it
if "$pm" search endlessh | grep -q endlessh; then
    "$pm" install -y endlessh
    endlessh -p 22
else
    "$pm" install -y libc6-dev
    "$pm" install -y git
    git clone https://github.com/skeeto/endlessh

    cd endlessh
    make
    mv endlessh /usr/local/bin/
    cp util/endlessh.service /etc/systemd/system/
    systemctl enable endlessh
    mkdir -p /etc/endlessh
    echo "Port 22" > /etc/endlessh/config
    systemctl start endlessh

# Check if successful, then exit
if systemctl is-active --quiet endlessh; then
    echo "Endlessh running on port 22. SSH running on $port"
    exit 0
else
    echo "[Error] Endlessh failed to start. Exiting."
    exit 1
fi
