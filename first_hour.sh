#!/bin/bash

# Package Management
# =======================================================================================
update() {
    echo "[Running update] Updating packages..."

    case $distro in
        *ubuntu* | *debian* | *mint*)
            apt-get update > /dev/null 
            apt-get -y upgrade > /dev/null 
            ;;
        *centos* | *rhel* | *fedora*)
            yum -y update > /dev/null 
            ;;
        *opensuse*)
            zypper refresh > /dev/null
            zypper update > /dev/null
            ;;
        *alpine*)
            apk update > /dev/null 
            apk upgrade > /dev/null
            ;;
        *)
            echo "Error updating packages. Moving on..."
            return 1
            ;;
    esac
    
    echo "[Completed update]"
}

clean_packages() {
    echo "[Running clean_packages] Cleaning up unnecessary packages..."

    case $distro in
        *ubuntu* | *debian* | *mint*)
            apt-get install -y deborphan > /dev/null 
            deborphan --guess-data | xargs apt-get -y remove --purge  > /dev/null 
            deborphan | xargs apt-get -y remove --purge  > /dev/null 
            ;;
        *centos* | *rhel* | *fedora*)
            yum -y autoremove > /dev/null
            ;;
        *opensuse*)
            zypper packages --orphaned | grep -E '^[ivcud]' | awk '{print $5}' | xargs zypper remove --clean-deps > /dev/null
            ;;
        *)
            echo "Error cleaning up packages. Moving on..."
            return 1
            ;;
    esac

    echo "[Completed clean_packages]"
}


# Enumeration
# =======================================================================================
enumerate() {
    echo "[Running enumerate] Enumerating system information. Writing to fh.txt..."
    echo "========== ENUMERATION ==========" >> fh.txt

    # OS
    hostname=$(hostname)    
    echo "Hostname: $hostname" >> fh.txt

    os_info=$(cat /etc/*-release 2>/dev/null)
    echo "OS Information:" >> fh.txt
    echo "$os_info" >> fh.txt

    # Network
    interfaces=$(ip a | grep -v "lo" | grep "UP" | awk '{print $2}' | cut -d ":" -f1)
    declare -A ip_addresses
    declare -A mac_addresses
    for interface in $interfaces; do
        ip_addresses["$interface"]=$(ip a show "$interface" | grep "inet" | awk '{print $2}')
        mac_addresses["$interface"]=$(ip a show "$interface" | grep "link/ether" | awk '{print $2}')
    done
    {
        for interface in $interfaces; do
            echo -e "\nInterface: $interface" 
            echo "  IP Address: ${ip_addresses[$interface]}"
            echo "  MAC Address: ${mac_addresses[$interface]}"
        done
    } >> fh.txt

    # Users
    echo -e "\nUsers:" >> fh.txt
    getent passwd | awk -F: '/\/(bash|sh)$/ { print $1 }' >> fh.txt

    # Groups
    echo -e "\nGroups:" >> fh.txt
    while IFS=: read -r group_name _ _ user_list; do
        if [ -n "$user_list" ]; then
            echo "Group: $group_name" >> fh.txt
            echo "Users: $user_list" >> fh.txt
        else
            echo "Deleting group: $group_name" >> fh.txt
            groupdel "$group_name" 2>/dev/null
        fi
    done < <(cat /etc/group)

    # Cron jobs
    echo -e "\nCron Jobs:" >> fh.txt
    directories=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.monthly" "/etc/cron.weekly" "/var/spool/cron" "/etc/anacrontab" "/var/spool/anacron")
    for directory in "${directories[@]}"; do
        echo "Cron Jobs in $directory:" >> fh.txt
        for file in "$directory"/*; do
            if [ -f "$file" ]; then
                echo "File: $file" >> fh.txt
                cat "$file" >> fh.txt
            fi
        done
    done
    echo "[Completed enumerate] Results in fh.txt"
}


# User Accounts
# =======================================================================================
manage_acc() {
    echo "[Running manage_acc] Changing user passwords and locking accounts (except for yourself and root)..."

    current_user=$(echo $SUDO_USER)
    for user in $(awk -F':' '$1 != "root" && $1 != "'"$current_user"'" && $7 != "/sbin/nologin" && $7 != "/bin/false" {print $1}' /etc/passwd); do
        new_password=$(openssl rand -base64 12)
        echo "$user:$new_password" | chpasswd
    done

    for user in $(awk -F':' '$1 != "root" && $1 != "'"$current_user"'" && $7 != "/sbin/nologin" && $7 != "/bin/false" {print $1}' /etc/passwd); do
        usermod --shell /sbin/nologin --lock $user
    done
    usermod -s /sbin/nologin root

    echo "[Completed manage_acc]"
}


# SSH
# =======================================================================================
configure_ssh() {
    echo "[Running configure_ssh] Updating SSH configuration file..."

    if [ -f /etc/ssh/sshd_config ]; then

        sed -i '/^#X11Forwarding/s/^#//' /etc/ssh/sshd_config
        sed -i '/^#MaxAuthTries/s/^#//' /etc/ssh/sshd_config
        sed -i '/^#IgnoreRhosts/s/^#//' /etc/ssh/sshd_config
        sed -i '/^#HostbasedAuthentication/s/^#//' /etc/ssh/sshd_config
        sed -i '/^#PermitRootLogin/s/^#//' /etc/ssh/sshd_config
        sed -i '/^#PermitEmptyPasswords/s/^#//' /etc/ssh/sshd_config

        sed -i 's/^X11Forwarding\s\+.*/X11Forwarding no/' /etc/ssh/sshd_config
        sed -i 's/^MaxAuthTries\s\+.*/MaxAuthTries 3/' /etc/ssh/sshd_config
        sed -i 's/^IgnoreRhosts\s\+.*/IgnoreRhosts yes/' /etc/ssh/sshd_config
        sed -i 's/^HostbasedAuthentication\s\+.*/HostbasedAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/^PermitRootLogin\s\+.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i 's/^PermitEmptyPasswords\s\+.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

        grep -q '^X11Forwarding\s\+no' /etc/ssh/sshd_config || echo "X11Forwarding no" >> /etc/ssh/sshd_config
        grep -q '^MaxAuthTries\s\+3' /etc/ssh/sshd_config || echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
        grep -q '^IgnoreRhosts\s\+yes' /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
        grep -q '^HostbasedAuthentication\s\+no' /etc/ssh/sshd_config || echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
        grep -q '^PermitRootLogin\s\+no' /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
        grep -q '^PermitEmptyPasswords\s\+no' /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
    fi 

    echo "*/10 * * * * root service ssh start" >> /etc/crontab

    echo "[Completed configure_ssh]"
}


# Firewall
# =======================================================================================
firewall() {
    echo "[Running firewall] Installing and allowing ssh in ufw or iptables..."

    case $distro in
        *ubuntu* | *debian* | *mint*)
            apt-get install -y ufw > /dev/null 
            ufw allow ssh
            ufw logging on 
            ufw enable 
            ;;
        *centos* | *rhel* | *fedora* | *opensuse* | *alpine*)
            iptables -P INPUT DROP
            iptables -P FORWARD DROP
            iptables -A INPUT -p tcp --dport 22 -j ACCEPT
            iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A OUTPUT -o lo -j ACCEPT
            systemctl start iptables
            systemctl enable iptables
            iptables -N LOGGING
            iptables -A INPUT -j LOGGING
            iptables -A LOGGING -j DROP
            service iptables save
            service iptables restart
            ;;
        *)
            echo "Error setting up ufw/iptables. Moving on..."
            return 1
            ;;
    esac

    echo "[Completed firewall]"
}

fail2ban() {
    echo "[Running fail2ban] Installing and starting fail2ban..."
    case $distro in
        *ubuntu* | *debian* | *mint*)
            apt-get install -y fail2ban > /dev/null 
            ;;
        *centos* | *rhel* | *fedora*)
            yum install -y epel-release > /dev/null 
            yum install -y fail2ban > /dev/null 
            ;;
        *opensuse*)
            zypper install -y fail2ban > /dev/null 
            ;;
        *alpine*)
            apk add fail2ban > /dev/null 
            ;;
        *)
            echo "Error installing fail2ban. Moving on..."
            return 1
            ;;
    esac

    systemctl start fail2ban
    systemctl enable fail2ban

    echo '[sshd]
    enabled = true
    port = ssh
    filter = sshd
    logpath = /var/log/auth.log
    maxretry = 3
    bantime = 1d
    ignoreip = 127.0.0.1' > /etc/fail2ban/jail.local

    systemctl restart fail2ban

    echo "[Completed fail2ban]"
}


# Logging
# =======================================================================================
auditd() {
    # /etc/audit/auditd.conf
    echo "[Running auditd] Installing and setting rules for auditd..."

    case $distro in
        *ubuntu* | *debian* | *mint*)
            apt-get install -y auditd > /dev/null
            ;;
        *centos* | *rhel* | *fedora*)
            yum install -y auditd > /dev/null 
            ;;
        *opensuse*)
            zypper install -y audit > /dev/null 
            ;;
        *alpine*)
            apk add audit > /dev/null 
            ;;
        *)
            echo "Error installing auditd. Moving on..."
            return 1
    esac

    if [ $distro != *alpine* ]; then
		systemctl start auditd
		systemctl enable auditd > /dev/null 
    else
		rc-service auditd start
		rc-update add auditd
    fi

    auditctl -e 1 > /dev/null 
    cat <<EOL > /etc/audit/audit.rules
    -w /etc/audit/ -p wa -k auditconfig
    -w /etc/libaudit.conf -p wa -k auditconfig
    -w /etc/audisp/ -p wa -k audispconfig
    -w /etc/sysctl.conf -p wa -k sysctl
    -w /etc/sysctl.d -p wa -k sysctl
    -w /etc/cron.allow -p wa -k cron
    -w /etc/cron.deny -p wa -k cron
    -w /etc/cron.d/ -p wa -k cron
    -w /etc/cron.daily/ -p wa -k cron
    -w /etc/cron.hourly/ -p wa -k cron
    -w /etc/crontab -p wa -k cron
    -w /etc/sudoers -p wa -k sudoers
    -w /etc/sudoers.d/ -p wa -k sudoers
    -w /usr/sbin/groupadd -p x -k group_add
    -w /usr/sbin/groupmod -p x -k group_mod
    -w /usr/sbin/addgroup -p x -k add_group
    -w /usr/sbin/useradd -p x -k user_add
    -w /usr/sbin/userdel -p x -k user_del
    -w /usr/sbin/usermod -p x -k user_mod
    -w /usr/sbin/adduser -p x -k add_user
    -w /etc/login.defs -p wa -k login
    -w /etc/securetty -p wa -k login
    -w /var/log/faillog -p wa -k login
    -w /var/log/lastlog -p wa -k login
    -w /var/log/tallylog -p wa -k login
    -w /etc/passwd -p wa -k users
    -w /etc/shadow -p wa -k users
    -w /etc/sudoers -p wa -k users
    -w /bin/rmdir -p x -k directory
    -w /bin/mkdir -p x -k directory
    -w /usr/bin/passwd -p x -k passwd
    -w /usr/bin/vim -p x -k text
    -w /bin/nano -p x -k text
    -w /usr/bin/pico -p x -k text
    EOL
    
    if [ $distro != *alpine* ]; then
        systemctl restart auditd 
    else
        rc-service auditd restart
    fi
    
    echo "[Completed auditd]"
}


# Configs
# =======================================================================================
ips() {
    echo "[Running ips] Disabling ipv6 and ip forwarding..."

    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    sysctl -w net.ipv4.ip_forward=0
    echo "nospoof on" >> /etc/host.conf

    echo "[Completed ips]"
}

cron() {
    echo "[Running cron] Denying users ability to use cron jobs..."

    echo "ALL" >> /etc/cron.deny
    if [ -f "/etc/rc.local" ]; then
        echo "exit 0" > /etc/rc.local
    fi

    echo "[Completed cron]"
}

change_bin() {
    echo "[Running change_bin] Deleting telnet, nc; changing to curlbk, wgetbk..."

    rm $(which telnet)
    rm $(which nc)

    mv $(which curl){,bk}
    mv $(which wget){,bk}

    echo "[Completed change_bin]"
}

modules() {
    echo "[Running modules] Disable ability to load new modules..."

    sysctl -w kernel.modules_disabled=1
    echo 'kernel.modules_disabled=1' > /etc/sysctl.conf

    echo "[Running modules]"
}


# Antivirus 
# =======================================================================================
clamav() {
    echo "[Running clamav] Running clamav scan. Writing to first_hour.txt..."

    case $distro in
        "ubuntu" | "debian" | "mint")
   		    apt-get install clamav clamav-daemon
   		    ;;
   	    "centos" | "rhel" | "fedora")
   		    yum install clamav clamav-server
   		    ;;
   	    "opensuse")
   		    zypper install clamav clamav-daemon
   		    ;;
   	    "alpine")
   		    apk add clamav clamav-daemon
   		    ;;
   	    *)
   		    echo "Error running clamav scan. Moving on..."
            return 1
   		    ;;
    esac

    echo -e "\n========== ClamAV Scan ==========" >> first_hour.txt
    freshclam
    clamscan -ri --move=/tmp/virus /home/ /bin/ /sbin/ /usr/bin/ /usr/sbin/ /etc/ /tmp/ /var/tmp/ >> first_hour.txt 2>/dev/null
    crontab -l | echo "clamscan -ri --move=/tmp/virus /home/ /bin/ /sbin/ /usr/bin/ /usr/sbin/ /etc/ /tmp/ /var/tmp/ >> /tmp/clamav 2>/dev/null" | crontab -

    echo "[Completed clamav] Results in first_hour.txt"
}

chkrootkit() {
    echo "[Running chkrootkit] Checking for rootkits. Writing to first_hour.txt..."

    case $distro in
        "ubuntu" | "debian" | "mint")
            apt-get install -y chkrootkit
   		    ;;
   	    "centos" | "rhel" | "fedora")
   		    yum install -y chkrootkit
   		    ;;
   	    "opensuse")
   		    zypper install chkrootkit
   		    ;;
   	    "alpine")
   		    apk add chkrootkit
   		    ;;
   	    *)
   		    echo "Error checking for rootkits. Moving on..."
            return 1
   		    ;;
    esac

    echo -e "\n========== Chkrootkit Reulsts ==========" >> first_hour.txt
    chkrootkit | grep -E 'INFECTED|suspicious' >> first_hour.txt

    echo "[Completed chkrootkit] Results in first_hour.txt"
}

debsums() {
    echo "[Running debsums] Running debsums and reinstalling as needed..."

    case $distro in
   	    "ubuntu" | "debian" | "mint")
   		    apt-get install debsums
   		    debsums -g
   		    apt-get install --reinstall $(dpkg -S $(debsums -c) | cut -d : -f 1 | sort -u)
   		    ;;
   	    "centos" | "rhel" | "fedora")
   		    yum reinstall $(rpm -qf $(rpm -Va --nofiles --noscripts --nodigest | awk '$1 ~ /^.M/{print $2}'))
   		    ;;
   	    "opensuse")
   		    zypper install --force --replacepkgs --from <repository> $(zypper verify -r 2>&1 | awk '/ERROR:/{print $4}')
   		    ;;
   	    "alpine")
   		    apk add --upgrade --available --reinstall $(apk verify -c 2>&1 | awk '/ERROR:/{print $3}')
   		    ;;
   	    *)
   		    echo "Error verifying files. Moving on..."
            return 1
   		    ;;
    esac

    echo "[Completed debsums]"
}

rpcbind() {
    echo "[Running rpcbind] Disabling rpcbind..."

    case $distro in
        "ubuntu" | "debian" | "mint" | "centos" | "rhel" | "fedora" | "opensuse")
            systemctl disable rpcbind
   		    systemctl stop rpcbind
   		    systemctl mask rpcbind
   		    systemctl stop rpcbind.socket
   		    systemctl disable rpcbind.socket
   		    ;;
        "alpine")
            rc-update del rpcbind
   		    rc-service rpcbind stop
   		    ;;
   	    *)
            echo "Error disabling rpcbind. Moving on..."
            return 1
   		    ;;
    esac
    
    echo "[Completed rpcbind]"
}

rkhunter() {
    echo "[Running rkhunter] Checking for rootkits. Writes to /var/log/rkhunter.log..."

    case $distro in
        "ubuntu" | "debian" | "mint")
            apt-get -y install rkhunter
            ;;
        "centos" | "rhel" | "fedora")
            yum -y install rkhunter
            ;;
        "opensuse")
            zypper -y install rkhunter
            ;;
        "alpine")
            apk add rkhunter
            ;;
        *)
            echo "Error running rkhunter. Moving on..."
            return 1
            ;;
    esac

    rkhunter --update
    rkhunter --propupd
    rkhunter -c --enable all --disable none --sk

    echo "[Completed rkhunter] Results in /var/log/rkhunter.log"
}


# Backups
# =======================================================================================
backup_configs() {
    echo "[Running backup_configs] Backing up files..."
    
    mkdir -p /var/backups
    cp -r /etc/pam* /var/backups
    cp -r /lib/security* /var/backups
    cp -r /etc /var/backups

    if [ -d "/var/www" ]; then
        cp -r /var/www /var/backups
    fi

    chattr +i -R /var/backups/*
}

# Check if running script as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root. Exiting"
    exit 1
fi

# Determine linux distro and call appropriate functions
if [ -e /etc/os-release ]; then
    . /etc/os-release
    distro=$ID
    echo "Detected: $distro"

    # call functions

else
    echo "Unable to determine distro. Exiting"
    exit 1
fi
