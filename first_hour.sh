#!/bin/bash

# groups
# /etc/init/, /etc/init.d/, /etc/pam.d
# /etc/sudoers (no % groups), backup: chmod 600 /bucket; cp /etc/sudoers /bucket/sudoers
# crontab -u as regular user and root, /etc/cron.* and /var/spool
# ~/.bashrc, /etc/bash.bashrc, /etc/profile, ~/.bash_profile, ~/.profile, ~/.bash_login
# ps auxfww
# netstat/ss -tulpna, lsof -nPi -sTCP:LISTEN
# env
# /etc/apt/sources.list, apt-cache policy, apt-key list
# lsof -i $port; whereis $program; dpkg -S $location; apt-get purge $package; 
    # rm $location; killall -9 $program
# service --status-all



clamav() {
    echo "[Running clamav] Running clamav scan. Writing to output.txt..."

    case $distro in
        "ubuntu" | "debian")
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

    echo "Clamav Output\n" >> output.txt
    freshclam
    clamscan -ri --move=/tmp/virus /home/ /bin/ /sbin/ /usr/bin/ /usr/sbin/ /etc/ /tmp/ /var/tmp/ >> output.txt 2>/dev/null
    echo "========================================" >> output.txt

    crontab -l | echo "clamscan -ri --move=/tmp/virus /home/ /bin/ /sbin/ /usr/bin/ /usr/sbin/ /etc/ /tmp/ /var/tmp/ >> /tmp/clamav 2>/dev/null" | crontab -

    echo "[Completed clamav] Results in output.txt"
}

debsums() {
    echo "[Running debsums] Running debsums and reinstalling as needed..."

    case $distro in
   	    "ubuntu" | "debian")
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

chkrootkit() {
    echo "Checking for rootkits. Writing to output.txt..."

    case $distro in
        "ubuntu" | "debian")
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

    echo "Chkrootkit Output" >> output.txt
    chkrootkit | grep -E 'INFECTED|suspicious' >> output.txt
    echo "========================================" >> output.txt

    echo "[Completed chkrootkit] Results in output.txt"
}

rpcbind() {
    echo "[Running rpcbind] Disabling rpcbind..."

    case $distro in
        "ubuntu" | "debian" | "centos" | "rhel" | "fedora" | "opensuse")
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

# /etc/audit/auditd.conf
auditd() {
    echo "[Running auditd] Installing and setting rules for auditd..."

    case $distro in
        "ubuntu" | "debian")
            apt-get install auditd
            ;;
        "centos" | "rhel" | "fedora")
            yum install auditd
            ;;
        "opensuse")
            zypper install audit
            ;;
        "alpine")
            apk add audit
            ;;
        *)
            echo "Error installing auditd. Moving on..."
            return 1
    esac

    if [ $distro != "alpine" ]; then
		systemctl start auditd
		systemctl enable auditd
    else
		rc-service auditd start
		rc-update add auditd
    fi

    auditctl -e 1
    auditctl -w /etc/audit/ -p wa -k auditconfig
    auditctl -w /etc/libaudit.conf -p wa -k auditconfig
    auditctl -w /etc/audisp/ -p wa -k audispconfig
    auditctl -w /etc/sysctl.conf -p wa -k sysctl
    auditctl -w /etc/sysctl.d -p wa -k sysctl
	auditctl -w /etc/cron.allow -p wa -k cron
	auditctl -w /etc/cron.deny -p wa -k cron
	auditctl -w /etc/cron.d/ -p wa -k cron
	auditctl -w /etc/cron.daily/ -p wa -k cron
	auditctl -w /etc/cron.hourly/ -p wa -k cron
	auditctl -w /etc/crontab -p wa -k cron
	auditctl -w /etc/sudoers -p wa -k sudoers
	auditctl -w /etc/sudoers.d/ -p wa -k sudoers
	auditctl -w /usr/sbin/groupadd -p x -k group_add
	auditctl -w /usr/sbin/groupmod -p x -k group_mod
	auditctl -w /usr/sbin/addgroup -p x -k add_group
	auditctl -w /usr/sbin/useradd -p x -k user_add
	auditctl -w /usr/sbin/userdel -p x -k user_del
	auditctl -w /usr/sbin/usermod -p x -k user_mod
	auditctl -w /usr/sbin/adduser -p x -k add_user
	auditctl -w /etc/login.defs -p wa -k login
	auditctl -w /etc/securetty -p wa -k login
	auditctl -w /var/log/faillog -p wa -k login
	auditctl -w /var/log/lastlog -p wa -k login
	auditctl -w /var/log/tallylog -p wa -k login
	auditctl -w /etc/passwd -p wa -k users
	auditctl -w /etc/shadow -p wa -k users
	auditctl -w /etc/sudoers -p wa -k users
	auditctl -w /bin/rmdir -p x -k directory
	auditctl -w /bin/mkdir -p x -k directory
	auditctl -w /usr/bin/passwd -p x -k passwd
	auditctl -w /usr/bin/vim -p x -k text
	auditctl -w /bin/nano -p x -k text
	auditctl -w /usr/bin/pico -p x -k text

	if [ $distro != "alpine" ]; then
		systemctl restart auditd
    else
		rc-service auditd restart
    fi

    echo "[Completed auditd]"
}

cron() {
    echo "[Running cron] Denying users ability to use cron jobs..."

    echo "ALL" >> /etc/cron.deny
    if [ $distro != "alpine" ]; then
        echo "exit 0" > /etc/rc.local
    fi

    echo "[Completed cron]"
}

ips() {
    echo "[Running ips] Disabling ipv6 and ip forwarding..."

    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    sysctl -w net.ipv4.ip_forward=0
    echo "nospoof on" >> /etc/host.conf

    echo "[Completed ips]"
}

change_bin() {
    echo "[Running change_bin] Deleting telnet, nc; changing to curlbk, wgetbk..."

    rm $(which telnet)
    rm $(which nc)

    mv $(which curl){,bk}
    mv $(which wget){,bk}

    echo "[Completed change_bin]"
}

update() {
    echo "[Running update] Updating packages..."

    case $distro in
        "ubuntu" | "debian")
            apt-get update
            apt-get -y upgrade
            ;;
        "centos" | "rhel" | "fedora")
            yum -y update
            ;;
        "opensuse")
            zypper refresh
            zypper update
            ;;
        "alpine")
            apk update
            apk upgrade
            ;;
        *)
            echo "Error updating packages. Moving on..."
            return 1
    esac
    
    echo "[Completed update]"
}

rkhunter() {
    echo "[Running rkhunter] Checking for rootkits. Writes to /var/log/rkhunter.log..."

    case $distro in
        "ubuntu" | "debian")
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
    esac

    rkhunter --update
    rkhunter --propupd
    rkhunter -c --enable all --disable none --sk

    echo "[Completed rkhunter] Results in /var/log/rkhunter.log"
}

# deborphan --guess-all
deborphan() {
    echo "[Running deborphan] Clean up unnecessary packages"

    case $distro in
        "ubuntu" | "debian")
            apt-get install -y deborphan
            deborphan --guess-data | xargs apt-get -y remove --purge
            deborphan | xargs apt-get -y remove --purge
            ;;
        "centos" | "rhel" | "fedora")
            yum -y install epel-release
            yum -y install deborphan
            deborphan --guess-data | xargs yum -y remove
            deborphan | xargs yum -y remove
            ;;
        "opensuse")
            zypper install -y deborphan
            deborphan --guess-data | xargs zypper remove
            deborphan | xargs zypper remove
            ;;
        "alpine")
            apk add deborphan
            deborphan --guess-data | xargs apk del
            deborphan | xargs apk del
            ;;
        *)
            echo "Error running deborphan. Moving on..."
            return 1
    esac

    echo "[Completed deborphan]"
}

firewall() {
    echo "[Running firewall] Installing and allowing ssh in ufw or iptables..."

    case $distro in
        "ubuntu" | "debian")
            apt-get install -y ufw
            ufw allow ssh
            ufw logging on 
            ufw enable 
            ufw start
            ;;
        "centos" | "rhel" | "fedora")
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A OUTPUT -o lo -j ACCEPT
            iptables -A INPUT -p tcp --dport 22 -j ACCEPT
            iptables -P INPUT DROP
            systemctl start iptables
            systemctl enable iptables
            iptables -N LOGGING
            iptables -A INPUT -j LOGGING
            iptables -A LOGGING -j DROP
            service iptables save
            service iptables restart

            ;;
        "opensuse")
            
            ;;
        "alpine")
            apk add iptables
            iptables -A INPUT -p tcp --dport 22 -j ACCEPT
            service iptables save
            service iptables restart
            ;;
        *)
            echo "Error setting up ufw/iptables. Moving on..."
            return 1
    esac

    echo "[Completed firewall]"
}








#1
lynis() {
    cd /usr/local
    git clone https://github.com/CISOfy/lynis
    chown -R 0:0 /usr/local/lynis
    cd /usr/local/lynis
    lynis audit system
    look through /var/log/lynis-report.dat 
    grep -E 'warning|suggestion' | sed -e 's/warning\[\]\=//g' | sed -e 's/suggestion\[\]\=//g'

}

#2
configure_ssh() {
 # no root login
 Protocol 2
LogLevel VERBOSE
X11Forwarding no
MaxAuthTries 4
IgnoreRhosts yes
HostbasedAuthentication no
PermitRootLogin no
PermitEmptyPasswords no

}

#3
fail2ban() {

}

#5
change_pass() {

}

#6
lock_accounts() {

}

#7
enumerate() {
    # os, network, port, users, groups
}

#9
backup_configs() {

}

#10
suid() {

}

#11
wazuh_agent() {

}

#12
wazuh_listen() {

}

# Check if running script as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Determine linux distro and call appropriate functions
if [ -e /etc/os-release ]; then
    . /etc/os-release
    distro=$ID
    echo "Detected: $distro"

    touch output.txt

    # call functions
    # change output of antivirus

else
    echo "Unable to determine distro. Exiting"
    exit 1
fi
