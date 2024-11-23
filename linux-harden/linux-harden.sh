#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

# Function to generate a report
generate_report() {
    local report_file=$1
    echo "Generating report: $report_file"
    {
        echo "Date: $(date)"
        echo "Hostname: $(hostname)"
        echo "Uptime: $(uptime -p)"
        echo "Running services:"
        systemctl list-units --type=service --state=running --no-pager --no-legend
        echo "UFW status:"
        ufw status verbose || echo "UFW not installed or enabled."
        echo "Fail2ban status:"
        fail2ban-client status || echo "Fail2ban not installed or running."
        echo "AppArmor status:"
        apparmor_status || echo "AppArmor not installed or running."
        echo "Sysctl settings:"
        sysctl -a
    } > "$report_file"
}

# Generate the before-hardening report
generate_report "before_hardening_report.txt"

# Update and upgrade system packages
echo "Updating and upgrading system packages..."
apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y || {
    echo "Package update/upgrade failed. Please check your APT configuration."
    exit 1
}

# Add a new user and grant sudo access
read -p "Enter the new username: " newuser
if id "$newuser" &>/dev/null; then
    echo "User $newuser already exists."
else
    adduser "$newuser" && usermod -aG sudo "$newuser" || {
        echo "Failed to add user $newuser."
        exit 1
    }
fi

# Disable root login via SSH
echo "Disabling root login via SSH..."
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# Setup SSH key-based authentication
mkdir -p /home/$newuser/.ssh
read -p "Paste the public SSH key for the new user: " sshkey
echo "$sshkey" > /home/$newuser/.ssh/authorized_keys
chown -R "$newuser:$newuser" /home/$newuser/.ssh
chmod 600 /home/$newuser/.ssh/authorized_keys
chmod 700 /home/$newuser/.ssh

# Disable password authentication
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Change the default SSH port
read -p "Enter the new SSH port: " sshport
if [[ "$sshport" =~ ^[0-9]+$ ]] && [ "$sshport" -gt 0 ] && [ "$sshport" -lt 65536 ]; then
    sed -i "s/^#*Port .*/Port $sshport/" /etc/ssh/sshd_config
    ufw allow "$sshport/tcp"
else
    echo "Invalid SSH port. Skipping port change."
fi

systemctl restart sshd || {
    echo "Failed to restart SSH service. Please check your SSH configuration."
    exit 1
}

# Install and configure UFW
echo "Installing and configuring UFW..."
apt install ufw -y
ufw default deny incoming
ufw default allow outgoing
ufw allow "$sshport/tcp"
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable || echo "UFW configuration failed."

# Install and configure Fail2ban
echo "Installing and configuring Fail2ban..."
apt install fail2ban -y
cat <<EOT > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = $sshport
EOT
systemctl restart fail2ban

# Disable unused services
echo "Disabling unused services..."
systemctl list-units --type=service --state=running > running_services.txt

# Configure system logging
echo "Configuring system logging..."
apt install rsyslog -y
systemctl enable rsyslog && systemctl start rsyslog

# Secure shared memory
echo "Securing shared memory..."
if ! grep -q "tmpfs /tmp tmpfs defaults,noexec,nosuid 0 0" /etc/fstab; then
    echo "tmpfs /tmp tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
fi

# Enable automatic security updates
echo "Enabling automatic security updates..."
apt install unattended-upgrades -y
dpkg-reconfigure --priority=low unattended-upgrades

# Install and configure AppArmor
echo "Installing and configuring AppArmor..."
apt install apparmor apparmor-profiles -y
systemctl enable apparmor && systemctl start apparmor

# Install and configure Logwatch
echo "Installing and configuring Logwatch..."
apt install logwatch -y
logwatch --detail high --mailto your-email@example.com --range 'between -7 days and today'

# Secure network configuration
echo "Securing network configuration..."
if ! grep -q "net.ipv4.icmp_echo_ignore_all = 1" /etc/sysctl.conf; then
    echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
fi
sysctl -p

# Function to harden specific services
harden_service() {
    local service_name=$1
    case $service_name in
    ssh.service)
        echo "SSH hardening already applied."
        ;;
    apache2.service)
        echo "Hardening Apache..."
        apt install libapache2-mod-security2 -y
        a2enmod security2
        echo "ServerTokens Prod" >> /etc/apache2/conf-available/security.conf
        echo "ServerSignature Off" >> /etc/apache2/conf-available/security.conf
        systemctl restart apache2
        ;;
    mysql.service)
        echo "Hardening MySQL..."
        mysql_secure_installation
        ;;
    *)
        echo "No specific hardening steps for $service_name."
        ;;
    esac
}

# Allow user to select services to harden
while true; do
    echo "Available running services:"
    running_services=$(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}')
    echo "$running_services"
    read -p "Enter the name of the service to harden (or 'done' to finish): " service_name
    if [ "$service_name" == "done" ]; then
        break
    elif echo "$running_services" | grep -qw "$service_name"; then
        harden_service "$service_name"
    else
        echo "Invalid service name. Please try again."
    fi
done

# Generate the after-hardening report
generate_report "after_hardening_report.txt"
echo "Linux hardening process completed. Reports generated: before_hardening_report.txt and after_hardening_report.txt."
