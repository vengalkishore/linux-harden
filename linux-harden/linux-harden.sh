#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root"
   exit 1
fi

# Function to generate a report
generate_report() {
    local report_file=$1
    echo "Generating report: $report_file"
    echo "Date: $(date)" > $report_file
    echo "Hostname: $(hostname)" >> $report_file
    echo "Uptime: $(uptime -p)" >> $report_file
    echo "Running services:" >> $report_file
    systemctl list-units --type=service --state=running --no-pager --no-legend >> $report_file
    echo "UFW status:" >> $report_file
    ufw status verbose >> $report_file
    echo "Fail2ban status:" >> $report_file
    fail2ban-client status >> $report_file
    echo "AppArmor status:" >> $report_file
    apparmor_status >> $report_file
    echo "Sysctl settings:" >> $report_file
    sysctl -a >> $report_file
}

# Generate the before report
generate_report "before_hardening_report.txt"

# Update and upgrade system packages
echo "Updating and upgrading system packages..."
apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y

# Add a new user and grant sudo access
echo "Creating a new user..."
read -p "Enter the new username: " newuser
adduser $newuser
usermod -aG sudo $newuser

# Disable root login via SSH
echo "Disabling root login via SSH..."
sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# Setup SSH key-based authentication
echo "Setting up SSH key-based authentication..."
mkdir -p /home/$newuser/.ssh
read -p "Paste the public SSH key for the new user: " sshkey
echo $sshkey > /home/$newuser/.ssh/authorized_keys
chown -R $newuser:$newuser /home/$newuser/.ssh
chmod 600 /home/$newuser/.ssh/authorized_keys
chmod 700 /home/$newuser/.ssh

# Disable password authentication
echo "Disabling password authentication..."
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

# Change the default SSH port
echo "Changing the default SSH port..."
read -p "Enter the new SSH port: " sshport
sed -i "s/#Port 22/Port $sshport/" /etc/ssh/sshd_config
ufw allow $sshport/tcp
systemctl restart sshd
# Install and configure UFW
echo "Installing and configuring UFW..."
apt install ufw -y
ufw default deny incoming
ufw default allow outgoing
ufw allow $sshport/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

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
# configure system logging
echo "Configuring system logging..."
apt install rsyslog -y
systemctl enable rsyslog
systemctl start rsyslog
# Secure shared memory
echo "Securing shared memory..."
echo "tmpfs /tmp tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
# enable automatic security updates
echo "Enabling automatic security updates..."
apt install unattended-upgrades -y
dpkg-reconfigure --priority=low unattended-upgrades
# Install and configure AppArmor.
echo "Installing and configuring AppArmor..."
apt install apparmor apparmor-profiles -y
systemctl enable apparmor
systemctl start apparmor
# install and configure logwatch.
echo "Installing and configuring logwatch..."
apt install logwatch -y
logwatch --detail high --mailto your-email@example.com --range 'between -7 days and today'

# secure network configuration
echo "Securing network configuration..."
echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
sysctl -p
# function  to harden specific services
harden_service() {
    local service_name=$1

    case $service_name in
        ssh.service)
            echo "Applying additional hardening to SSH..."
            # SSH hardening steps already applied above
            ;;
        apache2.service)
            echo "Applying hardening to Apache..."
            # Sample Apache hardening
            apt install libapache2-mod-security2 -y
            a2enmod security2
            echo "ServerTokens Prod" >> /etc/apache2/conf-available/security.conf
            echo "ServerSignature Off" >> /etc/apache2/conf-available/security.conf
            systemctl restart apache2
            ;;
        mysql.service)
            echo "Applying hardening to MySQL..."
            # Sample MySQL hardening
            mysql_secure_installation
            ;;
        *)
            echo "No specific hardening steps for $service_name"
            ;;
    esac
}
echo "Available running services:"
running_services=$(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}')
select_service() {
    echo "$running_services"
    read -p "Enter the name of the service to harden (or 'done' to finish): " service_name
    if [ "$service_name" == "done" ]; then
        return 1
    elif echo "$running_services" | grep -qw "$service_name"; then
        harden_service $service_name
    else
        echo "Invalid service name. Please try again."
    fi
    return 0
}

while true; do
    select_service || break
done
#generate the report
generate_report "after_hardening_report.txt"
echo "Linux hardening process completed. Reports generated: before_hardening_report.txt and after_hardening_report.txt"
