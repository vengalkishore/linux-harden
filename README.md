#How To Run 

- 1.git clone https://github.com/vengalkishore/linux-harden.git.
- 2.cd linux-harden.
- 3.chmod +x linux-harden.sh.
- 4.sudo ./linux-harden.

# Linux Hardening Script

This repository contains a bash script to harden a Linux system. The script performs various hardening steps such as updating system packages, configuring SSH, setting up a firewall, and hardening specific services. It also generates reports before and after the hardening process.

## Features

- System package updates and upgrades
- User creation and SSH key-based authentication setup
- Disable root login and password authentication via SSH
- Change default SSH port
- Install and configure UFW (Uncomplicated Firewall)
- Install and configure Fail2ban
- Secure shared memory
- Enable automatic security updates
- Install and configure AppArmor
- Install and configure Logwatch
- Secure network configuration
- Service-specific hardening (SSH, Apache, MySQL)
- Generate reports before and after hardening

## Usage

### Prerequisites

- The script must be run as root or with sudo privileges.
- Ensure you have a backup of your system before running the script.
