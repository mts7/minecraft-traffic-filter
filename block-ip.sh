#!/bin/bash

# Ensure the script is run with sudo, as it modifies system files and controls pfctl.
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run as root. Please use 'sudo ./block_ip.sh <ip_address>'."
   exit 1
fi

ip=$1

# Basic validation for the IP address argument
if [ -z "$ip" ]; then
    echo "Usage: $0 <ip_address_or_subnet>"
    echo "Example: $0 1.2.3.4"
    echo "Example: $0 1.2.3.0/24"
    exit 1
fi

echo "Adding block rule for ${ip} to /etc/pf.conf..."
# Add the block rule to pf.conf
# Using `echo "block drop from ${ip} to any"` is correct for adding the rule.
# Appending directly to /etc/pf.conf
echo "block drop from ${ip} to any" >> /etc/pf.conf

# Add a newline for readability in pf.conf (optional, but good practice)
#echo "" >> /etc/pf.conf

echo "Reloading pfctl rules to apply the changes..."
# Reload the pf.conf file
sudo pfctl -f /etc/pf.conf

# Ensure pfctl is enabled (it might already be, but this ensures it)
sudo pfctl -E

echo "Block rule for ${ip} added and pfctl reloaded."
echo "You can verify with 'sudo pfctl -sr'."

sudo cat /etc/pf.conf

