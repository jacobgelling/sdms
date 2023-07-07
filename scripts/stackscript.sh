#!/bin/sh
# MIT License
# Copyright (c) 2019 Jacob Gelling

# Declare variables
# <UDF name="email" label="Email" />
# <UDF name="hostname" label="Hostname" />

# Update packages
DEBIAN_FRONTEND=noninteractive apt-get -qy update
DEBIAN_FRONTEND=noninteractive apt-get -qy dist-upgrade

# Install git
DEBIAN_FRONTEND=noninteractive apt-get -qy install git

# Download SDMS
git clone https://github.com/jacobgelling/sdms.git /opt/sdms

# Add executable permission
chmod +x /opt/sdms/*.sh /opt/sdms/scripts/*.sh

# Symlink executable inside /usr/local/sbin
ln -s /opt/sdms/sdms.sh /usr/local/sbin/sdms

# Deploy server
/opt/sdms/sdms.sh --deploy "$EMAIL" "$HOSTNAME"

# Delete stackscript
rm /root/StackScript
