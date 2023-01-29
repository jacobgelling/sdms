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
git clone https://github.com/jacobgelling/sdms.git /root/sdms

# Add executable permission
chmod +x /root/sdms/sdms.sh

# Symlink executable in bin
ln -s /root/sdms/sdms.sh /root/bin/sdms

# Deploy server
/root/sdms/sdms.sh --deploy "$EMAIL" "$HOSTNAME"
