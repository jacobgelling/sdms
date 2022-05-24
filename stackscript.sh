#!/bin/sh
# MIT License
# Copyright (c) 2019 Jacob Gelling

# Declare variables
# <UDF name="email" />
# <UDF name="hostname" />

# Update packages
apt-get -y update
apt-get -y dist-upgrade

# Install git
apt-get -y install git

# Download SDMS
git clone https://github.com/jacobgelling/sdms.git /root/sdms

# Add executable permission
chmod +x /root/sdms/sdms.sh

# Symlink to executable
ln -s /root/sdms/sdms.sh /root/bin/sdms

# Deploy server
/root/sdms/sdms.sh --deploy "$EMAIL" "$HOSTNAME"
