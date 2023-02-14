#!/bin/sh
# MIT License
# Copyright (c) 2019 Jacob Gelling

# Enable automatic reboot for unattended upgrade
sed -i -e 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|g' "/etc/apt/apt.conf.d/50unattended-upgrades"
