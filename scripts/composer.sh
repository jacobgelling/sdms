#!/bin/sh
# MIT License
# Copyright (c) 2023 Jacob Gelling

# Get PHP version function
sdms_php() {
    # Get latest PHP folder
    if [ -d "/etc/php" ]; then
        sdms_php="$(ls /etc/php | sort -nr | head -n1)"
    fi

    # Check php.ini files exist
    if [ ! -f "/etc/php/$sdms_php/fpm/php.ini" ] || [ ! -f "/etc/php/$sdms_php/cli/php.ini" ]; then
        echo "sdms could not find php" >&2
        exit 1
    fi
}

# Get PHP version
sdms_php

# Uninstall Composer from package manager
DEBIAN_FRONTEND=noninteractive apt-get -qy remove --purge composer

# Download Composer installer
curl -sS https://getcomposer.org/installer -o composer-setup.php

# Verify installer signature
EXPECTED_SIGNATURE="$(curl -sS https://composer.github.io/installer.sha384sum)"
ACTUAL_SIGNATURE="$(php -r "echo hash_file('sha384', 'composer-setup.php');")"
if [ "$EXPECTED_SIGNATURE" != "$ACTUAL_SIGNATURE *composer-setup.php" ]; then
    echo 'sdms could not validate installer signature' >&2
    rm composer-setup.php
    exit 1
fi

# If PHP is version 7.2.5 or newer install Composer 2.x, otherwise install Composer 2.2.x
if [ "$(printf '%s\n' "7.2.5" "$sdms_php" | sort -V | head -n1)" = "7.2.5" ]; then
    php composer-setup.php --install-dir=/usr/local/bin --filename=composer --2
else
    php composer-setup.php --install-dir=/usr/local/bin --filename=composer --2.2
fi

# Remove Composer installer
rm composer-setup.php

# Create Composer self update service and timer
cat <<EOF > /etc/systemd/system/composer-self-update.service
[Unit]
Description=Updates composer.phar to the latest version

[Service]
Type=oneshot
Environment=HOME=/root
ExecStart=composer self-update
EOF

cat <<EOF > /etc/systemd/system/composer-self-update.timer
[Unit]
Description=Updates composer.phar to the latest version

[Timer]
OnCalendar=*-*-* 6,18:00
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start Composer self update timer
systemctl daemon-reload
systemctl enable composer-self-update.timer
systemctl start composer-self-update.timer
