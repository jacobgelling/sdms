#!/bin/sh
# MIT License
# Copyright (c) 2019 Jacob Gelling

# Enable default SSL listener
DEBIAN_FRONTEND=noninteractive apt-get -qy update
DEBIAN_FRONTEND=noninteractive apt-get -qy install ssl-cert
sed -i -e 's/# listen 443 ssl default_server;/listen 443 ssl default_server;/g' /etc/nginx/sites-available/default
sed -i -e 's/# listen [::]:443 ssl default_server;/listen [::]:443 ssl default_server;/g' /etc/nginx/sites-available/default
sed -i -e 's/# include snippets/snakeoil.conf;/include snippets/snakeoil.conf;/g' /etc/nginx/sites-available/default
