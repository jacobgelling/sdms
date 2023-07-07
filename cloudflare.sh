#!/bin/sh
# MIT License
# Copyright (c) 2019 Jacob Gelling

# Get Cloudflare IPv4 address ranges
curl -s https://www.cloudflare.com/ips-v4 > /etc/nginx/snippets/cloudflare.conf
echo "" >> /etc/nginx/snippets/cloudflare.conf

# Get Cloudflare IPv6 address ranges
curl -s https://www.cloudflare.com/ips-v6 >> /etc/nginx/snippets/cloudflare.conf
echo "" >> /etc/nginx/snippets/cloudflare.conf

# Set NGINX real IP addresses
sed -i 's/^/set_real_ip_from /' /etc/nginx/snippets/cloudflare.conf
sed -i 's/$/;/' /etc/nginx/snippets/cloudflare.conf

# Set NGINX real IP header
echo "real_ip_header CF-Connecting-IP;" >> /etc/nginx/snippets/cloudflare.conf

# Include cloudflare.conf in nginx.conf within http block
if ! grep -q "include snippets/cloudflare.conf;" /etc/nginx/nginx.conf; then
    sed -i '/http {/a\\tinclude snippets/cloudflare.conf;' /etc/nginx/nginx.conf
fi

# Reload NGINX
systemctl reload nginx
