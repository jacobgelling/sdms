#!/bin/sh
# MIT License
# Copyright (c) 2019 Jacob Gelling

# Set NGINX real IP header
echo "real_ip_header CF-Connecting-IP;" > /etc/nginx/snippets/cloudflare.conf

# Get Cloudflare IPv4 address ranges
curl_result=$(curl -s https://www.cloudflare.com/ips-v4)
if [ $? -eq 0 ]; then
    echo "$curl_result" | sed 's/^/set_real_ip_from /; s/$/;/' >> /etc/nginx/snippets/cloudflare.conf
else
    echo "sdms failed to download Cloudflare IPv4 address ranges"
    exit 1
fi

# Get Cloudflare IPv6 address ranges
curl_result=$(curl -s https://www.cloudflare.com/ips-v6)
if [ $? -eq 0 ]; then
    echo "$curl_result" | sed 's/^/set_real_ip_from /; s/$/;/' >> /etc/nginx/snippets/cloudflare.conf
else
    echo "sdms failed to download Cloudflare IPv6 address ranges"
    exit 1
fi

# Include cloudflare.conf in nginx.conf within http block
if ! grep -q "include snippets/cloudflare.conf;" /etc/nginx/nginx.conf; then
    sed -i '/http {/a\\tinclude snippets/cloudflare.conf;' /etc/nginx/nginx.conf
fi

# Reload NGINX
systemctl reload nginx
