#!/bin/sh
# MIT License
# Copyright (c) 2019 Jacob Gelling

# Exit when any command fails
set -e
trap 'echo "\"${BASH_COMMAND}\" failed with exit code $?."' EXIT

# Help function
sdms_help() {
    echo "sdms"
    echo "Usage: sdms --deploy email hostname"
    echo "       sdms --new domain"
    echo "       sdms --ssl domain"
    echo "       sdms --delete domain"
    echo "       sdms --backup"
}

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

# Password generation function
sdms_pass() {
    sdms_length=$1
    if [ -z "$sdms_length" ]; then
        sdms_length=16
    fi

    tr -dc 'a-zA-Z0-9-_!@#$%^&*\()_+{}|:<>?=' < /dev/urandom | head -c "${sdms_length}" | xargs
}

# Deploy function
sdms_deploy() {
    sdms_email="$1"
    sdms_hostname="$2"

    # Update and install packages
    DEBIAN_FRONTEND=noninteractive apt-get -qy update
    DEBIAN_FRONTEND=noninteractive apt-get -qy dist-upgrade
    DEBIAN_FRONTEND=noninteractive apt-get -qy install ca-certificates certbot composer curl git libnginx-mod-http-headers-more-filter libnginx-mod-http-uploadprogress mariadb-client mariadb-server nftables nginx php-cli php-curl php-fpm php-gd php-json php-mbstring php-mysql php-xml php-zip unattended-upgrades unzip wget zip

    # Set hostname
    hostnamectl set-hostname "$sdms_hostname"

    # Set timezone to UTC
    timedatectl set-timezone UTC

    # Enable unattended upgrades
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -plow unattended-upgrades

    # Configure git
    git config --global pull.rebase false

    # Disable extra version suffix in SSH banner
    if [ -f /etc/ssh/sshd_config ] && ! grep -q "DebianBanner" /etc/ssh/sshd_config; then
        {
            echo "" 
            echo "# Specifies whether the distribution-specified extra version suffix is"
            echo "# included during initial protocol handshake. The default is yes."
            echo "DebianBanner no"
        } >> "/etc/ssh/sshd_config"

        systemctl restart ssh.service
    fi

    # Configure nftables
    {
        echo '#!/usr/sbin/nft -f'
        echo 'flush ruleset'
        echo ''
        echo 'table inet filter {'
        echo '\tchain input {'
        echo '\t\ttype filter hook input priority 0;'
        echo ''
        echo '\t\t# Accept any localhost traffic'
        echo '\t\tiif lo accept'
        echo ''
        echo '\t\t# Accept traffic originated from us'
        echo '\t\tct state established,related accept'
        echo ''
        echo '\t\t# Accept SSH and web server traffic'
        echo '\t\ttcp dport { 22, 80, 443 } ct state new accept'
        echo ''
        echo '\t\t# Accept ICMP traffic'
        echo '\t\tip protocol icmp accept'
        echo '\t\tip6 nexthdr icmpv6 accept'
        echo ''
        echo '\t\t# Count and drop any other traffic'
        echo '\t\tcounter drop'
        echo '\t}'
        echo '}'
    } > /etc/nftables.conf
    nft -f /etc/nftables.conf
    systemctl enable nftables.service

    # Secure MariaDB server
    mariadb -e "DELETE FROM mysql.user WHERE User='';"
    mariadb -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    mariadb -e "DROP DATABASE IF EXISTS test;"
    mariadb -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
    mariadb -e "FLUSH PRIVILEGES;"

    # Generate Diffie–Hellman parameters
    touch /etc/nginx/dhparams.pem
    chmod o-r,o-w /etc/nginx/dhparams.pem
    openssl dhparam -out /etc/nginx/dhparams.pem 2048

    # Hide NGINX version
    if [ -f /etc/nginx/nginx.conf ]; then
        sed -i -e 's/# server_tokens off;/server_tokens off;\n\tmore_clear_headers Server;/g' /etc/nginx/nginx.conf

        # Enable gzip
        sed -i -e 's/# gzip on;/gzip on;/g' /etc/nginx/nginx.conf

        # Disable gzip for IE6
        sed -i -e 's/# gzip_disable "msie6";/gzip_disable "msie6";/g' /etc/nginx/nginx.conf

        # Enable gzip for proxies
        sed -i -e 's/# gzip_proxied any;/gzip_proxied any;/g' /etc/nginx/nginx.conf

        # Enable gzip vary
        sed -i -e 's/# gzip_vary on;/gzip_vary on;/g' /etc/nginx/nginx.conf

        # Increase gzip level
        sed -i -e 's/# gzip_comp_level/gzip_comp_level/g' /etc/nginx/nginx.conf

        # Set minimum gzip length
        sed -i -e 's/# gzip_types/gzip_min_length 256;\n\t# gzip_types/g' /etc/nginx/nginx.conf

        # Enable gzip for all applicable files
        sed -i -e 's/# gzip_types/gzip_types application\/vnd.ms-fontobject image\/svg+xml image\/x-icon text\/x-component/g' /etc/nginx/nginx.conf

        systemctl reload nginx.service
    else
        echo "sdms could not find /etc/nginx/nginx.conf" >&2
        exit 1
    fi

    # Create NGINX cache snippet
    {
        echo '# Cache the following file types for 1 month'
        echo 'location ~ \.(css|eot|gif|htc|ico|jpeg|jpg|js|otf|png|svg|ttf|woff|woff2)$ {'
        echo '\texpires 1M;'
        echo '\tlog_not_found off;'
        echo '}'
    } > /etc/nginx/snippets/cache.conf

    # Create NGINX SSL snippet
    {
        if [ "$(sed 's/\..*//' '/etc/debian_version')" -ge 10 ]; then
            echo 'ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;'
        else
            echo 'ssl_protocols TLSv1 TLSv1.1 TLSv1.2;'
        fi
        echo 'ssl_ciphers HIGH:!aNULL:!MD5;'
        echo 'ssl_prefer_server_ciphers on;'
        echo ''
        echo 'ssl_session_cache shared:SSL:10m;'
        echo 'ssl_session_timeout 2h;'
        echo ''
        echo 'ssl_stapling on;'
        echo 'ssl_stapling_verify on;'
        echo ''
        echo 'ssl_dhparam /etc/nginx/dhparams.pem;'
    } > /etc/nginx/snippets/ssl.conf

    # Create NGINX PHP snippet
    {
        echo '# Set max body size'
        echo 'client_max_body_size 38m;'
        echo ''
        echo '# Regex to split $uri to $fastcgi_script_name and $fastcgi_path'
        echo 'fastcgi_split_path_info ^(.+\.php)(/.+)$;'
        echo ''
        echo '# Check that the PHP script exists before passing it'
        echo 'try_files $fastcgi_script_name =404;'
        echo ''
        echo '# Bypass the fact that try_files resets $fastcgi_path_info'
        echo 'set $path_info $fastcgi_path_info;'
        echo 'fastcgi_param PATH_INFO $path_info;'
        echo ''
        echo 'fastcgi_index index.php;'
        echo 'include fastcgi.conf;'
    } > /etc/nginx/snippets/php.conf

    # Configure PHP
    sdms_php
    if [ -f "/etc/php/$sdms_php/cli/php.ini" ] && [ -f "/etc/php/$sdms_php/fpm/php.ini" ]; then
        # Hide version
        sed -i -e 's/expose_php = On/expose_php = Off/g' "/etc/php/$sdms_php/fpm/php.ini" "/etc/php/$sdms_php/cli/php.ini"

        # Set maximum file upload and post size
        sed -i -e 's/upload_max_filesize = 2M/upload_max_filesize = 32M/g' "/etc/php/$sdms_php/fpm/php.ini" "/etc/php/$sdms_php/cli/php.ini"
        sed -i -e 's/post_max_size = 8M/post_max_size = 38M/g' "/etc/php/$sdms_php/fpm/php.ini" "/etc/php/$sdms_php/cli/php.ini"

        # Hide PHP-FPM errors
        sed -i -e 's/display_errors = On/display_errors = Off/g' "/etc/php/$sdms_php/fpm/php.ini"

        # Enable strict sessions
        sed -i -e 's/session.use_strict_mode = 0/session.use_strict_mode = 1/g' "/etc/php/$sdms_php/fpm/php.ini" "/etc/php/$sdms_php/cli/php.ini"

        # Restart PHP-FPM
        systemctl restart "php$sdms_php-fpm.service"
    else
        echo "sdms could not find /etc/php/$sdms_php/cli/php.ini and /etc/php/$sdms_php/fpm/php.ini" >&2
        exit 1
    fi

    # Create www directory
    mkdir -p "/srv/www"

    # Register Let's Encrypt ACME account
    certbot register -m "$sdms_email" --agree-tos -n -q || certbot register -m "$sdms_email" --agree-tos -n -q --update-registration
}

# New domain function
sdms_new() {
    sdms_domain="$1"
    sdms_php

    # Get redirect domain
    if [ "${sdms_domain#www.}" != "${sdms_domain}" ]; then
        sdms_redirect_domain="${sdms_domain#www.}"
    else
        sdms_redirect_domain="www.$sdms_domain"
    fi

    # Create home variable
    sdms_home="/srv/www/$sdms_domain"

    # Check domain is not already added to server
    if [ -d "$sdms_home" ] || [ -d "/srv/www/$sdms_redirect_domain" ]; then
        echo "sdms found domain already exists" >&2
        exit 1
    fi

    # Create other variables
    sdms_username="$(echo "$sdms_domain" | sed -e 's/\./_/g' | head -c 32)"
    sdms_db_pass="$(sdms_pass 32)"

    # Create user
    adduser --system --home "$sdms_home" --group --gecos "" "$sdms_username"

    # Add www-data to group
    adduser www-data "$sdms_username"

    # Create required directories
    sudo -u "$sdms_username" mkdir "$sdms_home/sessions" "$sdms_home/tmp" "$sdms_home/root" "$sdms_home/root/public" "$sdms_home/.well-known" "$sdms_home/.ssh"
    chmod -R o-r,o-w,o-x "$sdms_home"

    # Create MariaDB database and user
    mariadb -e "CREATE DATABASE \`$sdms_username\`;"
    mariadb -e "GRANT ALL ON \`$sdms_username\`.* TO '$sdms_username'@'localhost' IDENTIFIED BY '$sdms_db_pass';"
    mariadb -e "FLUSH PRIVILEGES;"
    sudo -u "$sdms_username" touch "$sdms_home/.my.cnf"
    chmod o-r,o-w "$sdms_home/.my.cnf"
    {
        echo "[client]"
        echo "host=localhost"
        echo "user=$sdms_username"
        echo "password=$sdms_db_pass"
    } > "$sdms_home/.my.cnf"

    # Create PHP pool
    {
        echo "[$sdms_domain]"
        echo "user = $sdms_username"
        echo "group = $sdms_username"
        echo ""
        echo "listen = /run/php/$sdms_domain.sock"
        echo "listen.owner = www-data"
        echo "listen.group = www-data"
        echo "listen.allowed_clients = 127.0.0.1, ::1"
        echo ""
        echo "pm = ondemand"
        echo "pm.max_children = 5"
        echo ""
        echo "security.limit_extensions = .php"
        echo ""
        echo "env[HOSTNAME] = \$HOSTNAME"
        echo "env[PATH] = /usr/local/bin:/usr/bin:/bin"
        echo ""
        echo "php_admin_value[upload_tmp_dir] = $sdms_home/tmp"
        echo "env[TMP] = $sdms_home/tmp"
        echo "env[TMPDIR] = $sdms_home/tmp"
        echo "env[TEMP] = $sdms_home/tmp"
        echo ""
        echo "php_admin_value[session.save_path] = $sdms_home/sessions"
    } > "/etc/php/$sdms_php/fpm/pool.d/$sdms_domain.conf"

    # Disable default PHP-FPM pool
    if [ -f "/etc/php/$sdms_php/fpm/pool.d/www.conf" ]; then
        mv "/etc/php/$sdms_php/fpm/pool.d/www.conf" "/etc/php/$sdms_php/fpm/pool.d/www.conf.disabled"
    fi

    # Restart PHP-FPM
    systemctl restart "php$sdms_php-fpm.service"

    # Create NGINX config
    {
        echo "# Redirect $sdms_redirect_domain to $sdms_domain"
        echo "server {"
        echo "\tlisten 80;"
        echo "\tlisten [::]:80;"
        echo "\tserver_name $sdms_redirect_domain;"
        echo ""
        echo "\t# Allow ACME challenge validation by Let's Encrypt"
        echo "\tlocation ^~ /.well-known/acme-challenge/ {"
        echo "\t\troot $sdms_home;"
        echo "\t\tdefault_type text/plain;"
        echo "\t}"
        echo ""
        echo "\tlocation / {"
        echo "\t\treturn 301 http://$sdms_domain\$request_uri;"
        echo "\t}"
        echo "}"
        echo ""
        echo "# Serve website"
        echo "server {"
        echo "\tlisten 80;"
        echo "\tlisten [::]:80;"
        echo "\tserver_name $sdms_domain;"
        echo ""
        echo "\troot $sdms_home/root/public;"
        echo "\tindex index.php index.html;"
        echo ""
        echo "\tcharset utf-8;"
        echo "\tadd_header X-Content-Type-Options nosniff always;"
        echo ""
        echo "\tlocation / {"
        echo "\t\ttry_files \$uri \$uri/ /index.php\$is_args\$args;"
        echo "\t\t# try_files \$uri \$uri/ =404;"
        echo "\t}"
        echo ""
        echo "\t# Allow ACME challenge validation by Let's Encrypt"
        echo "\tlocation ^~ /.well-known/acme-challenge/ {"
        echo "\t\troot $sdms_home;"
        echo "\t\tdefault_type text/plain;"
        echo "\t}"
        echo ""
        echo "\t# Allow Git push to deploy"
        echo "\t# location ^~ /.git-webhooks/ {"
        echo "\t\t# root $sdms_home;"
        echo ""
        echo "\t\t# Execute .php files"
        echo "\t\t# location ~ \\.php\$ {"
        echo "\t\t\t# include snippets/php.conf;"
        echo "\t\t\t# fastcgi_pass unix:/run/php/$sdms_domain.sock;"
        echo "\t\t# }"
        echo "\t# }"
        echo ""
        echo "\t# Allow access to /.well-known/"
        echo "\tlocation ^~ /.well-known/ {}"
        echo ""
        echo "\t# Deny access to hidden files"
        echo "\tlocation ~ /\\. {"
        echo "\t\tdeny all;"
        echo "\t}"
        echo ""
        echo "\t# Execute .php files"
        echo "\tlocation ~ \\.php\$ {"
        echo "\t\tinclude snippets/php.conf;"
        echo "\t\tfastcgi_pass unix:/run/php/$sdms_domain.sock;"
        echo "\t}"
        echo ""
        echo "\t# Cache files"
        echo "\tinclude snippets/cache.conf;"
        echo "}"
    } > "/etc/nginx/sites-available/$sdms_domain"

    # Enable NGINX config
    ln -s "/etc/nginx/sites-available/$sdms_domain" "/etc/nginx/sites-enabled/$sdms_domain"

    # Restart NGINX
    systemctl restart nginx.service

    # Configure git
    sudo -u "$sdms_username" git config --global pull.rebase false
}

# SSL domain function
sdms_ssl() {
    sdms_domain="$1"

    # Get redirect domain
    if [ "${sdms_domain#www.}" != "${sdms_domain}" ]; then
        sdms_redirect_domain="${sdms_domain#www.}"
    else
        sdms_redirect_domain="www.$sdms_domain"
    fi

    # Create home variable
    sdms_home="/srv/www/$sdms_domain"

    # Check domain is added to server
    if [ ! -d "$sdms_home" ]; then
        echo "sdms domain does not exist" >&2
        exit 1
    fi

    # Generate SSL certificate
    certbot certonly --webroot -n -q --renew-hook "systemctl reload nginx.service" -w "$sdms_home" -d "$sdms_domain" -d "$sdms_redirect_domain"

    # Generate NGINX config
    {
        echo "# Redirect HTTP to HTTPS"
        echo "server {"
        echo "\tlisten 80;"
        echo "\tlisten [::]:80;"
        echo "\tserver_name $sdms_redirect_domain $sdms_domain;"
        echo ""
        echo "\t# Allow ACME challenge validation by Let's Encrypt"
        echo "\tlocation ^~ /.well-known/acme-challenge/ {"
        echo "\t\troot $sdms_home;"
        echo "\t\tdefault_type text/plain;"
        echo "\t}"
        echo ""
        echo "\tlocation / {"
        echo "\t\treturn 301 https://$sdms_domain\$request_uri;"
        echo "\t}"
        echo "}"
        echo ""
        echo "# Redirect $sdms_redirect_domain to $sdms_domain"
        echo "server {"
        echo "\tlisten 443 ssl http2;"
        echo "\tlisten [::]:443 ssl http2;"
        echo "\tserver_name $sdms_redirect_domain;"
        echo ""
        echo "\tssl_certificate /etc/letsencrypt/live/$sdms_domain/fullchain.pem;"
        echo "\tssl_trusted_certificate /etc/letsencrypt/live/$sdms_domain/chain.pem;"
        echo "\tssl_certificate_key /etc/letsencrypt/live/$sdms_domain/privkey.pem;"
        echo "\t# add_header Strict-Transport-Security max-age=31536000 always;"
        echo "\t# add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
        echo "\t# add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;"
        echo "\tinclude snippets/ssl.conf;"
        echo ""
        echo "\t# Allow ACME challenge validation by Let's Encrypt"
        echo "\tlocation ^~ /.well-known/acme-challenge/ {"
        echo "\t\troot $sdms_home;"
        echo "\t\tdefault_type text/plain;"
        echo "\t}"
        echo ""
        echo "\tlocation / {"
        echo "\t\treturn 301 https://$sdms_domain\$request_uri;"
        echo "\t}"
        echo "}"
        echo ""
        echo "# Serve website"
        echo "server {"
        echo "\tlisten 443 ssl http2;"
        echo "\tlisten [::]:443 ssl http2;"
        echo "\tserver_name $sdms_domain;"
        echo ""
        echo "\tssl_certificate /etc/letsencrypt/live/$sdms_domain/fullchain.pem;"
        echo "\tssl_trusted_certificate /etc/letsencrypt/live/$sdms_domain/chain.pem;"
        echo "\tssl_certificate_key /etc/letsencrypt/live/$sdms_domain/privkey.pem;"
        echo "\t# add_header Strict-Transport-Security max-age=31536000 always;"
        echo "\t# add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
        echo "\t# add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;"
        echo "\tinclude snippets/ssl.conf;"
        echo ""
        echo "\troot $sdms_home/root/public;"
        echo "\tindex index.php index.html;"
        echo ""
        echo "\tcharset utf-8;"
        echo "\tadd_header X-Content-Type-Options nosniff always;"
        echo ""
        echo "\tlocation / {"
        echo "\t\ttry_files \$uri \$uri/ /index.php\$is_args\$args;"
        echo "\t\t# try_files \$uri \$uri/ =404;"
        echo "\t}"
        echo ""
        echo "\t# Allow ACME challenge validation by Let's Encrypt"
        echo "\tlocation ^~ /.well-known/acme-challenge/ {"
        echo "\t\troot $sdms_home;"
        echo "\t\tdefault_type text/plain;"
        echo "\t}"
        echo ""
        echo "\t# Allow Git push to deploy"
        echo "\t# location ^~ /.git-webhooks/ {"
        echo "\t\t# root $sdms_home;"
        echo ""
        echo "\t\t# Execute .php files"
        echo "\t\t# location ~ \\.php\$ {"
        echo "\t\t\t# include snippets/php.conf;"
        echo "\t\t\t# fastcgi_pass unix:/run/php/$sdms_domain.sock;"
        echo "\t\t# }"
        echo "\t# }"
        echo ""
        echo "\t# Allow access to /.well-known/"
        echo "\tlocation ^~ /.well-known/ {}"
        echo ""
        echo "\t# Deny access to hidden files"
        echo "\tlocation ~ /\\. {"
        echo "\t\tdeny all;"
        echo "\t}"
        echo ""
        echo "\t# Execute .php files"
        echo "\tlocation ~ \\.php\$ {"
        echo "\t\tinclude snippets/php.conf;"
        echo "\t\tfastcgi_pass unix:/run/php/$sdms_domain.sock;"
        echo "\t}"
        echo ""
        echo "\t# Cache files"
        echo "\tinclude snippets/cache.conf;"
        echo "}"
    } > "/etc/nginx/sites-available/$sdms_domain"

    # Reload NGINX
    systemctl reload nginx.service
}

# Delete domain function
sdms_delete() {
    sdms_domain="$1"
    sdms_php

    # Create home variable
    sdms_home="/srv/www/$sdms_domain"

    # Check domain is added to server
    if [ ! -d "$sdms_home" ]; then
        echo "sdms domain does not exist" >&2
        exit 1
    fi

    # Disable NGINX config
    rm -f "/etc/nginx/sites-enabled/$sdms_domain"

    # Create username variable
    sdms_username="$(echo "$sdms_domain" | sed -e 's/\./_/g' | head -c 32)"

    # Remove www-data from group
    deluser www-data "$sdms_username"

    # Restart NGINX
    systemctl restart nginx.service

    # Delete PHP pool
    rm -f "/etc/php/$sdms_php/fpm/pool.d/$sdms_domain.conf"

    # Restart PHP-FPM
    systemctl restart "php$sdms_php-fpm.service"

    # Delete NGINX config
    rm -f "/etc/nginx/sites-available/$sdms_domain"

    # Delete MariaDB database and user
    mariadb -e "DROP DATABASE IF EXISTS \`$sdms_username\`;"
    mariadb -e "DROP USER IF EXISTS '$sdms_username'@'localhost';"
    mariadb -e "FLUSH PRIVILEGES;"

    # Delete user
    userdel -r "$sdms_username"

    # Delete SSL certificate
    certbot delete -n -q --cert-name "$sdms_domain"
}

# Backup server function
sdms_backup() {
    sdms_php
    sdms_time_backup="$(date +'%Y-%m-%d_%H%M')"

    # Dump databases
    mysqldump --all-databases | gzip -c > "sdms-backup-$sdms_time_backup.sql.gz"

    # Backup files, excluding temporary files
    tar --exclude="/srv/www/*/tmp/*" --exclude="/srv/www/*/sessions/*" --exclude="/srv/www/*/.well-known/acme-challenge/*" --exclude="/srv/www/*/root/storage/logs/*" -zcvf "sdms-backup-$sdms_time_backup.tar.gz" "/etc/letsencrypt" "/etc/nginx" "/etc/php/$sdms_php/cli" "/etc/php/$sdms_php/fpm" "/srv/www" "/etc/nftables.conf"
}

# Ensure script is running as root
if [ "$(id -u)" != "0" ]; then
    echo "sdms must be run as root" >&2
    exit 1
fi

# Ensure script is running on Debian 9 or later
if [ ! -f '/etc/debian_version' ] || [ "$(sed 's/\..*//' '/etc/debian_version')" -lt 9 ]; then
    echo "sdms must be run on Debian 9 or later" >&2
    exit 1
fi

# Parse CLI parameters and call respective functions
if [ -z "$1" ]; then
    sdms_help
    exit 1
fi
while test -n "$1"; do
    case "$1" in
        --deploy)
        if [ -z "$3" ] || [ ! -z "$4" ]; then
            echo "Usage: sdms --deploy email hostname" >&2
            exit 1
        fi
        sdms_deploy "$2" "$3"
        break
        ;;
        -n|--new)
        if [ -z "$2" ]; then
            echo "Usage: sdms --new domain..." >&2
            exit 1
        fi
        sdms_new "$2"
        break
        ;;
        -s|--ssl)
        if [ -z "$2" ]; then
            echo "Usage: sdms --ssl domain..." >&2
            exit 1
        fi
        sdms_ssl "$2"
        break
        ;;
        -d|--delete)
        if [ -z "$2" ]; then
            echo "Usage: sdms --delete domain..." >&2
            exit 1
        fi
        sdms_delete "$2"
        break
        ;;
        -b|--backup)
        sdms_backup
        break
        ;;
        -h|--help)
        sdms_help
        exit 0
        ;;
        *)
        sdms_help
        exit 1
        ;;
    esac
done
