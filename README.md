# SDMS
A simple LEMP (Linux, NGINX, MariaDB, PHP) server deployment and management script for Debian 9 (Stretch) and 10 (Buster). Intended for virtual hosting environments, this script enables the automated creation and removal of domains in the LEMP stack.

There are no user repository or compilation requirements, solely using packages provided and maintained by Debian for ease of upgrade and security.

The script is made available under the MIT licence.

## Features

* Server hardening
  * nftables firewall
  * Unattended upgrades
  * Diffie-Hellman parameters generation
  * Banner removal
* NGINX and PHP-FPM virtual host management
  * Add domain
  * Remove domain
  * Let's Encrypt SSL
* Backup of databases, SSL certificates, website files and configuartion files

## Usage
### Deploy server
```sh
$ script.sh --deploy email hostname
```
The `--deploy` option is intended to be run on a fresh installation, installing required packages and performing initial setup.

The email is used for the Let's Encrypt account. The hostname should be a fully qualified domain name.

### New domain
```sh
$ script.sh --new domain
```
The `--new` option creates a full LEMP virtual host for the given domain, which includes a web directory in `/srv/www`, a database, and a PHP-FPM pool.

### Generate SSL
```sh
$ script.sh --ssl domain
```
The `--ssl` option uses Let's Encrypt to generate a SSL certificate for the given domain and produces a relevant NGINX configuration file. Please note this overwrites the current configuration file for the domain.

### Delete domain
```sh
$ script.sh --delete domain
```
The `--delete` option simply deletes the given domain, including it's web directory, database, relevant configuration files, and SSL certificates.

### Backup

```sh
$ script.sh --backup
```
The `--backup` option performs a dump of all databases, and a backup of all relevant website and configuration files.