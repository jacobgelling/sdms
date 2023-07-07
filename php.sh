#!/bin/sh
# MIT License
# Copyright (c) 2023 Jacob Gelling

curl -sSL https://packages.sury.org/php/README.txt | sudo bash -x
DEBIAN_FRONTEND=noninteractive apt-get -qy update
DEBIAN_FRONTEND=noninteractive apt-get -qy dist-upgrade
