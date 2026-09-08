#!/bin/bash
# place at /usr/local/bin and set to chmod +x
set -e
DEB="/home/pi/.cache/accessiblewifi/accessiblewifi-update.deb"
if [ ! -f "$DEB" ]; then
    echo "Update file not found: $DEB" >&2
    exit 1
fi
apt-get install -y "$DEB"
