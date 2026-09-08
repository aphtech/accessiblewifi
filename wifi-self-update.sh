#!/bin/bash
# place in ~/.local/bin
set -e
PID="$1"
URL="$2"
CACHE_DIR="/home/pi/.cache/accessiblewifi"
DEST="$CACHE_DIR/accessiblewifi-update.deb"

mkdir -p "$CACHE_DIR"
curl -fsSL "$URL" -o "$DEST"

while kill -0 "$PID" 2>/dev/null; do
    sleep 0.2
done

sudo /usr/local/bin/accessiblewifi-apt-install.sh

setsid iristyper >/dev/null 2>&1 &
