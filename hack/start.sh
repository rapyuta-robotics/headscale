#!/bin/sh
set -x

./acl_watcher.sh &

/usr/local/bin/headscale serve --config /etc/headscale/config.yaml