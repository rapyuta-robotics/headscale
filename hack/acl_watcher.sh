#!/bin/sh
set -x

inotifywait --event moved_to --recursive --monitor /acl |
while read -r
do
    echo "$(date +%s) noticed acl update; triggered reload"
    killall -s SIGHUP headscale
done