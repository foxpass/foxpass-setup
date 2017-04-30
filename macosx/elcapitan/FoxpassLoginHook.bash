#!/bin/bash
LOGFILE=/var/log/loginhook.log
echo "$(date) Login hook exected for user $1" >> $LOGFILE

if [ ! -z "$1" ] && [ ! -d /Users/$1 ]; then
  echo "$(date) Adding user $1" >> $LOGFILE
  mkdir -p /Users/$1
  chown $1:staff /Users/$1
fi
