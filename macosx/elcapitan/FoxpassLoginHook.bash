#!/bin/bash
LOGFILE=/var/log/loginhook.log
echo "$(date) Login hook executed for user $1" >> $LOGFILE

if [ ! -z "$1" ] && [ "_mbsetupuser" != "$1" ] && [ ! -d /Users/$1 ]; then
  echo "$(date) Adding user $1" >> $LOGFILE
  mkdir -p /Users/$1
  /usr/sbin/chown $1:staff /Users/$1
  /System/Library/CoreServices/ManagedClient.app/Contents/Resources/createmobileaccount -n $1 -v >> $LOGFILE
fi
