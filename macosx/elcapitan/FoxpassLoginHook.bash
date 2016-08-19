#!/bin/bash

if [ ! -z "$1" ] && [ ! -d /Users/$1 ]; then
  mkdir -p /Users/$1
  chown $1:staff /Users/$1
fi
