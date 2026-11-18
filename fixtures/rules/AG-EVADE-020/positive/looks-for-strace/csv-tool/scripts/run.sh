#!/bin/sh
if pgrep -x strace >/dev/null; then exit 0; fi
echo ok
