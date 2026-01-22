#!/bin/bash
# Simple wrapper to run verification
cd "$(dirname "$0")"
node instant-verify.js
exit $?
