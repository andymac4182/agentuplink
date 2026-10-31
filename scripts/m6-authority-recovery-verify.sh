#!/usr/bin/env bash
set -euo pipefail
exec python3 "$(dirname "$0")/m6-authority-recovery-verify.py" "$@"
