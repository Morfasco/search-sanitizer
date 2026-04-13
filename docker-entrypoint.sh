#!/bin/sh
set -euo pipefail

mkdir -p "${XDG_CACHE_HOME:-/home/agent/.cache}/fontconfig"
mkdir -p /tmp/search-ocr

exec "$@"
