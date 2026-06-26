#!/usr/bin/env bash
# Removes the WebUp nftables table, restoring normal (unfiltered) input.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "must run as root" >&2; exit 1; fi
nft delete table inet webup 2>/dev/null || true
echo "webup nftables ruleset removed."
