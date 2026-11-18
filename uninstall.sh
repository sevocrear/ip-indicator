#!/usr/bin/env bash
# Stops vpn-indicator and removes it with its autostart entry.
# IP history (~/.local/share/vpn-indicator) is kept unless you pass --purge.
set -euo pipefail

pkill -f "vpn-indicator(\.py)?$" 2>/dev/null || true
rm -f "$HOME/.local/bin/vpn-indicator" "$HOME/.config/autostart/vpn-indicator.desktop"
if [[ "${1:-}" == "--purge" ]]; then
  rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/vpn-indicator"
  echo "Removed, history purged."
else
  echo "Removed. History kept in ${XDG_DATA_HOME:-$HOME/.local/share}/vpn-indicator (use --purge to delete)."
fi
