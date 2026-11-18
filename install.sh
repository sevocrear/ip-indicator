#!/usr/bin/env bash
# Installs vpn-indicator for the current user: copies the script to ~/.local/bin,
# adds a GNOME autostart entry and starts the indicator. Safe to re-run (upgrades in place).
# Usage: ./install.sh
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)/vpn_indicator.py"
BIN="$HOME/.local/bin/vpn-indicator"
AUTOSTART="$HOME/.config/autostart/vpn-indicator.desktop"

# Dependencies: GTK3 + AppIndicator bindings for Python, notify-send.
if ! python3 -c "import gi; gi.require_version('Gtk','3.0'); gi.require_version('AyatanaAppIndicator3','0.1')" 2>/dev/null \
   && ! python3 -c "import gi; gi.require_version('Gtk','3.0'); gi.require_version('AppIndicator3','0.1')" 2>/dev/null; then
  echo "Missing Python AppIndicator bindings. On Ubuntu/Debian:"
  echo "  sudo apt install python3-gi gir1.2-ayatanaappindicator3-0.1 libnotify-bin"
  exit 1
fi

# GNOME hides tray icons without this extension (Ubuntu ships it enabled).
if command -v gnome-extensions >/dev/null && ! gnome-extensions list --enabled 2>/dev/null | grep -q appindicator; then
  echo "Warning: no AppIndicator extension is enabled in GNOME Shell — the indicator won't be visible."
  echo "  Ubuntu: gnome-extensions enable ubuntu-appindicators@ubuntu.com"
  echo "  Other:  install 'AppIndicator and KStatusNotifierItem Support' from extensions.gnome.org"
fi

install -Dm755 "$SRC" "$BIN"
mkdir -p "$(dirname "$AUTOSTART")"
cat > "$AUTOSTART" <<EOF
[Desktop Entry]
Type=Application
Name=VPN Indicator
Comment=VPN status, external IP and country in the top bar
Exec=$BIN
Icon=network-vpn
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=5
EOF

pkill -f "vpn-indicator(\.py)?$" 2>/dev/null || true
nohup "$BIN" >/dev/null 2>&1 &
echo "Installed: $BIN (autostart: $AUTOSTART). The indicator is running."
