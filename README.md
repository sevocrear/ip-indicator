# vpn-indicator

VPN status, external IP and country in the GNOME top bar — with IP history and a warning
when your IP changes while the VPN is on.

```
VPN 🇳🇱 NL · 153.56.133.10        ← normal
⚠ VPN 🇩🇪 DE · 91.107.1.2         ← IP changed inside the VPN (3 min + notification)
off 🇷🇺 RU · 95.24.0.1             ← VPN is off
```

Click the indicator for the last 15 IPs (time, VPN on/off, country); clicking a row copies the IP.

## Install

Ubuntu / Debian with GNOME (X11 or Wayland):

```bash
sudo apt install python3-gi gir1.2-ayatanaappindicator3-0.1 libnotify-bin   # usually preinstalled on Ubuntu
git clone https://github.com/sevocrear/vpn-indicator.git && cd vpn-indicator
./install.sh
```

GNOME needs an AppIndicator extension to show tray icons. Ubuntu ships one enabled; on other distros install
[AppIndicator and KStatusNotifierItem Support](https://extensions.gnome.org/extension/615/appindicator-support/).
Also works on KDE, XFCE, Cinnamon, MATE and other desktops with a system tray.

Remove: `./uninstall.sh` (add `--purge` to delete the history).

## How it works

- **VPN on/off** — any *up* interface of link type `tun`/WireGuard (e.g. `FlClashX`, `Meta`, `tun0`,
  `wg0`, `sing-box`). This covers Clash/Mihomo/FlClash/Hiddify/v2rayN TUN mode, OpenVPN, WireGuard.
  Proxy-only (non-TUN) clients aren't detected as "on", but IP and country are still correct.
- **IP and country** — every 45 s from `ipinfo.io`, falling back to `ip-api.com` and `ifconfig.co`.
  The request follows your normal routing, so if your VPN rules send these domains direct, you'll see your real IP.
- **History** — `~/.local/share/vpn-indicator/history.jsonl`, one JSON line per change of IP or VPN state.

## Settings

Environment variables (put them into `Exec=` in `~/.config/autostart/vpn-indicator.desktop`,
e.g. `Exec=env VPN_INTERVAL=30 /home/you/.local/bin/vpn-indicator`):

| Variable | Default | Meaning |
|---|---|---|
| `VPN_IFACES` | auto | Comma-separated interfaces that mean "VPN on"; disables auto-detection |
| `VPN_IGNORE` | `tailscale*,zt*,docker*,virbr*,veth*` | Interfaces never treated as VPN (globs) |
| `VPN_INTERVAL` | `45` | Poll period, seconds |
| `VPN_HIGHLIGHT` | `180` | How long the "IP changed" warning stays, seconds |
| `VPN_LANG` | from `LANG` | `ru` or `en` |

## Development

```bash
python3 -m unittest discover -s tests
python3 vpn_indicator.py      # run from the checkout
```

---

### По-русски

Индикатор в верхней панели GNOME: VPN вкл/выкл, внешний IP, страна, история IP. Если при включённом VPN
IP сменился — значок ⚠ на 3 минуты и уведомление. Установка: `./install.sh`, удаление: `./uninstall.sh`.
Язык интерфейса берётся из системы (`VPN_LANG=ru|en`, чтобы задать явно).

## License

MIT
