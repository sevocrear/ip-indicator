#!/usr/bin/env python3
"""
vpn-indicator — VPN status, external IP and country in the GNOME top bar (AppIndicator).

Shows:
  * VPN on/off — on when a TUN/WireGuard interface is up (auto-detected, or VPN_IFACES);
  * external IP and country (flag + ISO code);
  * IP history in the menu, persisted to ~/.local/share/vpn-indicator/history.jsonl.

If the external IP changes while the VPN stays on, the icon turns into a warning, the label
gets a «⚠» prefix and a desktop notification is sent. The highlight lasts VPN_HIGHLIGHT
seconds or until «Clear highlight» is clicked.

Run:   python3 vpn_indicator.py        (install.sh sets up autostart)
Env:
  VPN_IFACES     comma-separated interface names treated as VPN; disables auto-detection
  VPN_IGNORE     comma-separated names (fnmatch globs) never treated as VPN
                 (default: tailscale*,zt*,docker*,virbr*,veth*)
  VPN_INTERVAL   poll period, seconds (default 45)
  VPN_HIGHLIGHT  how long the "IP changed" highlight lasts, seconds (default 180)
  VPN_LANG       ru|en, UI language (default: from LANG)
"""
import fnmatch
import json
import os
import subprocess
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

SYS_NET = Path("/sys/class/net")
ARPHRD_NONE = 65534  # link type of tun and wireguard devices
IFF_UP = 0x1

DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "vpn-indicator"
HISTORY_FILE = DATA_DIR / "history.jsonl"
HISTORY_IN_MENU = 15


def _csv(value):
    return [s.strip() for s in (value or "").split(",") if s.strip()]


# Several providers: if one is down or rate-limits us, the next one answers.
GEO_SOURCES = [
    ("https://ipinfo.io/json", lambda d: (d.get("ip"), d.get("country"), d.get("city"))),
    ("http://ip-api.com/json/?fields=query,countryCode,city",
     lambda d: (d.get("query"), d.get("countryCode"), d.get("city"))),
    ("https://ifconfig.co/json", lambda d: (d.get("ip"), d.get("country_iso"), d.get("city"))),
]

TEXTS = {
    "en": {
        "checking": "Checking…", "on": "on", "off": "off", "no_net": "no network",
        "history": "IP history:", "empty": "(empty)", "refresh": "Refresh now",
        "clear": "Clear highlight", "open": "Open history file", "quit": "Quit",
        "ip_changed": "VPN IP changed", "vpn_on": "VPN connected", "vpn_off": "VPN disconnected",
    },
    "ru": {
        "checking": "Проверка…", "on": "включён", "off": "выключен", "no_net": "нет сети",
        "history": "История IP:", "empty": "(пусто)", "refresh": "Обновить сейчас",
        "clear": "Сбросить подсветку", "open": "Открыть файл истории", "quit": "Выход",
        "ip_changed": "IP в VPN сменился", "vpn_on": "VPN включён", "vpn_off": "VPN выключен",
    },
}


def pick_lang(env=os.environ):
    lang = (env.get("VPN_LANG") or env.get("LANGUAGE") or env.get("LANG") or "en")[:2].lower()
    return lang if lang in TEXTS else "en"


# --- pure logic (covered by tests) -------------------------------------------

def flag(cc):
    """ISO country code → flag emoji (NL → 🇳🇱)."""
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🏳"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())


def find_vpn_iface(sys_net=SYS_NET, names=None, ignore=None):
    """Name of an UP VPN interface, or None.

    With explicit `names` only those are checked. Otherwise any interface whose link
    type is ARPHRD_NONE (tun, wireguard — what Clash/Mihomo/sing-box/Xray TUN mode,
    OpenVPN and WireGuard create) counts, except names matching `ignore`.
    TUN devices often report operstate "unknown", so we check IFF_UP in flags instead.
    """
    ignore = ignore or []
    candidates = names if names else sorted(p.name for p in sys_net.iterdir()) if sys_net.exists() else []
    for name in candidates:
        d = sys_net / name
        if not d.exists() or any(fnmatch.fnmatch(name, pat) for pat in ignore):
            continue
        try:
            if not names and int((d / "type").read_text()) != ARPHRD_NONE:
                continue
            if int((d / "flags").read_text(), 16) & IFF_UP:
                return name
        except (OSError, ValueError):
            continue
    return None


def classify(last, vpn, ip):
    """What a new observation means compared to the last history entry.

    Returns (record, event): record — whether to append to history;
    event — None | "ip_changed" (VPN stayed on, IP differs) | "vpn_on" | "vpn_off".
    """
    if last is None:
        return True, None
    if last.get("ip") == ip and bool(last.get("vpn")) == vpn:
        return False, None
    if vpn and last.get("vpn") and last.get("ip") != ip:
        return True, "ip_changed"
    if bool(last.get("vpn")) != vpn:
        return True, "vpn_on" if vpn else "vpn_off"
    return True, None


def format_label(vpn, ip, cc, t, highlight=False):
    if ip is None:
        label = ("VPN" if vpn else "—") + " · " + t["no_net"]
    else:
        label = f"{'VPN' if vpn else 'off'} {flag(cc)} {cc} · {ip}"
    return ("⚠ " + label) if highlight else label


def format_history_row(e):
    ts = (e.get("ts") or "")[5:16].replace("T", " ")
    return f"{ts}   {'VPN' if e.get('vpn') else 'off'}  {flag(e.get('cc'))} {e.get('cc')}  {e.get('ip')}"


def load_history(path=HISTORY_FILE):
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def append_history(entry, path=HISTORY_FILE):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# --- side effects ------------------------------------------------------------

def fetch_geo():
    """(ip, country, city) or None if every provider failed."""
    for url, parse in GEO_SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vpn-indicator", "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as r:
                ip, cc, city = parse(json.load(r))
            if ip:
                return ip, (cc or "??").upper(), city or ""
        except Exception:
            continue
    return None


def notify(title, body):
    try:
        subprocess.Popen(["notify-send", "-a", "vpn-indicator", "-i", "network-vpn", title, body])
    except OSError:
        pass


def run():
    import gi

    gi.require_version("Gtk", "3.0")
    try:
        gi.require_version("AyatanaAppIndicator3", "0.1")
        from gi.repository import AyatanaAppIndicator3 as AppIndicator
    except (ValueError, ImportError):
        gi.require_version("AppIndicator3", "0.1")
        from gi.repository import AppIndicator3 as AppIndicator
    from gi.repository import Gdk, GLib, Gtk

    names = _csv(os.environ.get("VPN_IFACES"))
    ignore = _csv(os.environ.get("VPN_IGNORE", "tailscale*,zt*,docker*,virbr*,veth*"))
    interval = int(os.environ.get("VPN_INTERVAL", "45"))
    highlight_s = int(os.environ.get("VPN_HIGHLIGHT", "180"))
    t = TEXTS[pick_lang()]

    class Indicator:
        def __init__(self):
            self.ind = AppIndicator.Indicator.new(
                "vpn-indicator", "network-vpn-symbolic", AppIndicator.IndicatorCategory.SYSTEM_SERVICES)
            self.ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)
            self.history = load_history()
            self.state = None
            self.highlight_until = 0
            self.busy = False
            self.ind.set_label("…", "")
            self.build_menu()
            self.refresh()
            GLib.timeout_add_seconds(interval, self.refresh)
            GLib.timeout_add_seconds(5, self.tick)

        def refresh(self, *_):
            if not self.busy:
                self.busy = True
                threading.Thread(target=self._worker, daemon=True).start()
            return True

        def _worker(self):
            iface = find_vpn_iface(names=names, ignore=ignore)
            geo = fetch_geo()
            GLib.idle_add(self._apply, iface, geo)

        def _apply(self, iface, geo):
            self.busy = False
            vpn = iface is not None
            if geo is None:
                self.state = {"vpn": vpn, "ip": None, "cc": None, "city": ""}
                self.render()
                return False
            ip, cc, city = geo
            self.state = {"vpn": vpn, "ip": ip, "cc": cc, "city": city}
            last = self.history[-1] if self.history else None
            record, event = classify(last, vpn, ip)
            if record:
                entry = {"ts": datetime.now().isoformat(timespec="seconds"), "ip": ip, "cc": cc,
                         "city": city, "vpn": vpn, "iface": iface}
                self.history.append(entry)
                append_history(entry)
            if event == "ip_changed":
                self.highlight_until = time.time() + highlight_s
                notify(t["ip_changed"], f"{last.get('ip')} ({last.get('cc')}) → {ip} ({cc})")
            elif event:
                notify(t[event], f"{flag(cc)} {cc} · {ip}")
            self.render()
            return False

        def tick(self):
            if self.highlight_until and time.time() > self.highlight_until:
                self.highlight_until = 0
                self.render()
            return True

        def render(self):
            s = self.state or {}
            hl = time.time() < self.highlight_until
            label = format_label(s.get("vpn"), s.get("ip"), s.get("cc"), t, hl)
            if hl:
                icon = "dialog-warning-symbolic"
            elif s.get("ip") is None:
                icon = "network-offline-symbolic"
            else:
                icon = "network-vpn-symbolic" if s["vpn"] else "network-vpn-disconnected-symbolic"
            self.ind.set_icon_full(icon, label)
            self.ind.set_label(label, "")
            self.build_menu()

        def _item(self, menu, label, cb=None):
            mi = Gtk.MenuItem(label=label)
            if cb:
                mi.connect("activate", cb)
            else:
                mi.set_sensitive(False)
            menu.append(mi)

        def build_menu(self):
            m = Gtk.Menu()
            s = self.state
            head = t["checking"] if not s else (
                f"VPN: {t['on'] if s.get('vpn') else t['off']}" + (f"  ·  {s['city']}" if s.get("city") else ""))
            self._item(m, head)
            m.append(Gtk.SeparatorMenuItem())
            self._item(m, t["history"])
            for e in reversed(self.history[-HISTORY_IN_MENU:]):
                self._item(m, format_history_row(e), lambda _w, ip=e.get("ip"): self.copy(ip))
            if not self.history:
                self._item(m, "  " + t["empty"])
            m.append(Gtk.SeparatorMenuItem())
            self._item(m, t["refresh"], self.refresh)
            self._item(m, t["clear"], self.clear_highlight)
            self._item(m, t["open"], self.open_history)
            self._item(m, t["quit"], lambda *_: Gtk.main_quit())
            m.show_all()
            self.ind.set_menu(m)
            self.menu = m  # keep a reference so the menu isn't garbage-collected

        def copy(self, ip):
            if ip:
                Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(ip, -1)

        def clear_highlight(self, *_):
            self.highlight_until = 0
            self.render()

        def open_history(self, *_):
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            HISTORY_FILE.touch()
            subprocess.Popen(["xdg-open", str(HISTORY_FILE)])

    Indicator()
    Gtk.main()


if __name__ == "__main__":
    run()
