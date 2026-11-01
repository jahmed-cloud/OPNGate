"""Guess what kind of device a client is from its hostname and maker, for the icons on the flow map and
Clients page. Hostname words win over the maker; ambiguous makers (Apple, Samsung, Sony) give no answer."""
import re

# 24x24 stroke icons.
ICONS = {
    "phone": "M8 2.5h8a1.5 1.5 0 0 1 1.5 1.5v16a1.5 1.5 0 0 1-1.5 1.5H8A1.5 1.5 0 0 1 6.5 20V4A1.5 1.5 0 0 1 8 2.5zM11 18.5h2",
    "tablet": "M6 2.5h12a1.5 1.5 0 0 1 1.5 1.5v16a1.5 1.5 0 0 1-1.5 1.5H6A1.5 1.5 0 0 1 4.5 20V4A1.5 1.5 0 0 1 6 2.5zM11 18.5h2",
    "laptop": "M5 5h14v10H5zM2.5 19h19l-2-4h-15z",
    "desktop": "M3 4h18v12H3zM9 20h6M12 16v4",
    "nas": "M5 3h14v18H5zM8 7h8M8 11h8M8 15h3M15.5 17.5h.01",
    "server": "M4 4h16v6H4zM4 14h16v6H4zM7.5 7h.01M7.5 17h.01M11 7h5M11 17h5",
    "network": "M3 10h18v6H3zM6.5 13h.01M9.5 13h.01M12.5 13h.01M15.5 13h2.5M7 10V6M17 10V6",
    "tv": "M3 6h18v11H3zM8 3l4 3 4-3M8 21h8",
    "console": "M7 8h10a4 4 0 0 1 4 4v1a3 3 0 0 1-5.4 1.8L14.5 14h-5l-1.1.8A3 3 0 0 1 3 13v-1a4 4 0 0 1 4-4zM8 10.5v3M6.5 12h3M16 11h.01M18 13h.01",
    "printer": "M7 8V3h10v5M7 17H4v-7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v7h-3M7 14h10v7H7z",
    "speaker": "M7 3h10v18H7zM12 7h.01M12 16.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z",
    "camera": "M3 7h12v10H3zM15 10.5l6-3.5v10l-6-3.5z",
    "watch": "M8 7h8v10H8zM9.5 7l.5-4h4l.5 4M9.5 17l.5 4h4l.5-4",
    "iot": "M9 18h6M10 21h4M12 3a6 6 0 0 0-3.5 10.9c.6.5 1 1.2 1 2.1h5c0-.9.4-1.6 1-2.1A6 6 0 0 0 12 3z",
    "device": "M7 7h10v10H7zM10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4",
}

LABELS = {"phone": "Phone", "tablet": "Tablet", "laptop": "Laptop", "desktop": "Computer", "nas": "NAS", "server": "Server",
          "network": "Network device", "tv": "TV / streamer", "console": "Game console", "printer": "Printer",
          "speaker": "Smart speaker", "camera": "Camera", "watch": "Watch", "iot": "Smart-home device", "device": "Device"}

# Checked in order; the first hit wins (so "nintendo switch" is a console before "switch" is network gear).
NAME_RULES = [
    ("console", r"playstation|ps[345]\b|xbox|nintendo|steam-?deck|game|console"),
    ("tablet", r"ipad|tablet|\btab\b|galaxy-?tab|kindle|fire-?hd"),
    ("watch", r"watch"),
    ("phone", r"iphone|android|pixel|galaxy|oneplus|redmi|xiaomi|phone|oppo|vivo|huawei|nokia|motorola|moto-?[a-z0-9]"),
    ("laptop", r"laptop|macbook|notebook|thinkpad|ideapad|zenbook|chromebook|surface|latitude|xps|-book\b"),
    ("nas", r"\bnas\b|nas-|synology|diskstation|qnap|truenas|unraid|omv"),
    ("server", r"server|proxmox|pve|esxi|docker|raspberry|\bpi\d?\b|homeassistant|home-assistant|hass"),
    ("network", r"switch|router|\bap\b|access-?point|unifi|ubnt|mikrotik|edgerouter|mesh|deco|orbi|opnsense|pfsense|firewall|extender"),
    ("tv", r"\btv\b|-tv|tv-|roku|chromecast|fire-?tv|firestick|apple-?tv|shield|bravia|webos|tizen"),
    ("printer", r"printer|print|\bmfc|laserjet|officejet|deskjet|epson|canon|brother"),
    ("speaker", r"speaker|echo|alexa|sonos|homepod|google-?home|nest-?(mini|audio|hub)"),
    ("camera", r"cam\b|camera|doorbell|\bring\b|wyze|reolink|hikvision|dahua|nvr"),
    ("iot", r"esp|tasmota|shelly|plug|bulb|light|tuya|sensor|thermostat|vacuum|roomba|hue"),
    ("desktop", r"desktop|\bpc\b|-pc|pc-|imac|workstation|tower"),
]
VENDOR_RULES = [
    ("nas", r"synology|qnap|western digital"),
    ("server", r"raspberry"),
    ("network", r"ubiquiti|mikrotik|tp-?link|netgear|cisco|aruba|juniper|zyxel|d-?link|deciso"),
    ("printer", r"brother|epson|canon|hewlett|lexmark|kyocera|ricoh|xerox"),
    ("speaker", r"amazon|sonos"),
    ("console", r"nintendo|valve"),
    ("camera", r"hikvision|dahua|reolink|wyze|axis"),
    ("iot", r"espressif|shelly|tuya|signify|philips lighting|lifx|ecobee|irobot"),
    ("phone", r"oneplus|xiaomi|motorola|huawei|oppo|vivo|nothing technology"),
    ("laptop", r"dell|lenovo|asustek|acer|microsoft"),
    ("desktop", r"intel corporate|micro-star|gigabyte|asrock"),
]
_NAME = [(k, re.compile(p)) for k, p in NAME_RULES]
_VENDOR = [(k, re.compile(p)) for k, p in VENDOR_RULES]


def kind(client) -> str:
    chosen = client.get("icon") if hasattr(client, "get") else None
    if chosen in ICONS:
        return chosen
    name = str((client.get("hostname") if hasattr(client, "get") else "") or "").lower()
    vendor = str((client.get("vendor") if hasattr(client, "get") else "") or "").lower()
    for k, rx in _NAME:
        if name and rx.search(name):
            return k
    for k, rx in _VENDOR:
        if vendor and rx.search(vendor):
            return k
    return "device"

def label(client) -> str:
    """The name shown for a device: the operator's name for it, else what the network reports."""
    return client.get("alias") or client.get("hostname") or client.get("vendor") or client.get("ip") or client["mac"]


# Clients joined with the names and icons operators chose (devices.label / kind read alias and icon).
CLIENTS = "SELECT c.*, l.name AS alias, l.icon AS icon FROM clients c LEFT JOIN device_labels l ON l.mac = c.mac"

# Ready-made category lists for a device (OPNsense Unbound blocklist ids; the agent allows the same set).
BLOCK_LISTS = {
    "ag": "Ads (AdGuard)", "ep": "Trackers", "hgz022": "Social media", "oisd2": "Adult content", "hgz019": "Gambling",
    "hgz009": "Scams", "hgz014": "VPN bypass", "hgz018": "Piracy",
    "tvtrack": "Smart-TV tracking", "phishing": "Phishing", "mining": "Crypto mining", "dating": "Dating sites",
}
