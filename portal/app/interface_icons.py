"""Presentation-only interface hints inferred from configured names, not hardware detection."""
import re

LABELS = {
    "wifi": "Wi-Fi", "wan": "Internet / WAN", "lan": "Ethernet / LAN",
    "vpn": "VPN", "management": "Management", "vlan": "VLAN",
    "bridge": "Bridge", "breakglass": "Recovery network", "network": "Network",
}
ICONS = {
    "wifi": "M2 8a16 16 0 0 1 20 0M5 12a11 11 0 0 1 14 0M8.5 16a5.5 5.5 0 0 1 7 0M12 20h.01",
    "wan": "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18",
    "lan": "M5 3h14v14H5zM8 3v5M11 3v5M14 3v5M17 3v5M9 17v4h6v-4",
    "vpn": "M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4M12 15v2",
    "management": "M3 4h18v13H3zM8 21h8M12 17v4M6 8l3 3-3 3M12 14h5",
    "vlan": "M12 3l9 5-9 5-9-5zM3 12l9 5 9-5M3 16l9 5 9-5",
    "bridge": "M3 19V5M21 19V5M3 9c5 7 13 7 18 0M3 17h18M8 13v4M16 13v4",
    "breakglass": "M12 3l8 3v5c0 5-4 9-8 11-4-2-8-6-8-11V6zM12 8v6M12 17h.01",
    "network": "M9 3h6v6H9zM2 15h6v6H2zM16 15h6v6h-6zM12 9v3M5 15v-3h14v3",
}


def kind(segment="", interface="", wan=False):
    """Prefer a named role; fall back to familiar OS names or a generic icon."""
    name = re.sub(r"[^a-z0-9]+", " ", str(segment or "").lower()).strip()
    for role, pattern in (
        ("breakglass", r"\bbreak ?glass\b|\brecovery\b"),
        ("wifi", r"\b(?:wi ?fi|wlan|wireless)\d*\b"),
        ("vpn", r"\b(?:vpn|wireguard|openvpn|ipsec|wg|ovpn)\d*\b"),
        ("management", r"\b(?:management|mgmt|admin)\b"),
        ("wan", r"\b(?:wan|internet)\d*\b"),
        ("lan", r"\b(?:lan|ethernet)\d*\b"),
        ("vlan", r"\bvlan\d*\b"),
        ("bridge", r"\bbridge\d*\b"),
    ):
        if re.search(pattern, name):
            return role
    if wan:
        return "wan"
    iface = str(interface or "").lower()
    for role, pattern in (
        ("wifi", r"(?:wlan|ath|iwm|iwlwifi|wlp|wlx).*"),
        ("vpn", r"(?:wg|ovpn[sc]?|tun|ipsec|enc)\d+"),
        ("vlan", r"(?:vlan\d+|[a-z]+\d+\.\d+)"),
        ("bridge", r"(?:bridge|br)\d+"),
        ("lan", r"(?:igc|igb|ix|em|re|vtnet|eth|enp|ens)\d[\da-z]*"),
    ):
        if re.fullmatch(pattern, iface):
            return role
    return "network"
