import pytest
from app.interface_icons import kind
from app.templating import interface_icon, flow_map


@pytest.mark.parametrize("segment,interface,wan,expected", [
    ("Wi-Fi", "igc1", False, "wifi"),
    ("WLAN2", "em0", False, "wifi"),
    ("LAN", "wg0", False, "lan"),
    ("Office VPN", "igc1", False, "vpn"),
    ("Management", "vlan20", False, "management"),
    ("Breakglass", "em0", False, "breakglass"),
    ("WAN", "igc0", False, "wan"),
    ("Uplink", "igc0", True, "wan"),
    ("Office", "wg0", False, "vpn"),
    ("Office", "igc1.20", False, "vlan"),
    ("Office", "bridge0", False, "bridge"),
    ("Office", "igc1", False, "lan"),
    ("Swan room", "mystery0", False, "network"),
    ("Marketing", "unknown", False, "network"),
    (None, None, False, "network"),
])
def test_interface_role_hint(segment, interface, wan, expected):
    assert kind(segment, interface, wan) == expected


def test_interface_icon_is_accessible_inline_svg():
    icon = str(interface_icon("WiFi", "igc1"))
    assert 'aria-label="Wi-Fi"' in icon
    assert '<title>Wi-Fi</title>' in icon
    assert '<path ' in icon


def test_flow_network_name_escaped_and_preserved_in_tooltip():
    name = 'WiFi <guest & visitors>'
    markup = str(flow_map({}, {}, [{"name": name, "iface": "igc1", "devices": [], "count": 123, "open": False}]))
    assert 'WiFi &lt;guest &amp; visitors&gt;' in markup
    assert '<path class="interface-glyph"' in markup
    assert '· Wi-Fi' in markup
    assert '<guest' not in markup
