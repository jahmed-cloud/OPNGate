"""MAC vendor lookup from the IEEE oui.txt list (optional file; download from
https://standards-oui.ieee.org/oui/oui.txt into the data directory)."""
import re
from functools import lru_cache

from .config import settings

_LINE = re.compile(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$")


@lru_cache(maxsize=1)
def _table() -> dict:
    table = {}
    try:
        with open(settings.oui_file, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _LINE.match(line.strip())
                if m:
                    table[m.group(1).replace("-", ":").lower()] = m.group(2).strip()
    except OSError:
        pass
    return table


def vendor(mac: str) -> str:
    mac = mac.lower()
    try:
        if int(mac[:2], 16) & 0x02:
            return "Private (randomised MAC)"
    except ValueError:
        return ""
    return _table().get(mac[:8], "")
