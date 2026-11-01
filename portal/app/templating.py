"""Jinja setup and small view helpers (server-rendered SVG charts: no CDN, strict CSP)."""
import contextvars
import html
import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi.templating import Jinja2Templates
from markupsafe import Markup

from . import devices
from .config import settings

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
# The viewer's zone for the page being rendered; templates render synchronously inside render().
_tz = contextvars.ContextVar("tz", default=timezone.utc)

NAV = [
    ("Monitor", [("/", "Overview", "overview"), ("/traffic", "Traffic", "traffic"), ("/dns", "DNS", "dns"), ("/vpn", "VPN", "vpn")]),
    ("Network", [("/clients", "Clients", "clients")]),
    ("Security", [("/threats", "Threats", "threats"), ("/alerts", "Alerts", "alerts")]),
    ("Control", [("/actions", "Actions", "actions")]),
    ("Admin", [("/audit", "Audit log", "audit"), ("/security", "Account security", "security")]),
]
# 24x24 stroke icons for the drawer.
NAV_ICONS = {
    "overview": "M4 4h7v7H4zM13 4h7v4h-7zM13 10h7v10h-7zM4 13h7v7H4z",
    "traffic": "M3 17l6-6 4 4 8-8M15 7h6v6",
    "dns": "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.4 2.5 3.6 5.5 3.6 9s-1.2 6.5-3.6 9c-2.4-2.5-3.6-5.5-3.6-9S9.6 5.5 12 3z",
    "vpn": "M6 11h12v10H6zM8.5 11V7.5a3.5 3.5 0 0 1 7 0V11M12 15v2",
    "clients": "M4 5h16v10H4zM2 19h20M9 15v4M15 15v4",
    "threats": "M12 3 5 6v5c0 4.5 3 8.4 7 10 4-1.6 7-5.5 7-10V6zM9.5 12l2 2 3.5-4",
    "alerts": "M6 16v-5a6 6 0 0 1 12 0v5l1.5 2h-15zM10 21h4",
    "actions": "M13 2 4 14h7l-1 8 9-12h-7z",
    "audit": "M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01",
    "security": "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4.5 21a7.5 7.5 0 0 1 15 0",
}


def _nav(path: str, is_operator: bool):
    """Drawer sections for this viewer, plus the (section, label) of the current page."""
    groups, current = [], None
    for section, items in NAV:
        shown = []
        for href, label, icon in items:
            if href == "/actions" and not is_operator:
                continue
            active = path == href or (href != "/" and path.startswith(href))
            if active:
                current = (section, label)
            shown.append((href, label, NAV_ICONS[icon], active))
        if shown:
            groups.append((section, shown))
    return groups, current


def _zone(name: str):
    if not name or len(name) > 64:
        return None
    try:
        return timezone.utc if name == "UTC" else ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return None


def viewer_tz(request):
    """The browser's own zone (cookie from portal.js), else PORTAL_TZ, else UTC."""
    return _zone(unquote(request.cookies.get("tz", ""))) or _zone(settings.default_tz) or timezone.utc


def local(ts) -> datetime:
    return datetime.fromtimestamp(int(ts), _tz.get())


def render(request, name: str, status_code: int = 200, **ctx):
    zone = viewer_tz(request)
    _tz.set(zone)
    ctx["tz_name"] = str(zone)
    ctx["tz_abbr"] = datetime.now(zone).strftime("%Z")
    session = ctx.get("session") or getattr(request.state, "session", None)
    ctx.setdefault("session", session)
    ctx["csrf"] = session.csrf if session else ""
    ctx["path"] = request.url.path
    ctx["nav"], ctx["nav_current"] = _nav(ctx["path"], bool(session and session.is_operator))
    ctx["rp_name"] = settings.rp_name
    # Live requests only need page content. Auth is still enforced by the route.
    ctx["fragment"] = bool(session and ctx.get("refresh") and request.headers.get("X-Auto-Refresh") == "1")
    response = templates.TemplateResponse(request, name, ctx, status_code=status_code)
    response.headers["Vary"] = "X-Auto-Refresh"
    if ctx["fragment"]:
        response.headers["X-Portal-Fragment"] = "1"
    return response


def fmt_ts(ts) -> str:
    if not ts:
        return "—"
    return local(ts).strftime("%Y-%m-%d %H:%M %Z")


def fmt_ago(ts) -> str:
    if not ts:
        return "never"
    delta = int(time.time()) - int(ts)
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if delta >= size:
            return f"{delta // size}{unit} ago"
    return "just now"


def fmt_bps(value) -> str:
    if value is None:
        return "—"
    value = float(value or 0)
    for unit in ("bit/s", "kbit/s", "Mbit/s", "Gbit/s"):
        if value < 1000:
            return f"{value:.0f} {unit}" if unit == "bit/s" else f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} Tbit/s"


def fmt_duration(seconds) -> str:
    seconds = int(seconds or 0)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    return f"{d}d {h}h" if d else f"{h}h {m}m" if h else f"{m}m {rem % 60}s" if m else f"{seconds}s"


def _number(value) -> str:
    for scale, suffix in ((1e9, "G"), (1e6, "M"), (1e3, "k")):
        if abs(value) >= scale:
            return f"{value / scale:.1f}{suffix}"
    return f"{value:.1f}" if value % 1 else f"{value:.0f}"


def time_chart(points, field: str, label: str, unit: str = "", cls: str = "primary", start=None, end=None) -> Markup:
    """Bounded, accessible SVG with local timestamps and gaps for missing observations."""
    valid = [(i, p) for i, p in enumerate(points)
             if isinstance(p.get(field), (int, float)) and math.isfinite(p[field])]
    if not valid:
        return Markup('<div class="chart-empty"><span>No observations in this period</span>'
                      '<span class="small muted">The graph appears when telemetry arrives.</span></div>')
    left, top, right, bottom = 56, 20, 622, 152
    first = start if start is not None else points[0]["ts"]
    last = end if end is not None else points[-1]["ts"]
    time_span = max(1, last - first)
    high = max(1, max(p[field] for _, p in valid))
    esc = html.escape
    color = cls if cls in ("primary", "alt", "warn", "bad") else "primary"
    title = f"{label} ({unit}). Times in {_tz.get()}. Gaps indicate missing observations."
    out = [f'<svg class="time-chart {color}" viewBox="0 0 640 188" role="img" aria-label="{esc(title)}" data-tips=\'{{tips}}\'>',
           f'<title>{esc(title)}</title>']
    for fraction in (0, .5, 1):
        y = bottom - fraction * (bottom - top)
        out.append(f'<line class="chart-grid" x1="{left}" x2="{right}" y1="{y}" y2="{y}"/>')
        out.append(f'<text class="chart-label" x="{left - 9}" y="{y + 4}" text-anchor="end">{_number(high * fraction)}</text>')
    coords, groups, tips = [], [], []
    for p in points:
        value = p.get(field)
        if not isinstance(value, (int, float)) or not math.isfinite(value):
            if coords:
                groups.append(coords)
                coords = []
            continue
        x = left + (max(first, p["ts"]) - first) / time_span * (right - left)
        y = bottom - value / high * (bottom - top)
        coords.append(f"{x:.2f},{y:.2f}")
        tips.append([round(x, 1), round(y, 1), f"{fmt_ts(p['ts'])} · {_number(value)} {unit}"])
    if coords:
        groups.append(coords)
    for group in groups:
        out.append(f'<polyline class="chart-line" points="{" ".join(group)}"/>')
    out.append(_hover_layer(tips, top, bottom, dot=True))
    for fraction, anchor in ((0, "start"), (.5, "middle"), (1, "end")):
        stamp = first + time_span * fraction
        fmt = "%d %b %H:%M" if time_span > 86400 else "%H:%M"
        out.append(f'<text class="chart-label" x="{left + fraction * (right - left):.1f}" y="178" text-anchor="{anchor}">'
                   f'{local(stamp).strftime(fmt)}</text>')
    out.append('</svg>')
    return Markup("".join(out).replace("{tips}", _tips_attr(tips), 1))


def _tips_attr(tips) -> str:
    """JSON for a single-quoted attribute: escaping only &, <, > and ' keeps it about a quarter smaller than
    escaping every double quote."""
    return html.escape(json.dumps(tips, separators=(",", ":"), ensure_ascii=False), quote=False).replace("'", "&#x27;")


def _hover_layer(tips, top, bottom, dot=False) -> str:
    """Hidden guide (and dot) that portal.js moves to the point nearest the pointer, reading data-tips.
    One layer per chart instead of a dot and <title> per point keeps the DOM small."""
    x = tips[0][0] if tips else 0
    return (f'<line class="hover-guide" x1="{x}" x2="{x}" y1="{top}" y2="{bottom}"/>'
            + (f'<circle class="hover-dot" cx="{x}" cy="{bottom}" r="3.5"/>' if dot else ""))


def _nice_ceiling(value: float) -> float:
    """Round up to 1, 2, 2.5 or 5 x 10^n so gridlines land on readable rates."""
    if value <= 0:
        return 1.0
    magnitude = 10 ** math.floor(math.log10(value))
    for step in (1, 2, 2.5, 5, 10):
        if value <= step * magnitude:
            return step * magnitude
    return 10 * magnitude


def _short_bps(value: float) -> str:
    for scale, unit in ((1e9, "Gbit/s"), (1e6, "Mbit/s"), (1e3, "kbit/s")):
        if value >= scale:
            n = value / scale
            return f"{n:g} {unit}" if n == int(n) else f"{n:.1f} {unit}"
    return f"{value:.0f} bit/s"


def traffic_chart(points, start, end) -> Markup:
    """WAN download (filled area) and upload (line) on one time axis, with one hover layer (see
    _hover_layer). Missing observations break both series."""
    def ok(v):
        return isinstance(v, (int, float)) and math.isfinite(v)
    valid = [p for p in points if ok(p.get("rx_bps")) or ok(p.get("tx_bps"))]
    if not valid:
        return Markup('<div class="chart-empty"><span>No observations in this period</span>'
                      '<span class="small muted">The graph appears when telemetry arrives.</span></div>')
    left, top, right, bottom = 74, 14, 988, 262
    span = max(1, end - start)
    high = _nice_ceiling(max(max(p.get("rx_bps") or 0, p.get("tx_bps") or 0) for p in valid) * 1.05)
    esc = html.escape
    x_of = lambda ts: left + (max(start, min(end, ts)) - start) / span * (right - left)  # noqa: E731
    y_of = lambda v: bottom - v / high * (bottom - top)  # noqa: E731
    title = f"WAN download and upload. Times in {_tz.get()}. Gaps indicate missing observations."
    tips = [[round(x_of(p["ts"]), 1), f'{fmt_ts(p["ts"])} · ↓ {fmt_bps(p.get("rx_bps"))} · ↑ {fmt_bps(p.get("tx_bps"))}']
            for p in points if ok(p.get("rx_bps")) or ok(p.get("tx_bps"))]
    out = [f'<svg class="traffic-chart" viewBox="0 0 1000 296" role="img" aria-label="{esc(title)}" '
           f"data-tips='{_tips_attr(tips)}'><title>{esc(title)}</title>"]
    for i in range(5):
        v = high * i / 4
        y = y_of(v)
        out.append(f'<line class="chart-grid" x1="{left}" x2="{right}" y1="{y:.1f}" y2="{y:.1f}"/>'
                   f'<text class="chart-label" x="{left - 10}" y="{y + 4:.1f}" text-anchor="end">{_short_bps(v)}</text>')
    ticks = 6
    for i in range(ticks + 1):
        ts = start + span * i / ticks
        anchor = "start" if i == 0 else "end" if i == ticks else "middle"
        fmt = "%d %b %H:%M" if span > 86400 else "%H:%M"
        out.append(f'<line class="chart-tick" x1="{x_of(ts):.1f}" x2="{x_of(ts):.1f}" y1="{bottom}" y2="{bottom + 5}"/>'
                   f'<text class="chart-label" x="{x_of(ts):.1f}" y="{bottom + 22}" text-anchor="{anchor}">{local(ts).strftime(fmt)}</text>')

    def runs(field):
        group, groups = [], []
        for p in points:
            if ok(p.get(field)):
                group.append((x_of(p["ts"]), y_of(p[field])))
            elif group:
                groups.append(group)
                group = []
        if group:
            groups.append(group)
        return groups

    for field, cls in (("rx_bps", "down"), ("tx_bps", "up")):
        for g in runs(field):
            line = " ".join(f"{x:.1f},{y:.1f}" for x, y in g)
            area = f"{g[0][0]:.1f},{bottom} {line} {g[-1][0]:.1f},{bottom}"
            out.append(f'<polygon class="traffic-area {cls}" points="{area}"/>')
            out.append(f'<polyline class="traffic-line {cls}" points="{line}"/>')
    out.append(_hover_layer(tips, top, bottom))
    out.append("</svg>")
    return Markup("".join(out))


def rate_bars(down, up, high) -> Markup:
    """Two thin bars (download, upload) scaled to the busiest interface; SVG so the CSP holds."""
    high = max(1.0, float(high or 0))
    w = lambda v: max(1.5, min(1.0, float(v or 0) / high) * 200)  # noqa: E731
    return Markup('<svg class="rate-bars" viewBox="0 0 200 22" preserveAspectRatio="none" aria-hidden="true">'
                  f'<rect class="track" x="0" y="2" width="200" height="7" rx="3.5"/><rect class="down" x="0" y="2" width="{w(down):.1f}" height="7" rx="3.5"/>'
                  f'<rect class="track" x="0" y="13" width="200" height="7" rx="3.5"/><rect class="up" x="0" y="13" width="{w(up):.1f}" height="7" rx="3.5"/></svg>')


def waf_chart(days) -> Markup:
    """Stacked daily counts: blocked and detected-only are disjoint categories."""
    if not days or not any(d["blocked"] or d["detected"] for d in days):
        return Markup('<div class="chart-empty"><span>No confirmed WAF events recorded</span>'
                      '<span class="small muted">This does not confirm that the WAF is enabled.</span></div>')
    high = max(1, max(d["blocked"] + d["detected"] for d in days))
    out = ['<svg class="waf-chart" viewBox="0 0 640 196" role="img" aria-label="Confirmed WAF events by UTC day">'
           '<title>Confirmed WAF events by UTC day. Blocked and detected only are separate categories.</title>']
    for n in (0, .5, 1):
        y = 156 - n * 126
        out.append(f'<line class="chart-grid" x1="48" x2="628" y1="{y}" y2="{y}"/>'
                   f'<text class="chart-label" x="40" y="{y+4}" text-anchor="end">{_number(high*n)}</text>')
    step = 570 / len(days)
    for i, d in enumerate(days):
        x, y = 54 + i * step, 156
        for kind in ("blocked", "detected"):
            height = d[kind] / high * 126
            y -= height
            out.append(f'<rect class="waf-{kind}" x="{x + 12:.1f}" y="{y:.1f}" width="{step - 24:.1f}" height="{height:.1f}" rx="2">'
                       f'<title>{html.escape(d["day"])}: {d[kind]} {kind}</title></rect>')
        out.append(f'<text class="chart-label" x="{x + step/2:.1f}" y="181" text-anchor="middle">'
                   f'{time.strftime("%d %b", time.gmtime(d["ts"]))}</text>')
    out.append('</svg>')
    return Markup("".join(out))


def sparkline(values, width: int = 600, height: int = 80, cls: str = "line") -> Markup:
    pts = [v for v in values if v is not None]
    if len(pts) < 2:
        return Markup('<p class="muted">Not enough data yet.</p>')
    lo, hi = min(pts), max(pts)
    span = (hi - lo) or 1
    step = width / (len(values) - 1)
    coords = []
    for i, v in enumerate(values):
        if v is None:
            continue
        coords.append(f"{i * step:.1f},{height - 4 - (v - lo) / span * (height - 8):.1f}")
    return Markup(
        f'<svg class="spark {cls}" viewBox="0 0 {width} {height}" preserveAspectRatio="none" role="img">'
        f'<polyline fill="none" points="{" ".join(coords)}"/></svg>'
        f'<div class="spark-scale"><span>{lo:.1f}</span><span>{hi:.1f}</span></div>'
    )


def uptime_bar(segments, start=None, end=None) -> Markup:
    """segments: list of (fraction_width, state) where state is up/down/nodata.
    Drawn as SVG attributes, not inline styles, so the strict CSP still holds."""
    runs = []
    for width, state in segments:  # merge neighbours in the same state: a few rects instead of 240
        if runs and runs[-1][1] == state:
            runs[-1][0] += width
        else:
            runs.append([width, state])
    x, rects = 0.0, []
    for width, state in runs:
        label = {"up": "Observed up", "down": "Outage observed", "nodata": "No WAN observation"}.get(state, "Unknown")
        if start is not None and end is not None:
            label = f"{fmt_ts(start + x * (end - start))} — {fmt_ts(start + (x + width) * (end - start))}: {label}"
        rects.append(f'<rect class="seg {state}" x="{x * 1000:.2f}" y="0" width="{width * 1000 + 0.5:.2f}" height="20"><title>{html.escape(label)}</title></rect>')
        x += width
    axis = ""
    if start is not None and end is not None:
        axis = f'<div class="time-axis"><span>{fmt_ts(start)}</span><span>{fmt_ts((start + end)/2)}</span><span>{fmt_ts(end)}</span></div>'
    return Markup(f'<svg class="uptime-bar" viewBox="0 0 1000 20" preserveAspectRatio="none" role="img" aria-label="Observed WAN availability over time"><title>Observed WAN availability over time; grey means no WAN observation.</title>{"".join(rects)}</svg>{axis}')


def _flow_level(bps) -> int:
    bps = float(bps or 0)
    return 0 if bps < 2_000 else 1 if bps < 1_000_000 else 2 if bps < 25_000_000 else 3


def _flow_pair(x1, y1, x2, y2, down_bps, up_bps, extra="") -> str:
    """Two curved lanes between nodes: download (towards the devices) and upload (back out).
    Dash animation speed shows the rate; idle links stay still. Classes only, so the CSP holds."""
    out = []
    gap = 2.5 if extra else 4
    for lane, bps, off in (("down", down_bps, -gap), ("up", up_bps, gap)):
        mx = (x1 + x2) / 2
        d = f"M{x1},{y1 + off} C{mx},{y1 + off} {mx},{y2 + off} {x2},{y2 + off}"
        out.append(f'<path class="lane {lane} {extra}" d="{d}"/>')
        out.append(f'<path class="flow {lane} {extra} lvl-{_flow_level(bps)}" d="{d}"/>')
    return "".join(out)


FLOW_ROW, FLOW_GAP, FLOW_TOP, FLOW_WIDTH = 50, 26, 26, 900  # device cards span x 630-880 (70%-97.8%)


def flow_layout(segments: list) -> int:
    """Give each segment and device node its row (y in viewBox units, plus top/height in % for the HTML
    hit area laid over each device card). Returns the viewBox height."""
    y = FLOW_TOP
    for s in segments:
        rows = max(1, len(s.get("devices") or []) + (1 if s.get("more") else 0))
        for i, d in enumerate(s.get("devices") or []):
            d["y"] = y + FLOW_ROW * i + FLOW_ROW / 2
        s["more_y"] = y + FLOW_ROW * (rows - 1) + FLOW_ROW / 2
        s["y"] = y + rows * FLOW_ROW / 2
        y += rows * FLOW_ROW + FLOW_GAP
    height = max(260, int(y - FLOW_GAP + FLOW_TOP))
    for s in segments:
        for d in s.get("devices") or []:
            d["top_pct"] = round((d["y"] - 20) / height * 100, 3)
            d["h_pct"] = round(40 / height * 100, 3)
    return height


def _fit(text: str, size: float, room: float) -> str:
    """textLength attributes that squeeze a line into its box when the rough width estimate says it would
    overflow (SVG text never wraps or clips by itself)."""
    return f' textLength="{room:.0f}" lengthAdjust="spacingAndGlyphs"' if len(text) * size * 0.6 > room else ""


def _rates(down, up, sep="   ") -> str:
    """↓ x ↑ y with coloured arrows (download orange, upload blue)."""
    return (f'<tspan class="arr down">↓</tspan> {html.escape(fmt_bps(down))}{sep}'
            f'<tspan class="arr up">↑</tspan> {html.escape(fmt_bps(up))}')


def _short(text, n) -> str:
    text = str(text or "")
    return text if len(text) <= n else text[: n - 1] + "…"


def flow_map(gw: dict, wan: dict, segments: list, height: int = 0) -> Markup:
    """Internet -> firewall -> segments -> each device, with live rates on every link.
    Call flow_layout(segments) first; devices carry down_bps/up_bps, paused, limit and domains."""
    height = height or flow_layout(segments)
    mid = height / 2
    e = html.escape
    parts = [f'<svg class="flowmap" viewBox="0 0 {FLOW_WIDTH} {height}" role="img" aria-label="Network traffic flow down to each device">']
    state = gw.get("state") or ("online" if gw.get("online") is True else "offline" if gw.get("online") is False else "unknown")
    up = state == "online"
    # Internet <-> firewall
    parts.append(_flow_pair(108, mid, 200, mid, wan.get("rx_bps"), wan.get("tx_bps")))
    parts.append(f'<text class="rate" x="154" y="{mid - 16}" text-anchor="middle">↓ {e(fmt_bps(wan.get("rx_bps")))}</text>')
    parts.append(f'<text class="rate up" x="154" y="{mid + 26}" text-anchor="middle">↑ {e(fmt_bps(wan.get("tx_bps")))}</text>')
    parts.append(f'<g class="node internet {"ok" if up else "bad" if state == "offline" else "unknown"}"><circle cx="60" cy="{mid}" r="48"/>'
                 f'<text class="title" x="60" y="{mid - 4}" text-anchor="middle">Internet</text>'
                 f'<text class="sub" x="60" y="{mid + 16}" text-anchor="middle">{e(state)}</text></g>')
    latency = gw.get("latency_ms")
    parts.append(f'<g class="node firewall"><rect x="200" y="{mid - 50}" width="150" height="100" rx="18"/>'
                 f'<text class="title" x="275" y="{mid - 16}" text-anchor="middle">Firewall</text>'
                 f'<text class="sub mono" x="275" y="{mid + 6}" text-anchor="middle">{e(gw.get("wan_ip") or "WAN —")}</text>'
                 f'<text class="sub" x="275" y="{mid + 26}" text-anchor="middle">'
                 f'{e(f"{latency:.0f} ms to internet" if isinstance(latency, (int, float)) else "")}</text></g>')
    for s in segments:
        sy = s["y"]
        parts.append(_flow_pair(350, mid, 420, sy, s.get("down_bps"), s.get("up_bps")))
        for d in s.get("devices") or []:
            dy = d["y"]
            paused = bool(d.get("paused"))
            kind = "paused" if paused else "limited" if d.get("limit") else "ok"
            if paused:
                parts.append(f'<path class="lane blocked" d="M560,{sy} C595,{sy} 595,{dy} 630,{dy}"/>')
            else:
                parts.append(_flow_pair(560, sy, 630, dy, d.get("down_bps"), d.get("up_bps"), "dev"))
            tags = []
            if paused:
                tags.append(("paused", "Paused"))
            elif d.get("limit"):
                tags.append(("limited", f'Capped ↓{d["limit"].get("down_mbps", 0):g}'))
            blocked = d.get("domains") or {}
            sites, cats = len(blocked.get("list") or []), len(blocked.get("lists") or [])
            if sites or cats:
                what = [f"{sites} site{'s' if sites != 1 else ''}"] if sites else []
                what += [f"{cats} list{'s' if cats != 1 else ''}"] if cats else []
                tags.append(("sites", " + ".join(what)))
            tag_text = " · ".join(v for _, v in tags)
            tag_svg = "".join(f'<tspan class="tag {k}">{" · " if i else ""}{e(v)}</tspan>' for i, (k, v) in enumerate(tags))
            # Card text runs from x=671 to 870; the name gets what the tag leaves (about 7 px per character).
            name_room = 199 - (len(tag_text) * 10.5 * 0.6 + 10 if tags else 0)
            name = _short(d["label"], max(6, int(name_room / 6.8)))
            plain = "paused" if paused else f'↓ {fmt_bps(d.get("down_bps"))}   ↑ {fmt_bps(d.get("up_bps"))}'
            speeds = "paused" if paused else _rates(d.get("down_bps"), d.get("up_bps"))
            what = devices.kind(d)
            parts.append(f'<g class="node device {kind}"><title>{e(d["label"])} · {e(devices.LABELS[what])} · {e(d.get("ip") or "")} · {e(d["mac"])}</title>'
                         f'<rect x="630" y="{dy - 20}" width="250" height="40" rx="10"/>'
                         f'<rect class="kind-bg" x="637" y="{dy - 13}" width="26" height="26" rx="7"/>'
                         f'<path class="kind" transform="translate(641 {dy - 9}) scale(.75)" d="{devices.ICONS[what]}"/>'
                         f'<circle class="dot" cx="661" cy="{dy + 11}" r="3.5"/>'
                         f'<text class="title" x="671" y="{dy - 3}">{e(name)}</text>'
                         f'<text class="sub" x="671" y="{dy + 13}"{_fit(plain, 10.5, 199)}>{speeds}</text>'
                         f'<text x="870" y="{dy - 3}" text-anchor="end"{_fit(tag_text, 10.5, 120)}>{tag_svg}</text></g>')
        if s.get("more"):
            my = s["more_y"]
            parts.append(f'<path class="lane devices" d="M560,{sy} C595,{sy} 595,{my} 630,{my}"/>')
            parts.append(f'<a href="/clients?segment={e(s["name"])}"><g class="node more"><rect x="630" y="{my - 17}" width="250" height="34" rx="10"/>'
                         f'<text class="sub" x="646" y="{my + 4}">+{s["more"]} more on {e(s["name"])} → Clients</text></g></a>')
        count = s.get("online", 0)
        if not s.get("open", True):
            if count:
                parts.append(f'<path class="lane devices" d="M560,{sy} C580,{sy} 580,{sy} 600,{sy}"/>')
            parts.append(f'<text class="sub hint" x="610" y="{sy + 4}">{count} device{"s" if count != 1 else ""} online'
                         f'{" · click the network to show them" if count else ""}</text>')
        elif not s.get("devices") and not s.get("more"):
            parts.append(f'<text class="sub" x="636" y="{sy + 4}">No devices online</text>')
        is_open = s.get("open", True)
        parts.append(f'<a class="seg-toggle" href="#" data-segment="{e(s["name"])}" role="button" aria-expanded="{"true" if is_open else "false"}" '
                     f'aria-label="{"Hide" if is_open else "Show"} devices on {e(s["name"])}">'
                     f'<g class="node segment{" open" if is_open else ""}"><rect x="420" y="{sy - 34}" width="140" height="68" rx="14"/>'
                     f'<text class="title" x="434" y="{sy - 11}">{e(_short(s["name"], 10))} <tspan class="count">{count}</tspan></text>'
                     f'<path class="chevron" d="{"M538 " + str(sy - 18) + " l5 5 5 -5" if is_open else "M540 " + str(sy - 21) + " l5 5 -5 5"}"/>'
                     f'<text class="sub rate-line" x="434" y="{sy + 8}"{_fit("↓ " + fmt_bps(s.get("down_bps")), 11.5, 112)}>'
                     f'<tspan class="arr down">↓</tspan> {e(fmt_bps(s.get("down_bps")))}</text>'
                     f'<text class="sub rate-line" x="434" y="{sy + 24}"{_fit("↑ " + fmt_bps(s.get("up_bps")), 11.5, 112)}>'
                     f'<tspan class="arr up">↑</tspan> {e(fmt_bps(s.get("up_bps")))}</text></g></a>')
    if not segments:
        parts.append(f'<text class="sub" x="440" y="{mid + 5}">Waiting for the firewall agent…</text>')
    parts.append("</svg>")
    return Markup("".join(parts))


def pretty(value) -> str:
    try:
        return json.dumps(json.loads(value), indent=1)[:2000] if value else ""
    except (TypeError, ValueError):
        return str(value)[:2000]


templates.env.filters.update(list_names=lambda ids: [devices.BLOCK_LISTS.get(i, i) for i in ids or []], pretty=pretty, ts=fmt_ts, ago=fmt_ago, bps=fmt_bps, duration=fmt_duration)
def device_icon(client) -> Markup:
    """The device-type icon for the Clients page (see devices.py)."""
    what = devices.kind(client)
    return Markup(f'<svg class="kind-icon" viewBox="0 0 24 24" role="img" aria-label="{devices.LABELS[what]}">'
                  f'<title>{devices.LABELS[what]}</title><path d="{devices.ICONS[what]}"/></svg>')


templates.env.globals.update(traffic_chart=traffic_chart, rate_bars=rate_bars, block_lists=devices.BLOCK_LISTS, device_icon=device_icon, sparkline=sparkline, time_chart=time_chart, waf_chart=waf_chart, uptime_bar=uptime_bar, flow_map=flow_map)
