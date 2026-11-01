"""Jinja setup and small view helpers (server-rendered SVG charts: no CDN, strict CSP)."""
import html
import json
import math
import time
from pathlib import Path

from fastapi.templating import Jinja2Templates
from markupsafe import Markup

from .config import settings

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

NAV = [
    ("/", "Overview"), ("/clients", "Clients"), ("/traffic", "Traffic"), ("/threats", "Threats"),
    ("/dns", "DNS"), ("/vpn", "VPN"), ("/alerts", "Alerts"), ("/audit", "Audit"),
]


def render(request, name: str, status_code: int = 200, **ctx):
    session = ctx.get("session") or getattr(request.state, "session", None)
    ctx.setdefault("session", session)
    ctx["csrf"] = session.csrf if session else ""
    ctx["nav"] = NAV + ([("/actions", "Actions")] if session and session.is_operator else [])
    ctx["path"] = request.url.path
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
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(ts)))


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
    """Bounded, accessible SVG with UTC timestamps and gaps for missing observations."""
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
    title = f"{label} ({unit}). UTC. Gaps indicate missing observations."
    out = [f'<svg class="time-chart {color}" viewBox="0 0 640 188" role="img" aria-label="{esc(title)}">',
           f'<title>{esc(title)}</title>']
    for fraction in (0, .5, 1):
        y = bottom - fraction * (bottom - top)
        out.append(f'<line class="chart-grid" x1="{left}" x2="{right}" y1="{y}" y2="{y}"/>')
        out.append(f'<text class="chart-label" x="{left - 9}" y="{y + 4}" text-anchor="end">{_number(high * fraction)}</text>')
    coords, groups, dots = [], [], []
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
        stamp = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(p["ts"]))
        tooltip = f"{stamp} · {_number(value)} {unit}"
        dots.append(f'<circle class="chart-point" cx="{x:.2f}" cy="{y:.2f}" r="2.5"><title>{esc(tooltip)}</title></circle>')
    if coords:
        groups.append(coords)
    for group in groups:
        out.append(f'<polyline class="chart-line" points="{" ".join(group)}"/>')
    out.extend(dots)
    for fraction, anchor in ((0, "start"), (.5, "middle"), (1, "end")):
        stamp = first + time_span * fraction
        fmt = "%d %b %H:%M" if time_span > 86400 else "%H:%M"
        out.append(f'<text class="chart-label" x="{left + fraction * (right - left):.1f}" y="178" text-anchor="{anchor}">'
                   f'{time.strftime(fmt, time.gmtime(stamp))}</text>')
    out.append('</svg>')
    return Markup("".join(out))


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
    x, rects = 0.0, []
    for width, state in segments:
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


def _flow_pair(x1, y1, x2, y2, down_bps, up_bps) -> str:
    """Two curved lanes between nodes: download (towards the devices) and upload (back out).
    Dash animation speed shows the rate; idle links stay still. Classes only, so the CSP holds."""
    out = []
    for lane, bps, off in (("down", down_bps, -4), ("up", up_bps, 4)):
        mx = (x1 + x2) / 2
        d = f"M{x1},{y1 + off} C{mx},{y1 + off} {mx},{y2 + off} {x2},{y2 + off}"
        out.append(f'<path class="lane {lane}" d="{d}"/>')
        out.append(f'<path class="flow {lane} lvl-{_flow_level(bps)}" d="{d}"/>')
    return "".join(out)


def flow_map(gw: dict, wan: dict, segments: list) -> Markup:
    """Internet -> firewall -> segments -> devices, with live rates on each link.
    segments: dicts with name, iface, down_bps, up_bps, online, names (a few device names)."""
    row_h, top = 86, 30
    height = max(250, top * 2 + row_h * max(len(segments), 1))
    mid = height / 2
    e = html.escape
    parts = [f'<svg class="flowmap" viewBox="0 0 1000 {height}" role="img" aria-label="Network traffic flow">']
    state = gw.get("state") or ("online" if gw.get("online") is True else "offline" if gw.get("online") is False else "unknown")
    up = state == "online"
    # Internet <-> firewall
    parts.append(_flow_pair(150, mid, 300, mid, wan.get("rx_bps"), wan.get("tx_bps")))
    parts.append(f'<text class="rate" x="225" y="{mid - 18}" text-anchor="middle">↓ {e(fmt_bps(wan.get("rx_bps")))}</text>')
    parts.append(f'<text class="rate up" x="225" y="{mid + 28}" text-anchor="middle">↑ {e(fmt_bps(wan.get("tx_bps")))}</text>')
    parts.append(f'<g class="node internet {"ok" if up else "bad" if state == "offline" else "unknown"}"><circle cx="90" cy="{mid}" r="52"/>'
                 f'<text class="title" x="90" y="{mid - 4}" text-anchor="middle">Internet</text>'
                 f'<text class="sub" x="90" y="{mid + 16}" text-anchor="middle">{html.escape(state)}</text></g>')
    latency = gw.get("latency_ms")
    parts.append(f'<g class="node firewall"><rect x="300" y="{mid - 52}" width="190" height="104" rx="18"/>'
                 f'<text class="title" x="395" y="{mid - 18}" text-anchor="middle">Firewall</text>'
                 f'<text class="sub mono" x="395" y="{mid + 4}" text-anchor="middle">{e(gw.get("wan_ip") or "WAN —")}</text>'
                 f'<text class="sub" x="395" y="{mid + 26}" text-anchor="middle">'
                 f'{e(f"{latency:.0f} ms to internet" if isinstance(latency, (int, float)) else "")}</text></g>')
    for i, s in enumerate(segments):
        y = top + row_h * i + row_h / 2
        parts.append(_flow_pair(490, mid, 610, y, s.get("down_bps"), s.get("up_bps")))
        parts.append(f'<g class="node segment"><rect x="610" y="{y - 30}" width="170" height="60" rx="14"/>'
                     f'<text class="title" x="626" y="{y - 6}">{e(s["name"])}</text>'
                     f'<text class="sub" x="626" y="{y + 15}">↓ {e(fmt_bps(s.get("down_bps")))}  ↑ {e(fmt_bps(s.get("up_bps")))}</text></g>')
        parts.append(f'<path class="lane devices" d="M780,{y} L812,{y}"/>')
        names = ", ".join(s.get("names") or [])
        more = s.get("online", 0) - len(s.get("names") or [])
        label = f'{s.get("online", 0)} device{"s" if s.get("online", 0) != 1 else ""}'
        parts.append(f'<g class="node devices"><text class="title" x="822" y="{y - 4}">{e(label)}</text>'
                     f'<text class="sub" x="822" y="{y + 15}">{e(names[:34] + ("…" if len(names) > 34 else ""))}'
                     f'{e(f" +{more}") if more > 0 and len(names) <= 34 else ""}</text></g>')
    if not segments:
        parts.append(f'<text class="sub" x="620" y="{mid + 5}">Waiting for the firewall agent…</text>')
    parts.append("</svg>")
    return Markup("".join(parts))


def pretty(value) -> str:
    try:
        return json.dumps(json.loads(value), indent=1)[:2000] if value else ""
    except (TypeError, ValueError):
        return str(value)[:2000]


templates.env.filters.update(pretty=pretty, ts=fmt_ts, ago=fmt_ago, bps=fmt_bps, duration=fmt_duration)
templates.env.globals.update(sparkline=sparkline, time_chart=time_chart, waf_chart=waf_chart, uptime_bar=uptime_bar, flow_map=flow_map)
