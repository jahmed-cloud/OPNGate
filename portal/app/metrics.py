"""Bounded, time-aligned telemetry for charts and downloads.

SQLite aggregates raw samples; Python receives at most 240 rows even for 30 days.
Missing buckets remain explicit gaps. Availability describes known samples, while
coverage describes occupied chart buckets; neither is an SLA measurement.
"""
import math

from . import db

RANGES = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
MAX_POINTS = 240
FIELDS = ("latency_ms", "loss_pct", "rx_bps", "tx_bps")


def window(key: str = "24h", now: int | None = None) -> dict:
    key = key if key in RANGES else "24h"
    now = db.now() if now is None else int(now)
    # Inclusive now, exclusive end: each sample belongs to exactly one bucket.
    start, end = now - RANGES[key] + 1, now + 1
    # Allow for two partially occupied end buckets while keeping <= MAX_POINTS.
    width = math.ceil(RANGES[key] / (MAX_POINTS - 1))
    first, last = start // width, (end - 1) // width
    rows = db.q(
        "SELECT CAST(ts / ? AS INTEGER) AS bucket, COUNT(*) AS sample_count, "
        "MIN(ts) AS first_seen, MAX(ts) AS last_seen, "
        "COUNT(CASE WHEN wan_up IN (0, 1) THEN 1 END) AS known_samples, "
        "SUM(CASE WHEN wan_up=1 THEN 1 ELSE 0 END) AS up_samples, "
        "MIN(CASE WHEN wan_up IN (0, 1) THEN wan_up END) AS wan_up, "
        "AVG(latency_ms) AS latency_ms, COUNT(latency_ms) AS latency_count, MAX(latency_ms) AS latency_max_ms, "
        "AVG(loss_pct) AS loss_pct, COUNT(loss_pct) AS loss_count, "
        "AVG(rx_bps) AS rx_bps, MAX(rx_bps) AS rx_peak_bps, "
        "AVG(tx_bps) AS tx_bps, MAX(tx_bps) AS tx_peak_bps "
        "FROM samples WHERE ts >= ? AND ts < ? GROUP BY bucket ORDER BY bucket",
        width, start, end,
    )
    indexed = {row["bucket"]: row for row in rows}
    points = []
    for bucket in range(first, last + 1):
        row = indexed.get(bucket)
        points.append({
            "ts": bucket * width,
            **{field: row[field] if row else None for field in FIELDS},
            "wan_up": row["wan_up"] if row else None,
            "sample_count": row["sample_count"] if row else 0,
        })

    def weighted(field: str, count: str):
        n = sum(row[count] for row in rows)
        return sum((row[field] or 0) * row[count] for row in rows) / n if n else None

    def maximum(field: str):
        return max((row[field] for row in rows if row[field] is not None), default=None)

    known = sum(row["known_samples"] for row in rows)
    summary = {
        "latency_avg_ms": weighted("latency_ms", "latency_count"),
        "latency_max_ms": maximum("latency_max_ms"),
        "loss_avg_pct": weighted("loss_pct", "loss_count"),
        "rx_peak_bps": maximum("rx_peak_bps"),
        "tx_peak_bps": maximum("tx_peak_bps"),
        "availability_pct": 100 * sum(row["up_samples"] for row in rows) / known if known else None,
        "coverage_pct": 100 * len(rows) / len(points),
        "sample_count": sum(row["sample_count"] for row in rows),
        "known_samples": known,
        "first_seen": rows[0]["first_seen"] if rows else None,
        "last_seen": rows[-1]["last_seen"] if rows else None,
        "occupied_buckets": len(rows),
        "total_buckets": len(points),
    }
    return {"range_key": key, "start": start, "end": end, "bucket_seconds": width,
            "points": points, "summary": summary}
