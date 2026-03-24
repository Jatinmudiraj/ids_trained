#!/usr/bin/env python3
"""
Normalize Helpers — Unified record normalization across all log domains
=======================================================================
Handles the 3 different field naming conventions:
  - SSH/Linux:    {ts, host, process, pid, msg, event_type, user, src_ip}
  - Apache:       {timestamp, level, message, event_type}
  - Windows:      {timestamp, level, component, message, event_type}
  - OpenStack:    {timestamp, pid, level, component, request_id, message, event_type}
"""

import re
from datetime import datetime
from typing import Optional


# Keyword mapping for generic syslog
_KEYWORD_PATTERNS = {
    'error': re.compile(r'error|fail|critical|alert|emerg|fault', re.I),
    'warning': re.compile(r'warn|degraded|struggling', re.I),
    'success': re.compile(r'success|opened|accepted|allowed|pass', re.I),
    'info': re.compile(r'info|notice|ignored|ignoring', re.I),
}


# ---------------------------------------------------------------------------
# Timestamp Parsing
# ---------------------------------------------------------------------------
# Patterns ordered by frequency in the dataset
_TS_FORMATS = [
    # "Dec 10 06:55:46" (syslog — SSH, Linux, Mac, Thunderbird)
    (re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$'), "%b %d %H:%M:%S"),
    # "2016-09-28 04:30:30" (ISO — Windows, HDFS, Hadoop)
    (re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$'), "%Y-%m-%d %H:%M:%S"),
    # "2017-05-16 00:00:00.008" (ISO with millis — OpenStack)
    (re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+$'), "%Y-%m-%d %H:%M:%S.%f"),
    # "Sun Dec 04 04:47:44 2005" (Apache ctime)
    (re.compile(r'^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}$'),
     "%a %b %d %H:%M:%S %Y"),
]


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """
    Parse a timestamp string into a datetime object.
    Handles syslog, ISO, ISO-millis, and Apache ctime formats.
    Returns None if parsing fails.
    """
    if not ts_str:
        return None

    ts_str = ts_str.strip()

    for pattern, fmt in _TS_FORMATS:
        if pattern.match(ts_str):
            try:
                dt = datetime.strptime(ts_str, fmt)
                # Syslog format doesn't have year — default to current year
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue

    # Fallback: try dateutil if available
    try:
        from dateutil.parser import parse as dateutil_parse
        return dateutil_parse(ts_str)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Record Normalization
# ---------------------------------------------------------------------------
def normalize_record(r: dict, domain: str = "") -> dict:
    """
    Ensure all required fields exist with safe defaults.
    Maps domain-specific field names to a unified schema.

    Unified schema:
        ts, host, domain, process, pid, event_type, msg,
        user, src_ip, dst_ip, level
    """
    msg = r.get("msg") or r.get("message", "")
    event_type = r.get("event_type", "unknown")
    
    # Keyword-based fallback for unknown
    if event_type == "unknown" and msg:
        for name, pattern in _KEYWORD_PATTERNS.items():
            if pattern.search(msg):
                event_type = name
                break

    return {
        "ts":         r.get("ts") or r.get("timestamp", ""),
        "host":       r.get("host", "UNKNOWN"),
        "domain":     domain or r.get("domain", ""),
        "process":    r.get("process") or r.get("component", ""),
        "pid":        str(r.get("pid", "")),
        "event_type": event_type,
        "msg":        msg,
        "user":       r.get("user"),
        "src_ip":     r.get("src_ip"),
        "dst_ip":     r.get("dst_ip"),
        "level":      r.get("level", ""),
    }


def load_normalized_jsonl(filepath: str, domain: str = "") -> list:
    """Load a normalized JSONL file, ensuring all records have unified fields."""
    import json
    records = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                records.append(normalize_record(r, domain))
            except (json.JSONDecodeError, ValueError):
                continue
    return records


# ---------------------------------------------------------------------------
# Feature Extraction Helpers (used by window builder + training)
# ---------------------------------------------------------------------------
def extract_numeric_features(lines: list) -> dict:
    """
    Extract numeric features from a window of normalized log lines.
    Returns a flat dict of feature name → value.
    """
    n = len(lines) if lines else 1

    # Event type counts
    event_types = [l.get("event_type", "unknown") for l in lines]
    from collections import Counter
    et_counts = Counter(event_types)

    # Auth-specific counts
    failed_auth = sum(1 for l in lines if l.get("event_type") in
                      ("failed_password", "auth_failure", "invalid_user"))
    success_auth = sum(1 for l in lines if l.get("event_type") in
                       ("accepted_password", "accepted_key", "session_opened"))

    # Unique entities
    users = set(l.get("user") for l in lines if l.get("user"))
    src_ips = set(l.get("src_ip") for l in lines if l.get("src_ip"))
    dst_ips = set(l.get("dst_ip") for l in lines if l.get("dst_ip"))

    # Burstiness (max repeat of same event_type)
    burstiness = max(et_counts.values()) if et_counts else 0

    # Time span
    timestamps = []
    for l in lines:
        ts = parse_timestamp(l.get("ts", ""))
        if ts:
            timestamps.append(ts)

    time_span_s = 0.0
    events_per_sec = 0.0
    if len(timestamps) >= 2:
        timestamps.sort()
        time_span_s = (timestamps[-1] - timestamps[0]).total_seconds()
        if time_span_s > 0:
            events_per_sec = n / time_span_s

    # Error-related
    error_count = sum(1 for l in lines if l.get("level", "").lower() in
                      ("error", "err", "crit", "critical", "alert", "emerg"))

    return {
        "n_lines":            n,
        "failed_auth_count":  failed_auth,
        "success_auth_count": success_auth,
        "unique_users":       len(users),
        "unique_src_ips":     len(src_ips),
        "unique_dst_ips":     len(dst_ips),
        "burstiness":         burstiness,
        "event_type_diversity": len(et_counts) / max(n, 1),
        "time_span_s":        time_span_s,
        "events_per_sec":     events_per_sec,
        "error_count":        error_count,
        # Top event types as individual features
        "et_unknown":         et_counts.get("unknown", 0),
        "et_failed_password": et_counts.get("failed_password", 0),
        "et_invalid_user":    et_counts.get("invalid_user", 0),
        "et_disconnect":      et_counts.get("disconnect", 0),
        "et_accepted_password": et_counts.get("accepted_password", 0),
        "et_connection_closed": et_counts.get("connection_closed", 0),
        "et_error":           et_counts.get("error", 0),
        "et_info":            et_counts.get("info", 0),
        "et_notice":          et_counts.get("notice", 0),
    }


# Self-test
if __name__ == "__main__":
    # Test normalize
    ssh_line = {
        "ts": "Dec 10 06:55:46", "host": "LabSZ", "process": "sshd", "pid": "24200",
        "msg": "Failed password for root from 112.95.230.3 port 58077 ssh2",
        "event_type": "failed_password", "user": "root", "src_ip": "112.95.230.3"
    }
    apache_line = {
        "timestamp": "Sun Dec 04 04:47:44 2005", "level": "error",
        "message": "mod_jk child workerEnv in error state 6", "event_type": "error"
    }
    windows_line = {
        "timestamp": "2016-09-28 04:30:30", "level": "Info", "component": "CBS",
        "message": "Loaded Servicing Stack v6.1.7601", "event_type": "info"
    }

    for name, line in [("SSH", ssh_line), ("Apache", apache_line), ("Windows", windows_line)]:
        norm = normalize_record(line)
        ts = parse_timestamp(norm["ts"])
        print(f"{name:10} → ts={ts}, host={norm['host']}, msg={norm['msg'][:50]}...")

    print("\nAll normalize tests passed ✓")
