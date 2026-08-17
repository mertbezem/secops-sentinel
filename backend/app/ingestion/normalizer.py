import datetime
import hashlib


def parse_timestamp(time_str: str) -> datetime.datetime:
    """
    Parses a raw timestamp string and returns a timezone-aware UTC datetime object.
    Supports formats:
    - 2020-11-14 08:41:59
    - 2020-11-14T08:41:59Z
    - 2020-11-14T08:41:59.123Z
    """
    if not time_str or not time_str.strip():
        return datetime.datetime.now(datetime.UTC)

    s = time_str.strip().replace("T", " ").rstrip("Z")
    
    # Check for fractional seconds
    if "." in s:
        s = s.split(".")[0]
        
    try:
        dt = datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=datetime.UTC)
    except Exception:
        pass

    try:
        dt = datetime.datetime.strptime(s, "%Y-%m-%d")
        return dt.replace(tzinfo=datetime.UTC)
    except Exception:
        return datetime.datetime.now(datetime.UTC)


def compute_derived_fields(
    machine_name: str,
    source: str,
    entry_type: str,
    time_str: str,
    message: str
) -> tuple[datetime.datetime, int, int, bool, str]:
    """
    Calculates derived fields:
    (ts_utc, hour_of_day, day_of_week, is_business_hours, dedup_hash)
    """
    ts_utc = parse_timestamp(time_str)
    hour_of_day = ts_utc.hour
    day_of_week = ts_utc.weekday()  # 0=Mon, 6=Sun
    
    # Business hours: Mon-Fri (0-4), 08:00 <= hour < 18:00 UTC
    is_business_hours = (day_of_week < 5) and (8 <= hour_of_day < 18)
    
    # SHA-256 deduplication hash
    hash_input = f"{machine_name.strip()}|{source.strip()}|{entry_type.strip()}|{ts_utc.isoformat()}|{message.strip()}"
    dedup_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
    
    return ts_utc, hour_of_day, day_of_week, is_business_hours, dedup_hash
