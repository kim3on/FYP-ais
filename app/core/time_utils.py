from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo


MALAYSIA_TZ = ZoneInfo("Asia/Kuala_Lumpur")
MALAYSIA_TIME_LABEL = "MYT"


def parse_datetime_as_utc(value) -> datetime | None:
    """Parse app timestamps, treating legacy timezone-less values as UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = str(value).strip()
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            try:
                parsed = datetime.fromisoformat(raw.replace(" ", "T"))
            except ValueError:
                return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def to_malaysia_datetime(value=None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc).astimezone(MALAYSIA_TZ)
    parsed = parse_datetime_as_utc(value)
    if parsed is None:
        return datetime.now(timezone.utc).astimezone(MALAYSIA_TZ)
    return parsed.astimezone(MALAYSIA_TZ)


def format_malaysia_timestamp(value, fallback: str = "") -> str:
    parsed = parse_datetime_as_utc(value)
    if parsed is None:
        return fallback
    return f"{parsed.astimezone(MALAYSIA_TZ).strftime('%Y-%m-%d %H:%M:%S')} {MALAYSIA_TIME_LABEL}"


def now_malaysia_timestamp() -> str:
    return f"{to_malaysia_datetime().strftime('%Y-%m-%d %H:%M:%S')} {MALAYSIA_TIME_LABEL}"


def malaysia_filename_timestamp(value=None) -> str:
    return to_malaysia_datetime(value).strftime("%Y%m%d_%H%M%S")
