"""
ADFIR Platform — Datetime Utilities
=====================================
Helper functions for timezone-aware datetime handling used throughout
the platform.  All timestamps are stored and compared in UTC.
"""

from datetime import datetime, timezone, timedelta


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime object."""
    return datetime.now(timezone.utc)


def to_utc(dt: datetime) -> datetime:
    """
    Ensure a datetime is timezone-aware and in UTC.
    If the datetime is naive (no tzinfo), it is assumed to be UTC.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def seconds_ago(seconds: int) -> datetime:
    """Return a UTC datetime that is ``seconds`` seconds in the past."""
    return utc_now() - timedelta(seconds=seconds)


def is_within_window(dt: datetime, window_seconds: int) -> bool:
    """
    Return True if ``dt`` occurred within the last ``window_seconds`` seconds.

    Args:
        dt: A timezone-aware datetime to check.
        window_seconds: The size of the look-back window in seconds.
    """
    threshold = seconds_ago(window_seconds)
    return to_utc(dt) >= threshold


def is_outside_business_hours(dt: datetime | None = None) -> bool:
    """
    Return True if the given datetime (or now) falls outside typical
    business hours (09:00–18:00 UTC Monday–Friday).
    Used by the Severity Classifier to calculate the time_risk_score.
    """
    dt = dt or utc_now()
    dt_utc = to_utc(dt)
    hour = dt_utc.hour
    weekday = dt_utc.weekday()  # Monday=0, Sunday=6
    is_weekend = weekday >= 5
    is_outside_hours = hour < 9 or hour >= 18
    return is_weekend or is_outside_hours
