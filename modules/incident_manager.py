"""Incident model and validation of the incident submission form (workflow step 1)."""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

import pandas as pd

MAX_TITLE = 150
MAX_DESCRIPTION = 4000


@dataclass
class Incident:
    title: str
    description: str
    application: str
    start_time: pd.Timestamp
    end_time: pd.Timestamp
    affected_service: str = ""
    is_demo: bool = False
    incident_id: str = field(default_factory=lambda: new_incident_id())

    def to_dict(self) -> dict:
        data = asdict(self)
        data["start_time"] = iso(self.start_time)
        data["end_time"] = iso(self.end_time)
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Incident":
        return cls(
            title=data["title"],
            description=data["description"],
            application=data.get("application", ""),
            start_time=to_utc(data["start_time"]),
            end_time=to_utc(data["end_time"]),
            affected_service=data.get("affected_service", "") or "",
            is_demo=bool(data.get("is_demo", False)),
            incident_id=data["incident_id"],
        )


def new_incident_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"INC-{stamp}-{uuid.uuid4().hex[:4].upper()}"


def to_utc(value) -> pd.Timestamp:
    """Parse a value into a timezone-aware UTC timestamp (naive values are treated as UTC)."""
    ts = pd.Timestamp(value)
    if ts.tzinfo is None:
        return ts.tz_localize("UTC")
    return ts.tz_convert("UTC")


def iso(ts) -> str:
    if ts is None or (isinstance(ts, float) and pd.isna(ts)):
        return ""
    try:
        return to_utc(ts).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        return str(ts)


def build_incident(
    title: str,
    description: str,
    application: str,
    start_time,
    end_time,
    affected_service: str = "",
    is_demo: bool = False,
) -> tuple[Incident | None, list[str]]:
    """Validate form input. Returns (incident, errors); incident is None if invalid."""
    errors: list[str] = []
    title = (title or "").strip()
    description = (description or "").strip()
    application = (application or "").strip()
    affected_service = (affected_service or "").strip()

    if not title:
        errors.append("Incident title is required.")
    elif len(title) > MAX_TITLE:
        errors.append(f"Incident title must be at most {MAX_TITLE} characters.")
    if not description:
        errors.append("Incident description is required.")
    elif len(description) > MAX_DESCRIPTION:
        errors.append(f"Incident description must be at most {MAX_DESCRIPTION} characters.")
    if not application:
        errors.append("Application name is required.")

    start = end = None
    try:
        start = to_utc(start_time)
    except (ValueError, TypeError):
        errors.append("Incident start time is not a valid date/time.")
    try:
        end = to_utc(end_time)
    except (ValueError, TypeError):
        errors.append("Incident end time is not a valid date/time.")
    if start is not None and end is not None and end <= start:
        errors.append("Incident end time must be after the start time.")

    if errors:
        return None, errors
    return (
        Incident(
            title=title,
            description=description,
            application=application,
            start_time=start,
            end_time=end,
            affected_service=affected_service,
            is_demo=is_demo,
        ),
        [],
    )
