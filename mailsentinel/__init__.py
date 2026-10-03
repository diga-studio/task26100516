"""MailSentinel: offline SPF path budget analysis over the IPv4 space."""

from __future__ import annotations

from .analyzer import analyze_records
from .parser import parse_all
from .types import Interval, Result


def analyze(records: dict[str, str], root: str) -> list[Interval]:
    """Analyze a domain -> SPF text snapshot rooted at ``root``.

    Returns a list of non-overlapping Intervals that cover the entire IPv4
    space, each carrying the final verdict and reference budget count.
    Adjacent intervals with identical verdict and count are merged.
    """
    return analyze_records(parse_all(records), root)


__all__ = ["analyze", "Interval", "Result"]
