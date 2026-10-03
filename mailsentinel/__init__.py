"""MailSentinel: offline SPF path-budget analysis."""

from .analyze import analyze
from .types import Interval

__all__ = ["analyze", "Interval"]
