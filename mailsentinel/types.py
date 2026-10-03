"""Core data types for MailSentinel SPF path budget analysis."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Result(Enum):
    """SPF evaluation results."""

    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    PERMERROR = "permerror"


class MechanismKind(Enum):
    IP4 = "ip4"
    INCLUDE = "include"
    ALL = "all"


@dataclass(frozen=True)
class Mechanism:
    """A single SPF mechanism with its qualifier."""

    kind: MechanismKind
    qualifier: Result
    # For IP4: (network_address, prefix_length). For INCLUDE: target domain.
    value: object = None


@dataclass(frozen=True)
class Record:
    """A parsed SPF record: ordered mechanisms plus optional redirect."""

    mechanisms: tuple[Mechanism, ...]
    redirect: Optional[str] = None


@dataclass(frozen=True)
class Interval:
    """A half-open IPv4 interval [start, end) with uniform verdict and count."""

    start: int
    end: int  # exclusive
    verdict: Result
    count: int
