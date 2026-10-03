"""Whole-IPv4-space interval analysis on top of the per-address evaluator."""

from __future__ import annotations

from .evaluator import Evaluator
from .types import Interval, MechanismKind, Record

_IPV4_SPACE = 1 << 32


def _boundaries(records: dict[str, Record]) -> list[int]:
    """Sorted split points where any ip4 mechanism match set may change."""
    points = {0, _IPV4_SPACE}
    for record in records.values():
        for mech in record.mechanisms:
            if mech.kind is MechanismKind.IP4:
                network_address, prefixlen = mech.value
                size = 1 << (32 - prefixlen)
                points.add(network_address)
                points.add(network_address + size)
    return sorted(points)


def analyze_records(records: dict[str, Record], root: str) -> list[Interval]:
    """Analyze parsed records, returning merged intervals covering all IPv4."""
    evaluator = Evaluator(records)
    points = _boundaries(records)

    intervals: list[Interval] = []
    for start, end in zip(points, points[1:]):
        # Verdict and count are constant within an atomic interval because
        # the set of matching ip4 mechanisms cannot change inside it.
        verdict, count = evaluator.evaluate(root, start)
        if (
            intervals
            and intervals[-1].verdict is verdict
            and intervals[-1].count == count
        ):
            intervals[-1] = Interval(
                intervals[-1].start, end, verdict, count
            )
        else:
            intervals.append(Interval(start, end, verdict, count))
    return intervals
