"""Public entry point: analyze(records, root)."""

from __future__ import annotations

from typing import Dict, List

from .evaluator import evaluate_segment
from .parser import parse_records
from .segments import atomic_segments, cidr_bounds, merge_intervals
from .types import Interval


def analyze(records: Dict[str, str], root: str) -> List[Interval]:
    """Analyze SPF verdicts and budget counts over the whole IPv4 space.

    Returns disjoint, adjacent intervals covering 0.0.0.0-255.255.255.255,
    each carrying the final verdict and reference count for its addresses.
    Adjacent intervals with identical (verdict, count) are merged.
    """
    parsed = parse_records(records)
    if root not in parsed:
        raise KeyError(f"root domain {root!r} not present in records")

    cidrs = sorted(
        {m.value for rec in parsed.values() for m in rec.mechanisms if m.kind == "ip4"}
    )
    bounds = {cidr: cidr_bounds(cidr) for cidr in cidrs}

    results = []
    for seg_start, seg_end in atomic_segments(cidrs):
        def ip4_matches(cidr: str, _s: int = seg_start) -> bool:
            first, last = bounds[cidr]
            return first <= _s <= last

        verdict, count = evaluate_segment(parsed, root, ip4_matches)
        results.append((seg_start, seg_end, verdict, count))

    return merge_intervals(results)
