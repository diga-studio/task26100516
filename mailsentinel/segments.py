"""Partition of the IPv4 space by CIDR boundaries and interval merging."""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Tuple

from .types import Interval

_IPV4_SIZE = 1 << 32


def cidr_bounds(cidr: str) -> Tuple[int, int]:
    """Return (first, last) integer addresses of a CIDR (ip allowed w/o prefix)."""
    net = ipaddress.ip_network(cidr, strict=False)
    return int(net.network_address), int(net.broadcast_address)


def atomic_segments(cidrs: List[str]) -> List[Tuple[int, int]]:
    """Split [0, 2**32) into atomic segments aligned to all CIDR boundaries."""
    cuts = {0, _IPV4_SIZE}
    for cidr in cidrs:
        first, last = cidr_bounds(cidr)
        cuts.add(first)
        cuts.add(last + 1)
    ordered = sorted(cuts)
    return [(ordered[i], ordered[i + 1] - 1) for i in range(len(ordered) - 1)]


def merge_intervals(results: List[Tuple[int, int, str, int]]) -> List[Interval]:
    """Merge adjacent segments with identical (verdict, count)."""
    merged: List[Interval] = []
    for start, end, verdict, count in results:
        if merged and merged[-1].verdict == verdict and merged[-1].count == count:
            merged[-1] = Interval(
                start=merged[-1].start,
                end=str(ipaddress.ip_address(end)),
                verdict=verdict,
                count=count,
            )
        else:
            merged.append(
                Interval(
                    start=str(ipaddress.ip_address(start)),
                    end=str(ipaddress.ip_address(end)),
                    verdict=verdict,
                    count=count,
                )
            )
    return merged
