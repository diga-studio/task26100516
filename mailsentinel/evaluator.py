"""Per-segment SPF evaluation with reference budget counting."""

from __future__ import annotations

from typing import Callable, Dict, Tuple

from .types import (
    MAX_REFERENCES,
    NEUTRAL,
    PASS,
    PERMERROR,
    QUALIFIER_TO_VERDICT,
    Record,
)


def evaluate_segment(
    parsed: Dict[str, Record],
    root: str,
    ip4_matches: Callable[[str], bool],
) -> Tuple[str, int]:
    """Evaluate the SPF policy for one atomic segment.

    ``ip4_matches(cidr)`` reports whether an ip4 mechanism's CIDR covers the
    segment (sound because segments are atomic w.r.t. all CIDRs).
    Returns (verdict, count).
    """

    def eval_domain(domain: str, count: int) -> Tuple[str, int]:
        record = parsed[domain]
        for mech in record.mechanisms:
            if mech.kind == "ip4":
                if ip4_matches(mech.value):
                    return QUALIFIER_TO_VERDICT[mech.qualifier], count
            elif mech.kind == "all":
                return QUALIFIER_TO_VERDICT[mech.qualifier], count
            elif mech.kind == "include":
                count += 1
                if count > MAX_REFERENCES:
                    return PERMERROR, count
                verdict, count = eval_domain(mech.value, count)
                if verdict == PASS:
                    return QUALIFIER_TO_VERDICT[mech.qualifier], count
                if verdict == PERMERROR:
                    return PERMERROR, count
                # fail / softfail / neutral: include does not match, continue
        if record.redirect is not None:
            count += 1
            if count > MAX_REFERENCES:
                return PERMERROR, count
            return eval_domain(record.redirect, count)
        return NEUTRAL, count

    return eval_domain(root, 0)
