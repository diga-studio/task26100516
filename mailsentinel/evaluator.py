"""Per-address SPF evaluation with reference budget counting."""

from __future__ import annotations

from .types import MechanismKind, Record, Result

# Maximum number of include/redirect references allowed per evaluation.
# Attempting the (MAX_REFERENCES + 1)-th reference yields permerror.
MAX_REFERENCES = 10


class Evaluator:
    """Evaluates parsed records for one source IPv4 address at a time."""

    def __init__(self, records: dict[str, Record]) -> None:
        self._records = records

    def evaluate(self, root: str, address: int) -> tuple[Result, int]:
        """Return (verdict, reference count) for one IPv4 address."""
        # Reading the root record itself does not count against the budget.
        return self._eval_domain(root, address, 0)

    def _eval_domain(
        self, domain: str, address: int, count: int
    ) -> tuple[Result, int]:
        record = self._records[domain]

        for mech in record.mechanisms:
            if mech.kind is MechanismKind.IP4:
                network_address, prefixlen = mech.value
                mask = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF
                if address & mask == network_address & mask:
                    return mech.qualifier, count
            elif mech.kind is MechanismKind.ALL:
                return mech.qualifier, count
            else:  # INCLUDE
                count += 1
                if count > MAX_REFERENCES:
                    return Result.PERMERROR, count
                target_result, count = self._eval_domain(
                    mech.value, address, count
                )
                if target_result is Result.PERMERROR:
                    return Result.PERMERROR, count
                if target_result is Result.PASS:
                    return mech.qualifier, count
                # fail / softfail / neutral: include does not match, continue.

        if record.redirect is not None:
            count += 1
            if count > MAX_REFERENCES:
                return Result.PERMERROR, count
            return self._eval_domain(record.redirect, address, count)

        return Result.NEUTRAL, count
