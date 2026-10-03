"""Parsing of SPF record text into Record structures."""

from __future__ import annotations

from typing import Dict

from .types import Mechanism, Record

_QUALIFIERS = "+-~?"


def parse_record(text: str) -> Record:
    """Parse a single SPF record text into a Record."""
    terms = text.split()
    if not terms or terms[0] != "v=spf1":
        raise ValueError(f"not an SPF record: {text!r}")

    mechanisms = []
    redirect = None
    for term in terms[1:]:
        if term.startswith("redirect="):
            redirect = term[len("redirect="):]
            continue
        qualifier = "+"
        if term[0] in _QUALIFIERS:
            qualifier = term[0]
            term = term[1:]
        if term == "all":
            mechanisms.append(Mechanism(kind="all", qualifier=qualifier))
        elif term.startswith("ip4:"):
            mechanisms.append(
                Mechanism(kind="ip4", qualifier=qualifier, value=term[len("ip4:"):])
            )
        elif term.startswith("include:"):
            mechanisms.append(
                Mechanism(
                    kind="include", qualifier=qualifier, value=term[len("include:"):]
                )
            )
        else:
            raise ValueError(f"unsupported term: {term!r}")
    return Record(mechanisms=mechanisms, redirect=redirect)


def parse_records(records: Dict[str, str]) -> Dict[str, Record]:
    """Parse a domain -> SPF-text snapshot into domain -> Record."""
    return {domain: parse_record(text) for domain, text in records.items()}
