"""Parsing of SPF record text into Record objects."""

from __future__ import annotations

import ipaddress

from .types import Mechanism, MechanismKind, Record, Result

_QUALIFIERS = {
    "+": Result.PASS,
    "-": Result.FAIL,
    "~": Result.SOFTFAIL,
    "?": Result.NEUTRAL,
}


def parse_record(text: str) -> Record:
    """Parse one SPF record text (starting with "v=spf1") into a Record."""
    terms = text.split()
    if not terms or terms[0] != "v=spf1":
        raise ValueError(f"not an SPF record: {text!r}")

    mechanisms: list[Mechanism] = []
    redirect: str | None = None

    for term in terms[1:]:
        if term.startswith("redirect="):
            if redirect is not None:
                raise ValueError(f"duplicate redirect in: {text!r}")
            redirect = term[len("redirect="):]
            continue

        qualifier = _QUALIFIERS.get(term[0], Result.PASS)
        body = term[1:] if term[0] in _QUALIFIERS else term

        if body == "all":
            mechanisms.append(Mechanism(MechanismKind.ALL, qualifier))
        elif body.startswith("ip4:"):
            network = ipaddress.IPv4Network(body[len("ip4:"):], strict=False)
            value = (int(network.network_address), network.prefixlen)
            mechanisms.append(Mechanism(MechanismKind.IP4, qualifier, value))
        elif body.startswith("include:"):
            target = body[len("include:"):]
            mechanisms.append(Mechanism(MechanismKind.INCLUDE, qualifier, target))
        else:
            raise ValueError(f"unsupported term {term!r} in: {text!r}")

    return Record(mechanisms=tuple(mechanisms), redirect=redirect)


def parse_all(records: dict[str, str]) -> dict[str, Record]:
    """Parse a domain -> SPF text snapshot into domain -> Record."""
    return {domain: parse_record(text) for domain, text in records.items()}
