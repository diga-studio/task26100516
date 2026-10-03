"""End-to-end tests for MailSentinel SPF path budget analysis."""

from __future__ import annotations

import ipaddress

import pytest

from mailsentinel import analyze
from mailsentinel.evaluator import Evaluator
from mailsentinel.parser import parse_all
from mailsentinel.types import Result

IPV4_SPACE = 1 << 32


def ip(text: str) -> int:
    return int(ipaddress.IPv4Address(text))


def as_tuples(intervals):
    return [(iv.start, iv.end, iv.verdict, iv.count) for iv in intervals]


def assert_tiling(intervals):
    """Intervals must cover all IPv4, be disjoint, and be maximally merged."""
    assert intervals, "expected at least one interval"
    assert intervals[0].start == 0
    assert intervals[-1].end == IPV4_SPACE
    for prev, cur in zip(intervals, intervals[1:]):
        assert prev.end == cur.start, "gap or overlap between intervals"
        assert (prev.verdict, prev.count) != (cur.verdict, cur.count), (
            "adjacent intervals with identical verdict and count must be merged"
        )


def assert_matches_evaluator(records, root, intervals):
    """Every interval boundary (+/-1) must agree with per-address evaluation."""
    evaluator = Evaluator(parse_all(records))
    samples = {0, IPV4_SPACE - 1}
    for iv in intervals:
        samples.add(iv.start)
        samples.add(iv.end - 1)
        if iv.end < IPV4_SPACE:
            samples.add(iv.end)
    for address in sorted(samples):
        verdict, count = evaluator.evaluate(root, address)
        iv = next(i for i in intervals if i.start <= address < i.end)
        assert (iv.verdict, iv.count) == (verdict, count), hex(address)


@pytest.mark.parametrize(
    "qualifier,expected",
    [
        ("+", Result.PASS),
        ("-", Result.FAIL),
        ("~", Result.SOFTFAIL),
        ("?", Result.NEUTRAL),
        ("", Result.PASS),  # default qualifier is "+"
    ],
)
def test_qualifiers(qualifier, expected):
    intervals = analyze({"root": f"v=spf1 {qualifier}all"}, "root")
    assert as_tuples(intervals) == [(0, IPV4_SPACE, expected, 0)]


def test_no_match_without_redirect_is_neutral():
    intervals = analyze({"root": "v=spf1 ip4:10.0.0.0/8"}, "root")
    assert_tiling(intervals)
    assert as_tuples(intervals) == [
        (0, ip("10.0.0.0"), Result.NEUTRAL, 0),
        (ip("10.0.0.0"), ip("11.0.0.0"), Result.PASS, 0),
        (ip("11.0.0.0"), IPV4_SPACE, Result.NEUTRAL, 0),
    ]


def test_adjacent_intervals_with_same_result_are_merged():
    records = {"root": "v=spf1 ip4:10.0.0.0/24 ip4:10.0.1.0/24 ip4:10.0.2.0/24 -all"}
    intervals = analyze(records, "root")
    assert_tiling(intervals)
    assert as_tuples(intervals) == [
        (0, ip("10.0.0.0"), Result.FAIL, 0),
        (ip("10.0.0.0"), ip("10.0.3.0"), Result.PASS, 0),
        (ip("10.0.3.0"), IPV4_SPACE, Result.FAIL, 0),
    ]


def test_redirect_counts_and_adopts_target_result():
    records = {
        "root": "v=spf1 ip4:10.0.0.0/8 redirect=t",
        "t": "v=spf1 ~include:u ip4:192.0.2.0/24",
        "u": "v=spf1 ip4:203.0.113.0/24 ?all",
    }
    intervals = analyze(records, "root")
    assert_tiling(intervals)
    assert_matches_evaluator(records, "root", intervals)
    assert as_tuples(intervals) == [
        # outside 10/8: redirect (1) + include (1); u neutral -> no match
        (0, ip("10.0.0.0"), Result.NEUTRAL, 2),
        # inside 10/8: root ip4 matches before redirect
        (ip("10.0.0.0"), ip("11.0.0.0"), Result.PASS, 0),
        (ip("11.0.0.0"), ip("192.0.2.0"), Result.NEUTRAL, 2),
        # u neutral -> include no match -> t ip4 matches
        (ip("192.0.2.0"), ip("192.0.3.0"), Result.PASS, 2),
        (ip("192.0.3.0"), ip("203.0.113.0"), Result.NEUTRAL, 2),
        # u pass -> include matches -> qualifier "~" applies
        (ip("203.0.113.0"), ip("203.0.114.0"), Result.SOFTFAIL, 2),
        (ip("203.0.114.0"), IPV4_SPACE, Result.NEUTRAL, 2),
    ]


def test_redirect_loop_yields_permerror_everywhere():
    records = {
        "root": "v=spf1 redirect=r",
        "r": "v=spf1 redirect=r",
    }
    intervals = analyze(records, "root")
    assert as_tuples(intervals) == [(0, IPV4_SPACE, Result.PERMERROR, 11)]


def test_eleventh_reference_only_reached_by_small_segment():
    """Only a small address segment reaches the 11th reference; the rest
    pass early through progressively narrower ip4 exits."""
    ranges = [
        "128.0.0.0/1", "64.0.0.0/2", "32.0.0.0/3", "16.0.0.0/4",
        "8.0.0.0/5", "4.0.0.0/6", "2.0.0.0/7", "1.0.0.0/8",
        "0.128.0.0/9", "0.64.0.0/10",
    ]
    records = {"root": "v=spf1 include:d1 -all"}
    for index, cidr in enumerate(ranges, start=1):
        records[f"d{index}"] = f"v=spf1 ip4:{cidr} include:d{index + 1} ~all"
    records["d11"] = "v=spf1 ~all"  # referenced but never actually read

    intervals = analyze(records, "root")
    assert_tiling(intervals)
    assert_matches_evaluator(records, "root", intervals)
    assert as_tuples(intervals) == [
        (ip("0.0.0.0"), ip("0.64.0.0"), Result.PERMERROR, 11),
        (ip("0.64.0.0"), ip("0.128.0.0"), Result.PASS, 10),
        (ip("0.128.0.0"), ip("1.0.0.0"), Result.PASS, 9),
        (ip("1.0.0.0"), ip("2.0.0.0"), Result.PASS, 8),
        (ip("2.0.0.0"), ip("4.0.0.0"), Result.PASS, 7),
        (ip("4.0.0.0"), ip("8.0.0.0"), Result.PASS, 6),
        (ip("8.0.0.0"), ip("16.0.0.0"), Result.PASS, 5),
        (ip("16.0.0.0"), ip("32.0.0.0"), Result.PASS, 4),
        (ip("32.0.0.0"), ip("64.0.0.0"), Result.PASS, 3),
        (ip("64.0.0.0"), ip("128.0.0.0"), Result.PASS, 2),
        (ip("128.0.0.0"), IPV4_SPACE, Result.PASS, 1),
    ]


def _complement(*cidrs: str):
    """CIDR list covering all of IPv4 except the given networks."""
    parts = [ipaddress.IPv4Network("0.0.0.0/0")]
    for cidr in cidrs:
        net = ipaddress.IPv4Network(cidr)
        parts = [
            piece
            for part in parts
            for piece in (part.address_exclude(net) if net.subnet_of(part) else [part])
        ]
    return parts


def test_repeated_include_non_pass_continues_and_loop_is_partial():
    """Repeated includes whose target returns non-pass must continue, and a
    reference loop must only affect the addresses that actually enter it."""
    complement = _complement("192.0.2.0/24", "203.0.113.0/24")
    z_terms = " ".join(
        ["ip4:203.0.113.0/24"] + [f"-ip4:{net}" for net in complement] + ["include:z"]
    )
    records = {
        "root": "v=spf1 include:x include:x ?all",
        "x": "v=spf1 include:y -all",
        "y": "v=spf1 ip4:198.51.100.0/24 include:z ~all",
        "z": f"v=spf1 {z_terms}",
    }

    intervals = analyze(records, "root")
    assert_tiling(intervals)
    assert_matches_evaluator(records, "root", intervals)
    assert as_tuples(intervals) == [
        (0, ip("192.0.2.0"), Result.NEUTRAL, 6),
        # only this segment actually walks into the z -> z loop
        (ip("192.0.2.0"), ip("192.0.3.0"), Result.PERMERROR, 11),
        (ip("192.0.3.0"), ip("198.51.100.0"), Result.NEUTRAL, 6),
        # y ip4 matches -> y pass -> x pass -> first include matches
        (ip("198.51.100.0"), ip("198.51.101.0"), Result.PASS, 2),
        (ip("198.51.101.0"), ip("203.0.113.0"), Result.NEUTRAL, 6),
        # z ip4 matches -> z pass -> y pass -> x pass
        (ip("203.0.113.0"), ip("203.0.114.0"), Result.PASS, 3),
        (ip("203.0.114.0"), IPV4_SPACE, Result.NEUTRAL, 6),
    ]


def test_permerror_propagates_through_include_chain():
    records = {
        "root": "v=spf1 include:a -all",
        "a": "v=spf1 include:b +all",
        "b": "v=spf1 include:b",
    }
    intervals = analyze(records, "root")
    assert as_tuples(intervals) == [(0, IPV4_SPACE, Result.PERMERROR, 11)]
