import ipaddress
import unittest

from mailsentinel import analyze
from mailsentinel.types import (
    FAIL,
    NEUTRAL,
    PASS,
    PERMERROR,
    SOFTFAIL,
    Interval,
)


def assert_full_coverage(testcase, intervals):
    testcase.assertEqual(intervals[0].start, "0.0.0.0")
    testcase.assertEqual(intervals[-1].end, "255.255.255.255")
    for prev, cur in zip(intervals, intervals[1:]):
        testcase.assertEqual(
            int(ipaddress.ip_address(cur.start)),
            int(ipaddress.ip_address(prev.end)) + 1,
        )
    for cur in intervals[1:]:
        testcase.assertFalse(
            cur.verdict == intervals[intervals.index(cur) - 1].verdict
            and cur.count == intervals[intervals.index(cur) - 1].count,
            "adjacent intervals with identical verdict and count must be merged",
        )


class TestBasicMechanisms(unittest.TestCase):
    def test_ip4_and_all_qualifiers(self):
        intervals = analyze(
            {"r.com": "v=spf1 ip4:10.0.0.0/8 ?ip4:192.168.0.0/16 ~all"},
            "r.com",
        )
        self.assertEqual(
            intervals,
            [
                Interval("0.0.0.0", "9.255.255.255", SOFTFAIL, 0),
                Interval("10.0.0.0", "10.255.255.255", PASS, 0),
                Interval("11.0.0.0", "192.167.255.255", SOFTFAIL, 0),
                Interval("192.168.0.0", "192.168.255.255", NEUTRAL, 0),
                Interval("192.169.0.0", "255.255.255.255", SOFTFAIL, 0),
            ],
        )
        assert_full_coverage(self, intervals)

    def test_no_match_no_redirect_is_neutral(self):
        intervals = analyze({"r.com": "v=spf1 -ip4:10.0.0.0/8"}, "r.com")
        self.assertEqual(
            intervals,
            [
                Interval("0.0.0.0", "9.255.255.255", NEUTRAL, 0),
                Interval("10.0.0.0", "10.255.255.255", FAIL, 0),
                Interval("11.0.0.0", "255.255.255.255", NEUTRAL, 0),
            ],
        )

    def test_include_pass_applies_qualifier(self):
        intervals = analyze(
            {
                "r.com": "v=spf1 -include:a.com ~all",
                "a.com": "v=spf1 ip4:10.0.0.0/8",
            },
            "r.com",
        )
        self.assertEqual(
            intervals,
            [
                Interval("0.0.0.0", "9.255.255.255", SOFTFAIL, 1),
                Interval("10.0.0.0", "10.255.255.255", FAIL, 1),
                Interval("11.0.0.0", "255.255.255.255", SOFTFAIL, 1),
            ],
        )
        assert_full_coverage(self, intervals)

    def test_redirect_only_when_no_mechanism_matches(self):
        intervals = analyze(
            {
                "r.com": "v=spf1 ip4:10.0.0.0/8 redirect=b.com",
                "b.com": "v=spf1 -all",
            },
            "r.com",
        )
        self.assertEqual(
            intervals,
            [
                Interval("0.0.0.0", "9.255.255.255", FAIL, 1),
                Interval("10.0.0.0", "10.255.255.255", PASS, 0),
                Interval("11.0.0.0", "255.255.255.255", FAIL, 1),
            ],
        )
        assert_full_coverage(self, intervals)


class TestBudgetCounting(unittest.TestCase):
    def test_count_accumulates_across_nesting(self):
        intervals = analyze(
            {
                "r.com": "v=spf1 include:a.com -all",
                "a.com": "v=spf1 include:b.com ip4:10.0.0.0/8",
                "b.com": "v=spf1 ip4:10.0.0.0/8",
            },
            "r.com",
        )
        # 10/8: a.com's include:b.com passes -> count 2; others: -all -> count 2
        self.assertEqual(
            intervals,
            [
                Interval("0.0.0.0", "9.255.255.255", FAIL, 2),
                Interval("10.0.0.0", "10.255.255.255", PASS, 2),
                Interval("11.0.0.0", "255.255.255.255", FAIL, 2),
            ],
        )

    def test_eleventh_reference_is_permerror_with_count_11(self):
        # Only 128.0.0.0/1 falls into the self-loop; 0.0.0.0/1 passes early.
        intervals = analyze(
            {
                "r.com": "v=spf1 ip4:0.0.0.0/1 include:loop.com -all",
                "loop.com": "v=spf1 include:loop.com",
            },
            "r.com",
        )
        self.assertEqual(
            intervals,
            [
                Interval("0.0.0.0", "127.255.255.255", PASS, 0),
                Interval("128.0.0.0", "255.255.255.255", PERMERROR, 11),
            ],
        )
        assert_full_coverage(self, intervals)

    def test_permerror_propagates_through_include(self):
        intervals = analyze(
            {
                "r.com": "v=spf1 include:a.com -all",
                "a.com": "v=spf1 include:loop.com",
                "loop.com": "v=spf1 include:loop.com",
            },
            "r.com",
        )
        self.assertEqual(
            intervals, [Interval("0.0.0.0", "255.255.255.255", PERMERROR, 11)]
        )

    def test_redirect_loop_hits_budget(self):
        intervals = analyze(
            {
                "r.com": "v=spf1 redirect=a.com",
                "a.com": "v=spf1 redirect=r.com",
            },
            "r.com",
        )
        self.assertEqual(
            intervals, [Interval("0.0.0.0", "255.255.255.255", PERMERROR, 11)]
        )


class TestRepeatedIncludeAndPartialLoop(unittest.TestCase):
    def test_non_pass_include_continues_and_loop_is_partial(self):
        intervals = analyze(
            {
                "r.com": "v=spf1 include:a.com include:b.com -all",
                "a.com": "v=spf1 ip4:198.51.100.0/24",
                "b.com": "v=spf1 ip4:203.0.113.0/24 include:b.com",
            },
            "r.com",
        )
        self.assertEqual(
            intervals,
            [
                Interval("0.0.0.0", "198.51.99.255", PERMERROR, 11),
                Interval("198.51.100.0", "198.51.100.255", PASS, 1),
                Interval("198.51.101.0", "203.0.112.255", PERMERROR, 11),
                Interval("203.0.113.0", "203.0.113.255", PASS, 2),
                Interval("203.0.114.0", "255.255.255.255", PERMERROR, 11),
            ],
        )
        assert_full_coverage(self, intervals)

    def test_repeated_include_counts_each_time(self):
        intervals = analyze(
            {
                "r.com": "v=spf1 include:a.com include:a.com -all",
                "a.com": "v=spf1 ~all",
            },
            "r.com",
        )
        # a.com softfails (non-pass) both times; root falls through to -all.
        self.assertEqual(
            intervals, [Interval("0.0.0.0", "255.255.255.255", FAIL, 2)]
        )


if __name__ == "__main__":
    unittest.main()
