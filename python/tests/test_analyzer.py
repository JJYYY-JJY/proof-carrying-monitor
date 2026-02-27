"""Tests for pcm_diff_analyzer.analyzer — DiffAnalyzer instantiation and analysis."""

from __future__ import annotations

from pcm_diff_analyzer.analyzer import DiffAnalyzer
from pcm_diff_analyzer.models import DiffReport, Policy


class TestDiffAnalyzer:
    def test_instantiation(self, empty_policy: Policy) -> None:
        analyzer = DiffAnalyzer(policy_old=empty_policy, policy_new=empty_policy)
        assert analyzer.policy_old == empty_policy
        assert analyzer.policy_new == empty_policy

    def test_analyze_returns_diff_report(self, empty_policy: Policy, sample_policy: Policy) -> None:
        analyzer = DiffAnalyzer(policy_old=empty_policy, policy_new=sample_policy)
        report = analyzer.analyze()
        assert isinstance(report, DiffReport)
        # Stub implementation returns equivalent
        assert report.is_equivalent is True
        assert report.diffs == []
