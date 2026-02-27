"""Tests for pcm_diff_analyzer.solver — PolicyEncoder instantiation."""

from __future__ import annotations

from pcm_diff_analyzer.solver import PolicyEncoder


class TestPolicyEncoder:
    def test_instantiation(self) -> None:
        encoder = PolicyEncoder()
        assert encoder.solver is not None
