"""Z3/SMT encoding of PCM policies for diff analysis."""

from __future__ import annotations

from typing import TYPE_CHECKING

from z3 import Solver  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from pcm_diff_analyzer.models import DiffResult, Policy


class PolicyEncoder:
    """将 PCM 策略编码为 Z3 公式"""

    def __init__(self) -> None:
        self.solver = Solver()

    def encode_policy(self, policy: Policy) -> None:
        """编码策略规则为 Z3 约束。

        Args:
            policy: The policy to encode.
        """
        _ = policy  # TODO: implement encoding

    def find_diff(self, policy_old: Policy, policy_new: Policy) -> list[DiffResult]:
        """求解两个策略的差异。

        Args:
            policy_old: The old policy.
            policy_new: The new policy.

        Returns:
            A list of DiffResult instances describing differences.
        """
        _ = policy_old  # TODO: implement diff solving
        _ = policy_new
        return []
