"""Diff certificate generation for PCM policy diffs."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pcm_diff_analyzer.models import DiffReport


class DiffCertGenerator:
    """Generates a cryptographic certificate for a policy diff report."""

    def generate(self, report: DiffReport) -> bytes:
        """Generate a diff certificate from a DiffReport.

        Args:
            report: The diff report to certify.

        Returns:
            Serialised certificate bytes.
        """
        _ = report  # TODO: implement certificate generation
        return b""
