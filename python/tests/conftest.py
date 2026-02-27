"""Shared test fixtures for pcm_diff_analyzer tests."""

from __future__ import annotations

import pytest

from pcm_diff_analyzer.models import (
    ActionType,
    Literal,
    Policy,
    Request,
    Rule,
)


@pytest.fixture()
def empty_policy() -> Policy:
    """An empty policy with no rules."""
    return Policy(rules=[])


@pytest.fixture()
def sample_request() -> Request:
    """A sample HTTP-out request."""
    return Request(
        request_id="r1",
        action_type=ActionType.HTTP_OUT,
        principal="alice",
        target="api.example.com",
    )


@pytest.fixture()
def deny_rule() -> Rule:
    """A rule that denies unauthorised HTTP-out."""
    return Rule(
        head_predicate="deny",
        head_args=["Req", "unauthorized_http"],
        body=[
            Literal(predicate="action", args=["Req", "HttpOut", "P", "_"]),
            Literal(predicate="has_role", args=["P", "http_allowed"], negated=True),
        ],
        reason="unauthorized_http",
    )


@pytest.fixture()
def sample_policy(deny_rule: Rule) -> Policy:
    """A sample policy with one deny rule."""
    return Policy(rules=[deny_rule])
