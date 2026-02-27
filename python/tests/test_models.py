"""Tests for pcm_diff_analyzer.models — Pydantic model serialization/deserialization."""

from __future__ import annotations

from pcm_diff_analyzer.models import (
    ActionType,
    DiffKind,
    DiffReport,
    DiffResult,
    Label,
    Literal,
    Policy,
    Request,
    Rule,
    Verdict,
)


class TestActionType:
    def test_enum_values(self) -> None:
        assert ActionType.HTTP_OUT == 2
        assert ActionType.DB_WRITE == 3
        assert ActionType.TOOL_CALL == 1


class TestLabel:
    def test_ordering(self) -> None:
        assert Label.PUBLIC < Label.SECRET
        assert Label.CONFIDENTIAL >= Label.INTERNAL
        assert Label.SECRET > Label.PUBLIC

    def test_all_values(self) -> None:
        assert list(Label) == [
            Label.PUBLIC,
            Label.INTERNAL,
            Label.CONFIDENTIAL,
            Label.SECRET,
        ]


class TestRequest:
    def test_roundtrip(self) -> None:
        req = Request(
            request_id="r1",
            action_type=ActionType.HTTP_OUT,
            principal="alice",
            target="api.example.com",
            attributes={"key": "value"},
        )
        data = req.model_dump()
        restored = Request.model_validate(data)
        assert restored == req

    def test_defaults(self) -> None:
        req = Request(request_id="r2")
        assert req.action_type == ActionType.ACTION_TYPE_UNSPECIFIED
        assert req.principal == ""
        assert req.attributes == {}


class TestRuleAndPolicy:
    def test_rule_roundtrip(self) -> None:
        rule = Rule(
            head_predicate="deny",
            head_args=["Req", "reason"],
            body=[Literal(predicate="action", args=["Req", "HttpOut"], negated=False)],
            reason="test",
        )
        data = rule.model_dump()
        restored = Rule.model_validate(data)
        assert restored == rule

    def test_policy_roundtrip(self) -> None:
        policy = Policy(
            rules=[
                Rule(head_predicate="deny", head_args=["Req", "r1"]),
            ],
            version="1.0",
        )
        data = policy.model_dump()
        restored = Policy.model_validate(data)
        assert restored == policy
        assert len(restored.rules) == 1


class TestDiffModels:
    def test_diff_result_roundtrip(self) -> None:
        dr = DiffResult(
            kind=DiffKind.ESCALATION,
            example_request=Request(request_id="r1"),
            verdict_old=Verdict.DENY,
            verdict_new=Verdict.ALLOW,
        )
        data = dr.model_dump()
        restored = DiffResult.model_validate(data)
        assert restored.kind == DiffKind.ESCALATION
        assert restored == dr

    def test_diff_report_empty(self) -> None:
        report = DiffReport(diffs=[], is_equivalent=True, summary="identical")
        assert report.is_equivalent is True
        assert report.diffs == []
        data = report.model_dump()
        restored = DiffReport.model_validate(data)
        assert restored == report
