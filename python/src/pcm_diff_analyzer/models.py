"""Core data models for PCM diff analysis, aligned with proto definitions."""

from __future__ import annotations

from enum import IntEnum

from pydantic import BaseModel


class ActionType(IntEnum):
    """Action types matching proto ActionType enum."""

    ACTION_TYPE_UNSPECIFIED = 0
    TOOL_CALL = 1
    HTTP_OUT = 2
    DB_WRITE = 3
    DB_READ_SENSITIVE = 4
    FILE_WRITE = 5
    FILE_READ = 6
    CUSTOM = 15


class Label(IntEnum):
    """Security labels with total ordering (lower value = less sensitive)."""

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Label):
            return NotImplemented
        return self.value <= other.value

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Label):
            return NotImplemented
        return self.value < other.value

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Label):
            return NotImplemented
        return self.value >= other.value

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Label):
            return NotImplemented
        return self.value > other.value


class Verdict(IntEnum):
    """Decision verdict matching proto Verdict enum."""

    VERDICT_UNSPECIFIED = 0
    ALLOW = 1
    DENY = 2
    ERROR = 3


class DiffKind(IntEnum):
    """Kind of policy difference."""

    DIFF_KIND_UNSPECIFIED = 0
    ESCALATION = 1  # Deny -> Allow
    BREAKING = 2  # Allow -> Deny


class Request(BaseModel):
    """A monitored request, aligned with proto Request."""

    request_id: str
    action_type: ActionType = ActionType.ACTION_TYPE_UNSPECIFIED
    principal: str = ""
    target: str = ""
    attributes: dict[str, str] = {}


class Literal(BaseModel):
    """A literal in a rule body (positive or negative atom reference)."""

    predicate: str
    args: list[str] = []
    negated: bool = False


class Rule(BaseModel):
    """A single policy rule (head :- body)."""

    head_predicate: str
    head_args: list[str] = []
    body: list[Literal] = []
    reason: str = ""


class Policy(BaseModel):
    """A PCM policy consisting of a list of rules."""

    rules: list[Rule] = []
    version: str = ""
    content_hash: str = ""


class DiffResult(BaseModel):
    """A single difference between two policies."""

    kind: DiffKind
    example_request: Request
    verdict_old: Verdict
    verdict_new: Verdict


class DiffReport(BaseModel):
    """Report summarising all differences between two policies."""

    diffs: list[DiffResult] = []
    is_equivalent: bool = True
    summary: str = ""
