from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class VerificationStatus(StrEnum):
    confirmed = "CONFIRMED"
    failed = "FAILED"
    unclear = "UNCLEAR"


class AttackRequest(BaseModel):
    method: str
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any | None = None
    notes: str | None = None


class Finding(BaseModel):
    id: str
    service: str
    file: str
    line: int | None = None
    vulnerability_type: str
    owasp_api_category: str | None = None
    hypothesis: str
    confidence_initial: float = Field(ge=0, le=1)
    victim_identity: str | None = None
    attack_request: AttackRequest | None = None
    expected_response_signal: str | None = None
    setup_state: str | None = None
    target_state_required: str | None = None


class FindingSet(BaseModel):
    target: str = "crAPI"
    service: str
    source: str
    findings: list[Finding]


class SandboxExecution(BaseModel):
    command: list[str] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    timed_out: bool = False


class GeneratedPoc(BaseModel):
    poc_code: str
    success_criterion: str
    expected_evidence: str
    assumptions: list[str] = Field(default_factory=list)


class VerifiedFinding(Finding):
    poc_used: str
    success_criterion: str
    sandbox_execution: SandboxExecution
    status: VerificationStatus
    evidence: str
    confidence: float = Field(ge=0, le=1)
    needs_human_review: bool


class VerificationSet(BaseModel):
    target_url: HttpUrl
    service: str
    source: str
    findings: list[VerifiedFinding]


def load_findings(path: Path) -> FindingSet:
    return FindingSet.model_validate_json(path.read_text())


def load_verified(path: Path) -> VerificationSet:
    return VerificationSet.model_validate_json(path.read_text())


def model_dump_json(data: BaseModel | dict[str, Any]) -> str:
    if isinstance(data, BaseModel):
        return data.model_dump_json(indent=2)
    return BaseModel.model_validate(data).model_dump_json(indent=2)
