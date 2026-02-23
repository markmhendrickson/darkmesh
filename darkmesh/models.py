from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class IngestRequest(BaseModel):
    dataset: str
    records: List[Dict]


class WarmIntroTarget(BaseModel):
    company: Optional[str] = None
    role: Optional[str] = None


class WarmIntroConstraints(BaseModel):
    max_candidates: int = Field(default=3, ge=1, le=10)
    min_strength: float = Field(default=0.5, ge=0.0, le=1.0)


class WarmIntroRequest(BaseModel):
    template: str = Field(default="warm_intro_v1")
    target: WarmIntroTarget
    constraints: WarmIntroConstraints = WarmIntroConstraints()


class PsiPayload(BaseModel):
    protocol: str = "dh-psi-v1"
    p: str
    x_values: List[str]


class WarmIntroPsiRequest(BaseModel):
    request_id: str
    requester_id: str
    target: WarmIntroTarget
    psi: PsiPayload


class WarmIntroPsiResponse(BaseModel):
    request_id: str
    eligible: bool
    responder: Optional[Dict] = None
    target_strength: Optional[float] = None
    psi: Optional[Dict] = None


class WarmIntroCandidate(BaseModel):
    pseudonym_id: str
    score: float
    requires_consent: bool = True
    consent_id: Optional[str] = None


class WarmIntroResponse(BaseModel):
    request_id: str
    candidates: List[WarmIntroCandidate]
    privacy_cost: float


class WarmIntroConsentRequest(BaseModel):
    request_id: str
    consent_id: str


class WarmIntroConsentResponse(BaseModel):
    request_id: str
    consent_id: str
    approved: bool
    pseudonym_id: str
    intro: Optional[Dict] = None
