from typing import Literal
from pydantic import Field, model_validator
from .config import StrictModel

class SourceSpan(StrictModel):
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    snippet: str = Field(min_length=1)

    @model_validator(mode="after")
    def ordered(self):
        if self.end_line < self.start_line:
            raise ValueError("end_line precedes start_line")
        return self

class Finding(StrictModel):
    type: str
    cwe: str | None = None
    severity: Literal["info", "low", "medium", "high", "critical"]
    location: SourceSpan
    evidence: list[SourceSpan] = Field(min_length=1)
    explanation: str
    preconditions: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    status: Literal["static_evidence", "needs_runtime_validation"]

class Lesson(StrictModel):
    pattern: str
    required_evidence: list[str]
    counterevidence: list[str]
    inspection_steps: list[str]
    reporting_threshold: str

class LessonSet(StrictModel):
    lessons: list[Lesson] = Field(min_length=1, max_length=16)

class ModelResponse(StrictModel):
    model: str
    text: str
    usage: dict = Field(default_factory=dict)
    finish_reason: str | None = None
    latency_seconds: float
    attempts: int
