from typing import Protocol
from ..schemas import ModelResponse

class ModelClient(Protocol):
    def generate(self, messages: list[dict[str, str]], response_schema: dict | None = None) -> ModelResponse: ...
