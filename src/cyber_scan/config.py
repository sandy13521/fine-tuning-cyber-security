from pathlib import Path
from typing import Literal
from urllib.parse import urlparse
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

class ModelConfig(StrictModel):
    provider: Literal["openai_compatible"] = "openai_compatible"
    model: str = Field(min_length=1)
    base_url: str
    api_key_env: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    timeout_seconds: float = Field(default=60, gt=0, le=300)
    retries: int = Field(default=2, ge=0, le=5)
    max_output_tokens: int = Field(default=1024, gt=0)
    token_parameter: Literal["max_tokens", "max_completion_tokens"] = "max_tokens"
    temperature: float | None = None
    response_format: Literal["prompt", "json_object", "json_schema"] = "prompt"

    @field_validator("base_url")
    @classmethod
    def validate_url(cls, value):
        url = urlparse(value)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("base_url must be HTTPS without credentials, query or fragment")
        return value.rstrip("/")

class AppConfig(StrictModel):
    input_dir: Path
    output_dir: Path = Path("runs")
    max_file_bytes: int = Field(default=2_000_000, gt=0)
    bundle_token_budget: int = Field(default=12000, ge=256)
    context_char_budget: int = Field(default=12000, ge=0)
    tokenizer: str = "utf8_bytes"
    include_globs: list[str] = Field(default_factory=lambda: ["*.java", "*.kt", "*.xml", "*.json", "*.properties", "*.txt", "*.smali", "*.js", "*.html"])
    exclude_globs: list[str] = Field(default_factory=list)
    models: dict[str, ModelConfig] = Field(default_factory=dict)

    @field_validator("tokenizer")
    @classmethod
    def validate_tokenizer(cls, value):
        if value != "utf8_bytes" and not value.startswith("tiktoken:"):
            raise ValueError("Use utf8_bytes or tiktoken:<encoding>")
        return value

def load_config(path: Path) -> AppConfig:
    config = AppConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    for name in ("input_dir", "output_dir"):
        value = getattr(config, name)
        setattr(config, name, (path.resolve().parent / value).resolve())
    return config
