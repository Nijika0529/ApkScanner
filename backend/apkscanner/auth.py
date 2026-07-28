from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AuthStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["start", "wait", "tap", "text", "keyevent", "assert_text"]
    component: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.$/]+$")
    seconds: float | None = Field(default=None, ge=0, le=30)
    x: int | None = Field(default=None, ge=0, le=10_000)
    y: int | None = Field(default=None, ge=0, le=10_000)
    secret: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_.-]{1,64}$")
    value: str | None = Field(default=None, max_length=500)
    keycode: int | None = Field(default=None, ge=0, le=1000)

    @model_validator(mode="after")
    def validate_action_fields(self) -> AuthStep:
        required = {
            "wait": self.seconds is not None,
            "tap": self.x is not None and self.y is not None,
            "text": (self.secret is None) != (self.value is None),
            "keyevent": self.keycode is not None,
            "assert_text": (
                self.value is not None
                and bool(self.value.strip())
                and self.secret is None
            ),
        }
        if self.action in required and not required[self.action]:
            raise ValueError(f"auth step {self.action!r} is missing required fields")
        return self


class AuthFlow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    profile: str = Field(default="default-single-account", min_length=1, max_length=128)
    package: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.]+$")
    steps: list[AuthStep] = Field(min_length=1, max_length=100)

    @property
    def required_secrets(self) -> set[str]:
        return {step.secret for step in self.steps if step.secret is not None}


def load_auth_flow(path: Path | None) -> AuthFlow | None:
    if path is None:
        return None
    if not path.is_file():
        raise ValueError(f"authentication flow does not exist: {path}")
    if path.stat().st_size > 1_000_000:
        raise ValueError("authentication flow exceeds 1 MB")
    return AuthFlow.model_validate(json.loads(path.read_text(encoding="utf-8")))


class CredentialStore:
    """Secret references backed by the host operating-system keyring."""

    service = "apk-scanner"

    @staticmethod
    def _key(profile: str, name: str) -> str:
        return f"{profile}:{name}"

    def set(self, profile: str, name: str, value: str) -> None:
        import keyring

        keyring.set_password(self.service, self._key(profile, name), value)

    def get(self, profile: str, name: str) -> str | None:
        import keyring

        return keyring.get_password(self.service, self._key(profile, name))

    def delete(self, profile: str, name: str) -> None:
        import keyring
        from keyring.errors import PasswordDeleteError

        try:
            keyring.delete_password(self.service, self._key(profile, name))
        except PasswordDeleteError:
            return
