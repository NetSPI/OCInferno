from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


class ErrorCode:
    UNKNOWN = "UNKNOWN"
    CONFIG_KEY_INVALID = "CONFIG_KEY_INVALID"
    CONFIG_VALUE_INVALID = "CONFIG_VALUE_INVALID"
    MODULE_EXECUTION_FAILED = "MODULE_EXECUTION_FAILED"
    MODULE_IMPORT_FAILED = "MODULE_IMPORT_FAILED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    TARGET_SELECTION_FAILED = "TARGET_SELECTION_FAILED"
    RETRY_POLICY_INVALID = "RETRY_POLICY_INVALID"


@dataclass
class OCIInfernoError(Exception):
    code: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        if self.details:
            return f"[{self.code}] {self.message} ({self.details})"
        return f"[{self.code}] {self.message}"


class ConfigError(OCIInfernoError):
    pass


class ModuleExecutionError(OCIInfernoError):
    pass


class AuthError(OCIInfernoError):
    pass


class RetryPolicyError(OCIInfernoError):
    pass


@dataclass
class OperationResult:
    ok: bool
    code: int = 0
    message: str = ""
    error_code: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def success(cls, message: str = "", *, error_code: str = "", **data: Any) -> "OperationResult":
        return cls(ok=True, code=0, message=message, error_code=str(error_code or ""), data=dict(data))

    @classmethod
    def failure(
        cls,
        message: str,
        code: int = 1,
        *,
        error_code: str = ErrorCode.UNKNOWN,
        **data: Any,
    ) -> "OperationResult":
        return cls(ok=False, code=int(code), message=message, error_code=str(error_code or ErrorCode.UNKNOWN), data=dict(data))

    @classmethod
    def from_exception(cls, exc: Exception, *, fallback_code: str = ErrorCode.UNKNOWN, **data: Any) -> "OperationResult":
        if isinstance(exc, OCIInfernoError):
            merged = dict(exc.details or {})
            merged.update(data)
            return cls.failure(exc.message, error_code=exc.code, **merged)
        # Keep OCI SDK ServiceError output concise; str(exc) can be a huge dict blob.
        if getattr(exc, "__class__", type(exc)).__name__ == "ServiceError":
            service = str(getattr(exc, "target_service", "") or "").strip()
            op = str(getattr(exc, "operation_name", "") or "").strip()
            status = str(getattr(exc, "status", "") or "").strip()
            code = str(getattr(exc, "code", "") or "").strip()
            msg = str(getattr(exc, "message", "") or "").strip() or str(exc)
            parts = []
            if service:
                parts.append(f"service={service}")
            if op:
                parts.append(f"operation={op}")
            if status:
                parts.append(f"status={status}")
            if code:
                parts.append(f"code={code}")
            parts.append(f"message={msg}")
            concise = "ServiceError(" + ", ".join(parts) + ")"
            return cls.failure(concise, error_code=fallback_code, **data)

        return cls.failure(f"{type(exc).__name__}: {exc}", error_code=fallback_code, **data)
