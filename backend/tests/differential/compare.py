"""
Comparison and normalization for the differential harness.

The hazard with a harness like this is that it quietly passes: normalize too
much and two servers "agree" because every interesting field was erased. So
normalization here is deliberately narrow and explicit.

**Only these are normalized, and only for documented reasons:**

* `cred_id` -- `uuid4().hex` on both servers (`server.py:150`,
  `api/mint.py:register_device`), so it can never match. Replaced by a stable
  placeholder derived from the order it was issued in, which still detects a
  server returning the *wrong* credential.
* credential `expiry_ms` -- `now_ms() + 180d` on both, so it differs by the
  milliseconds between the two requests. Compared with a tolerance.
* `ts` -- `now_ms()`, same reasoning.
* `mint_sig` -- signs a string containing `cred_id`, so it cannot match once
  `cred_id` differs. **Not erased**: each signature is verified against its own
  server's `mint_pub` instead, which is a stronger check than equality.

Everything else is compared byte for byte, including `blind_sig`, `root`,
`proof`, `status` and `detail`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

#: Credential expiry and audit `ts` are wall-clock; the two requests cannot be
#: simultaneous. Tolerance is far tighter than any real divergence would be.
TIMESTAMP_TOLERANCE_MS = 10_000

#: A 32-character hex credential id.
_CRED_ID_RE = re.compile(r"\b[0-9a-f]{32}\b")


class Mismatch(AssertionError):
    """The two servers disagreed."""


@dataclass
class CredentialAliases:
    """Maps each server's `cred_id` values to shared placeholders.

    Registration order is the key: the nth credential issued by the reference
    and the nth issued by the backend are the same logical credential.
    """

    reference: dict[str, str] = field(default_factory=dict)
    backend: dict[str, str] = field(default_factory=dict)
    _next: int = 0

    def pair(self, reference_id: str, backend_id: str) -> str:
        placeholder = f"<cred-{self._next}>"
        self._next += 1
        self.reference[reference_id] = placeholder
        self.backend[backend_id] = placeholder
        return placeholder

    def substitute(self, value: Any, side: str) -> Any:
        """Replace known credential ids anywhere in a structure, including
        inside free-text `detail` strings such as
        `"...credential {cred_id} revoked"`."""
        table = self.reference if side == "reference" else self.backend
        if isinstance(value, str):
            for real, placeholder in table.items():
                value = value.replace(real, placeholder)
            return value
        if isinstance(value, dict):
            return {k: self.substitute(v, side) for k, v in value.items()}
        if isinstance(value, list):
            return [self.substitute(v, side) for v in value]
        return value


def _strip_volatile(value: Any, keys: tuple[str, ...]) -> Any:
    """Remove wall-clock fields, which are compared separately."""
    if isinstance(value, dict):
        return {
            k: _strip_volatile(v, keys) for k, v in value.items() if k not in keys
        }
    if isinstance(value, list):
        return [_strip_volatile(v, keys) for v in value]
    return value


def normalize(
    payload: Any,
    side: str,
    aliases: CredentialAliases | None = None,
    *,
    drop: tuple[str, ...] = (),
) -> Any:
    """Apply the documented normalizations and nothing else."""
    result = payload
    if aliases is not None:
        result = aliases.substitute(result, side)
    if drop:
        result = _strip_volatile(result, drop)
    return result


def _diff(left: Any, right: Any, path: str = "") -> list[str]:
    """Human-readable differences between two JSON structures."""
    if type(left) is not type(right) and not (
        isinstance(left, (int, float)) and isinstance(right, (int, float))
    ):
        return [f"{path or '<root>'}: type {type(left).__name__} != {type(right).__name__}"]

    if isinstance(left, dict):
        problems = []
        for key in sorted(set(left) | set(right)):
            where = f"{path}.{key}" if path else key
            if key not in left:
                problems.append(f"{where}: missing from reference (backend={right[key]!r})")
            elif key not in right:
                problems.append(f"{where}: missing from backend (reference={left[key]!r})")
            else:
                problems.extend(_diff(left[key], right[key], where))
        return problems

    if isinstance(left, list):
        if len(left) != len(right):
            return [f"{path or '<root>'}: length {len(left)} != {len(right)}"]
        problems = []
        for index, (a, b) in enumerate(zip(left, right)):
            problems.extend(_diff(a, b, f"{path}[{index}]"))
        return problems

    if left != right:
        return [f"{path or '<root>'}: {left!r} != {right!r}"]
    return []


def assert_json_equal(reference: Any, backend: Any, context: str = "") -> None:
    """Fail with a precise diff if the two payloads differ."""
    problems = _diff(reference, backend)
    if problems:
        header = f"servers disagree{f' on {context}' if context else ''}:"
        raise Mismatch(header + "\n  " + "\n  ".join(problems))


def assert_responses_equal(
    reference_response,
    backend_response,
    context: str = "",
    aliases: CredentialAliases | None = None,
    *,
    drop: tuple[str, ...] = (),
) -> tuple[Any, Any]:
    """Compare status code and body, returning both decoded bodies.

    Error bodies are compared too: both servers raise FastAPI `HTTPException`,
    so a non-2xx is `{"detail": "..."}` on each side and the detail strings must
    match.
    """
    if reference_response.status_code != backend_response.status_code:
        raise Mismatch(
            f"status differs{f' on {context}' if context else ''}: "
            f"reference={reference_response.status_code} "
            f"backend={backend_response.status_code}\n"
            f"  reference body: {reference_response.text[:300]}\n"
            f"  backend body:   {backend_response.text[:300]}"
        )

    reference_body = _decode(reference_response)
    backend_body = _decode(backend_response)

    assert_json_equal(
        normalize(reference_body, "reference", aliases, drop=drop),
        normalize(backend_body, "backend", aliases, drop=drop),
        context,
    )
    return reference_body, backend_body


def _decode(response) -> Any:
    try:
        return response.json()
    except ValueError:
        return {"<non-json body>": response.text}


def assert_close_in_time(reference_ms: int, backend_ms: int, context: str) -> None:
    """Two wall-clock values taken moments apart."""
    delta = abs(int(reference_ms) - int(backend_ms))
    if delta > TIMESTAMP_TOLERANCE_MS:
        raise Mismatch(
            f"{context}: timestamps differ by {delta}ms "
            f"(reference={reference_ms}, backend={backend_ms})"
        )


def looks_like_cred_id(value: str) -> bool:
    return bool(_CRED_ID_RE.fullmatch(value))
