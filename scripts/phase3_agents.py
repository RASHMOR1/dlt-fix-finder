#!/usr/bin/env python3
"""Optional agent-backed helpers for phase 3 and phase 4."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)
LIMIT_EXHAUSTION_PATTERNS = (
    "rate limit",
    "rate-limit",
    "429",
    "too many requests",
    "quota",
    "usage limit",
    "limit reached",
    "out of credits",
    "credit balance is too low",
    "credits balance is too low",
    "retry after",
    "try again later",
)
DEFAULT_CODEX_MODEL = "gpt-5.4"

MAPPER_INSTRUCTIONS = """You are the Mapper agent for vulnerability-fix analysis.

Your job is to map the commit into the correct project subsystem and bug shape before anyone writes prose.

Rules:
- Use only the provided commit, patch evidence, and project context.
- First reconstruct the protocol/security invariant that the patch could affect. If no security-relevant invariant is changed, say so explicitly.
- Prefer conservative labels over dramatic ones.
- Do not claim exploitability unless the code clearly supports it.
- If the patch looks like an API cleanup, role removal, serialization baseline update, test-only change, migration, performance change, or refactor, classify it as non-security unless the code evidence shows a concrete security invariant being fixed.
- If context_depth is deep, use the traced subsystem context to map the real business-logic path instead of over-weighting helper modules.
- Return JSON only.

Return an object with these keys:
- subsystem: short slug
- bug_class: short slug
- confidence: one of low, medium, high
- security_verdict: one of confirmed, likely, unclear, not-security
- validated_as: one of security-fix, security-hardening, unclear, not-security
- keep_in_security_corpus: boolean
- protocol_security_invariant: short paragraph describing the invariant, or why none is shown
- rationale: short paragraph
- affected_code_paths: array of objects with file, line, role
- claim_boundaries: array of short strings describing what is not proven by the patch
"""

DRAFTER_INSTRUCTIONS = """You are the Drafter agent for vulnerability-fix analysis.

Write a finding draft from the mapper result and provided code evidence.

Rules:
- Use only the supplied evidence.
- Be explicit about observed changes before inference.
- Keep the report useful for RAG retrieval and later manual review.
- Do not invent impact claims that are not grounded in the code.
- If the mapper did not identify a grounded security invariant, write the draft as a rejection note instead of forcing a vulnerability narrative.
- If context_depth is deep, reconstruct the before/after behavior explicitly from the changed paths and traced subsystem context.
- Return JSON only.

Return an object with these keys:
- summary
- before_after_behavior
- root_cause
- walkthrough: array of numbered-step strings without the numbers
- fix_pattern
- how_it_was_fixed
- why_it_matters: array of short bullet strings
- evidence_notes
"""

SKEPTIC_INSTRUCTIONS = """You are the Skeptic agent for vulnerability-fix analysis.

You review the mapper and drafter outputs and remove unsupported claims.

Rules:
- Be strict about evidence.
- Downgrade subsystem, bug class, or confidence if the code does not support the stronger claim.
- Set `security_verdict` to `not-security` and `keep_in_security_corpus` to false when the patch is just cleanup, refactor, testing, migration, role removal, serialization baseline update, or other non-vulnerability work.
- Set `security_verdict` to `unclear` and `keep_in_security_corpus` to false when the patch may be security relevant but the vulnerability thesis is not established by the provided evidence.
- Preserve useful grounded explanation when possible.
- If helper files were added, treat them as support code unless the evidence clearly makes them the root cause.
- Return JSON only.

Return an object with these keys:
- subsystem
- bug_class
- confidence: one of low, medium, high
- security_verdict: one of confirmed, likely, unclear, not-security
- validated_as: one of security-fix, security-hardening, unclear, not-security
- keep_in_security_corpus: boolean
- protocol_security_invariant
- summary
- before_after_behavior
- root_cause
- walkthrough: array of step strings
- fix_pattern
- how_it_was_fixed
- why_it_matters: array of short bullet strings
- evidence_notes
- verification_notes: array of short strings
"""

VALIDATOR_INSTRUCTIONS = """You are the Validator agent for a security-fix corpus.

You review a generated finding and decide whether the supplied code evidence actually supports keeping it in a security-focused corpus.

Rules:
- Use only the provided finding, commit metadata, patch evidence, and project context.
- Be conservative. A commit can be a real bug fix and still be `not-security` or `unclear` from the patch alone.
- Use `not-security` for product work, API cleanup, migrations, performance work, reliability-only fixes, or maintenance changes.
- Use `unclear` when the patch may be security relevant but the evidence does not prove that confidently.
- Use `security-hardening` when the patch clearly tightens security-sensitive behavior or removes an exposed risky condition, even if the patch does not prove a concrete exploitable bug.
- Use `security-fix` only when the code strongly supports that a security issue was being fixed.
- `keep_in_security_corpus` should be true only when the evidence supports retaining the finding as a security-fix or security-hardening case.
- Use `final_bug_class`, `final_impact_type`, `final_confidence`, and `final_tags` when the original phase-3 metadata is too strong, too specific, or misleading for a RAG corpus; otherwise leave them null/empty.
- Return JSON only.

Return an object with these keys:
- validation_status: one of completed, failed
- security_verdict: one of confirmed, likely, unclear, not-security
- validated_as: one of security-fix, security-hardening, unclear, not-security
- keep_in_security_corpus: boolean
- final_bug_class: conservative slug for the validated finding, or null when the original is already accurate
- final_impact_type: array of conservative impact slugs for the validated finding, or empty when unchanged
- final_confidence: one of low, medium, high, or null when unchanged
- final_tags: array of conservative tag slugs for the final corpus entry, or empty when unchanged
- rationale: short paragraph
- security_evidence: array of short bullet strings
- missing_evidence: array of short bullet strings
- claim_boundaries: array of short bullet strings
"""


@dataclass
class AgentRunConfig:
    provider: str = "auto"
    model: str = DEFAULT_CODEX_MODEL
    strict: bool = False


@dataclass
class AgentFinding:
    subsystem: str | None = None
    bug_class: str | None = None
    confidence: str | None = None
    summary: str | None = None
    before_after_behavior: str | None = None
    root_cause: str | None = None
    walkthrough: list[str] = field(default_factory=list)
    fix_pattern: str | None = None
    how_it_was_fixed: str | None = None
    why_it_matters: list[str] = field(default_factory=list)
    evidence_notes: str | None = None
    affected_code_paths: list[dict[str, Any]] = field(default_factory=list)
    verification_notes: list[str] = field(default_factory=list)
    security_verdict: str | None = None
    validated_as: str | None = None
    keep_in_security_corpus: bool | None = None
    protocol_security_invariant: str | None = None


@dataclass
class ValidationResult:
    validation_status: str = "completed"
    security_verdict: str = "unclear"
    validated_as: str = "unclear"
    keep_in_security_corpus: bool = False
    final_bug_class: str | None = None
    final_impact_type: list[str] = field(default_factory=list)
    final_confidence: str | None = None
    final_tags: list[str] = field(default_factory=list)
    rationale: str | None = None
    security_evidence: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    claim_boundaries: list[str] = field(default_factory=list)


class LLMClient(Protocol):
    def complete_json(self, instructions: str, input_text: str) -> dict[str, Any]:
        ...


class LimitExhaustedError(RuntimeError):
    """Raised when the backing agent reports quota or rate-limit exhaustion."""


def build_json_only_prompt(instructions: str, input_text: str) -> str:
    return (
        "Use only the provided instructions and input.\n"
        "Do not run commands, inspect files, or rely on external context.\n"
        "Return exactly one JSON object and nothing else.\n\n"
        f"Instructions:\n{instructions.strip()}\n\n"
        f"Input:\n{input_text.strip()}\n"
    )


def summarize_error_text(command_name: str, text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    error_lines = [line for line in lines if "error" in line.lower()]
    summary = " ".join((error_lines or lines)[-6:]) if lines else f"{command_name} exec failed"
    return summary


def format_exec_error(command_name: str, completed: subprocess.CompletedProcess[str]) -> str:
    combined = "\n".join(part for part in (completed.stderr, completed.stdout) if part).strip()
    return f"{command_name} exec failed: {summarize_error_text(command_name, combined)}"


def is_limit_exhaustion_text(text: str) -> bool:
    lowered = " ".join(text.lower().split())
    return any(pattern in lowered for pattern in LIMIT_EXHAUSTION_PATTERNS)


def raise_agent_exec_error(
    command_name: str,
    completed: subprocess.CompletedProcess[str],
    response_text: str = "",
) -> None:
    combined = "\n".join(part for part in (completed.stderr, completed.stdout, response_text) if part).strip()
    summary = summarize_error_text(command_name, combined)
    if is_limit_exhaustion_text(combined):
        raise LimitExhaustedError(f"{command_name} usage limit reached: {summary}")
    raise RuntimeError(f"{command_name} exec failed: {summary}")


def parse_agent_json_output(command_name: str, text: str) -> dict[str, Any]:
    try:
        return parse_json_output(text)
    except ValueError as exc:
        if is_limit_exhaustion_text(text):
            summary = summarize_error_text(command_name, text)
            raise LimitExhaustedError(f"{command_name} usage limit reached: {summary}") from exc
        raise


class CodexExecClient:
    """Minimal JSON-oriented wrapper around `codex exec`."""

    def __init__(
        self,
        model: str | None,
        codex_path: str | None = None,
        timeout_seconds: int = 300,
    ) -> None:
        resolved_path = codex_path or shutil.which("codex")
        if not resolved_path:
            raise RuntimeError("codex CLI not found on PATH")
        self._codex_path = resolved_path
        self._model = model
        self._timeout_seconds = timeout_seconds
        self._ensure_login()

    def _ensure_login(self) -> None:
        completed = subprocess.run(
            [self._codex_path, "login", "status"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        status_text = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
        lowered = status_text.lower()
        if completed.returncode != 0 or "not logged in" in lowered or "logged in" not in lowered:
            raise RuntimeError(
                "codex CLI is not logged in. Run `codex login` to use the ChatGPT-backed pipeline."
            )

    def complete_json(self, instructions: str, input_text: str) -> dict[str, Any]:
        prompt = build_json_only_prompt(instructions, input_text)
        with tempfile.TemporaryDirectory(prefix="dlt-fix-finder-codex-") as tmpdir:
            output_path = Path(tmpdir) / "last_message.txt"
            command = [
                self._codex_path,
                "exec",
                "--skip-git-repo-check",
                "--cd",
                tmpdir,
                "--ephemeral",
                "--sandbox",
                "read-only",
                "-c",
                'model_reasoning_effort="high"',
            ]
            if self._model:
                command.extend(["-m", self._model])
            command.extend(
                [
                    "--output-last-message",
                    str(output_path),
                    prompt,
                ]
            )
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=self._timeout_seconds,
                check=False,
            )
            response_text = output_path.read_text(encoding="utf-8") if output_path.exists() else completed.stdout

        if completed.returncode != 0:
            raise_agent_exec_error("codex", completed, response_text)
        if not response_text.strip():
            raise RuntimeError("codex exec returned no final message")
        return parse_agent_json_output("codex", response_text)


class ClaudeExecClient:
    """Minimal JSON-oriented wrapper around `claude -p`."""

    def __init__(
        self,
        model: str | None,
        claude_path: str | None = None,
        timeout_seconds: int = 300,
    ) -> None:
        resolved_path = claude_path or shutil.which("claude")
        if not resolved_path:
            raise RuntimeError("claude CLI not found on PATH")
        self._claude_path = resolved_path
        self._model = model
        self._timeout_seconds = timeout_seconds

    def complete_json(self, instructions: str, input_text: str) -> dict[str, Any]:
        prompt = build_json_only_prompt(instructions, input_text)
        command = [
            self._claude_path,
            "-p",
            prompt,
            "--output-format",
            "text",
        ]
        if self._model:
            command.extend(["--model", self._model])
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=self._timeout_seconds,
            check=False,
        )
        response_text = completed.stdout
        if completed.returncode != 0:
            raise_agent_exec_error("claude", completed, response_text)
        if not response_text.strip():
            raise RuntimeError("claude exec returned no final message")
        return parse_agent_json_output("claude", response_text)


def create_llm_client(config: AgentRunConfig) -> LLMClient:
    provider = resolve_agent_provider(config.provider)
    if provider == "codex":
        return CodexExecClient(model=config.model)
    if provider == "claude":
        model = None if config.model in {"gpt-5", DEFAULT_CODEX_MODEL} else config.model
        return ClaudeExecClient(model=model)
    raise ValueError(f"unsupported agent provider: {config.provider}")


def resolve_agent_provider(provider: str | None) -> str:
    cleaned = (provider or "auto").strip().lower()
    if cleaned in {"codex", "claude"}:
        return cleaned
    if cleaned != "auto":
        raise ValueError(f"unsupported agent provider: {provider}")

    # Prefer explicit host-session signals first.
    if os.environ.get("CLAUDECODE") or any(name.startswith("CLAUDE_CODE_") for name in os.environ):
        return "claude"
    if any(name.startswith("CODEX_") for name in os.environ):
        return "codex"

    # Fall back to whichever CLI is available locally.
    has_claude = shutil.which("claude") is not None
    has_codex = shutil.which("codex") is not None
    if has_claude and not has_codex:
        return "claude"
    if has_codex and not has_claude:
        return "codex"
    if has_codex:
        return "codex"
    if has_claude:
        return "claude"
    raise RuntimeError("no supported agent CLI found on PATH; install codex or claude, or use heuristic mode")


def parse_json_output(text: str) -> dict[str, Any]:
    candidate = text.strip()
    if candidate.startswith("{") and candidate.endswith("}"):
        return json.loads(candidate)

    fenced = JSON_BLOCK_RE.search(candidate)
    if fenced:
        return json.loads(fenced.group(1))

    start = candidate.find("{")
    end = candidate.rfind("}")
    if start != -1 and end != -1 and end > start:
        return json.loads(candidate[start : end + 1])
    raise ValueError("agent did not return a JSON object")


def _clean_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", value.strip())


def _clean_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items = [_clean_text(item) for item in value if isinstance(item, str)]
    return [item for item in items if item]


def _clean_paths(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    cleaned: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        file = _clean_text(item.get("file"))
        role = _clean_text(item.get("role"))
        line = item.get("line")
        if not file:
            continue
        try:
            line_value = int(line)
        except (TypeError, ValueError):
            line_value = 1
        cleaned.append({"file": file, "line": line_value, "role": role or "related code path"})
    return cleaned


def _clean_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return default


def _clean_optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return None


def normalize_security_verdict(value: Any) -> str | None:
    cleaned = _clean_text(value).lower()
    return cleaned if cleaned in {"confirmed", "likely", "unclear", "not-security"} else None


def normalize_validated_as(value: Any) -> str | None:
    cleaned = _clean_text(value).lower()
    return cleaned if cleaned in {"security-fix", "security-hardening", "unclear", "not-security"} else None


def _clean_slug(value: Any) -> str | None:
    cleaned = re.sub(r"[^a-z0-9]+", "-", _clean_text(value).lower()).strip("-")
    if not cleaned or len(cleaned) > 80:
        return None
    return cleaned


def _clean_slug_list(value: Any, limit: int = 10) -> list[str]:
    if not isinstance(value, list):
        return []
    cleaned = [_clean_slug(item) for item in value]
    return list(dict.fromkeys(item for item in cleaned if item))[:limit]


def normalize_confidence(value: Any) -> str | None:
    cleaned = _clean_text(value).lower()
    return cleaned if cleaned in {"low", "medium", "high"} else None


def normalize_mapper_output(payload: dict[str, Any]) -> AgentFinding:
    return AgentFinding(
        subsystem=_clean_text(payload.get("subsystem")) or None,
        bug_class=_clean_text(payload.get("bug_class")) or None,
        confidence=_clean_text(payload.get("confidence")) or None,
        security_verdict=normalize_security_verdict(payload.get("security_verdict")),
        validated_as=normalize_validated_as(payload.get("validated_as")),
        keep_in_security_corpus=_clean_optional_bool(payload.get("keep_in_security_corpus")),
        protocol_security_invariant=_clean_text(payload.get("protocol_security_invariant")) or None,
        evidence_notes=_clean_text(payload.get("rationale")) or None,
        affected_code_paths=_clean_paths(payload.get("affected_code_paths")),
        verification_notes=_clean_list(payload.get("claim_boundaries")),
    )


def normalize_drafter_output(payload: dict[str, Any]) -> AgentFinding:
    return AgentFinding(
        summary=_clean_text(payload.get("summary")) or None,
        before_after_behavior=_clean_text(payload.get("before_after_behavior")) or None,
        root_cause=_clean_text(payload.get("root_cause")) or None,
        walkthrough=_clean_list(payload.get("walkthrough")),
        fix_pattern=_clean_text(payload.get("fix_pattern")) or None,
        how_it_was_fixed=_clean_text(payload.get("how_it_was_fixed")) or None,
        why_it_matters=_clean_list(payload.get("why_it_matters")),
        evidence_notes=_clean_text(payload.get("evidence_notes")) or None,
    )


def normalize_skeptic_output(payload: dict[str, Any]) -> AgentFinding:
    return AgentFinding(
        subsystem=_clean_text(payload.get("subsystem")) or None,
        bug_class=_clean_text(payload.get("bug_class")) or None,
        confidence=_clean_text(payload.get("confidence")) or None,
        security_verdict=normalize_security_verdict(payload.get("security_verdict")),
        validated_as=normalize_validated_as(payload.get("validated_as")),
        keep_in_security_corpus=_clean_optional_bool(payload.get("keep_in_security_corpus")),
        protocol_security_invariant=_clean_text(payload.get("protocol_security_invariant")) or None,
        summary=_clean_text(payload.get("summary")) or None,
        before_after_behavior=_clean_text(payload.get("before_after_behavior")) or None,
        root_cause=_clean_text(payload.get("root_cause")) or None,
        walkthrough=_clean_list(payload.get("walkthrough")),
        fix_pattern=_clean_text(payload.get("fix_pattern")) or None,
        how_it_was_fixed=_clean_text(payload.get("how_it_was_fixed")) or None,
        why_it_matters=_clean_list(payload.get("why_it_matters")),
        evidence_notes=_clean_text(payload.get("evidence_notes")) or None,
        verification_notes=_clean_list(payload.get("verification_notes")),
    )


def normalize_validation_result(payload: dict[str, Any]) -> ValidationResult:
    validation_status = _clean_text(payload.get("validation_status")).lower() or "completed"
    if validation_status not in {"completed", "failed"}:
        validation_status = "completed"

    security_verdict = normalize_security_verdict(payload.get("security_verdict")) or "unclear"
    validated_as = normalize_validated_as(payload.get("validated_as")) or "unclear"

    keep_default = security_verdict in {"confirmed", "likely"} and validated_as in {"security-fix", "security-hardening"}
    final_bug_class = _clean_slug(payload.get("final_bug_class"))
    final_impact_type = _clean_slug_list(payload.get("final_impact_type"), limit=6)
    final_confidence = normalize_confidence(payload.get("final_confidence"))
    final_tags = _clean_slug_list(payload.get("final_tags"), limit=10)
    if validated_as == "not-security" or security_verdict == "not-security":
        final_bug_class = final_bug_class or "not-security"
        final_impact_type = final_impact_type or ["non-security"]
        final_confidence = final_confidence or "low"
        final_tags = final_tags or ["not-security", "non-security"]
    return ValidationResult(
        validation_status=validation_status,
        security_verdict=security_verdict,
        validated_as=validated_as,
        keep_in_security_corpus=_clean_bool(payload.get("keep_in_security_corpus"), default=keep_default),
        final_bug_class=final_bug_class,
        final_impact_type=final_impact_type,
        final_confidence=final_confidence,
        final_tags=final_tags,
        rationale=_clean_text(payload.get("rationale")) or None,
        security_evidence=_clean_list(payload.get("security_evidence")),
        missing_evidence=_clean_list(payload.get("missing_evidence")),
        claim_boundaries=_clean_list(payload.get("claim_boundaries")),
    )


def _json_prompt(title: str, payload: dict[str, Any]) -> str:
    return f"{title}\n\nReturn JSON only.\n\n{json.dumps(payload, indent=2, sort_keys=True)}"


def run_mapper_drafter_skeptic(
    bundle: dict[str, Any],
    client: LLMClient,
) -> AgentFinding:
    mapper_raw = client.complete_json(
        MAPPER_INSTRUCTIONS,
        _json_prompt("Analyze this finding context as the Mapper agent.", bundle),
    )
    mapper = normalize_mapper_output(mapper_raw)

    drafter_raw = client.complete_json(
        DRAFTER_INSTRUCTIONS,
        _json_prompt(
            "Write the finding draft using this context and mapper result.",
            {"context": bundle, "mapper": mapper_raw},
        ),
    )
    drafter = normalize_drafter_output(drafter_raw)

    skeptic_raw = client.complete_json(
        SKEPTIC_INSTRUCTIONS,
        _json_prompt(
            "Review the draft strictly and return a corrected finding.",
            {"context": bundle, "mapper": mapper_raw, "draft": drafter_raw},
        ),
    )
    skeptic = normalize_skeptic_output(skeptic_raw)

    return AgentFinding(
        subsystem=skeptic.subsystem or mapper.subsystem,
        bug_class=skeptic.bug_class or mapper.bug_class,
        confidence=skeptic.confidence or mapper.confidence,
        security_verdict=skeptic.security_verdict or mapper.security_verdict,
        validated_as=skeptic.validated_as or mapper.validated_as,
        keep_in_security_corpus=(
            skeptic.keep_in_security_corpus
            if skeptic.keep_in_security_corpus is not None
            else mapper.keep_in_security_corpus
        ),
        protocol_security_invariant=skeptic.protocol_security_invariant or mapper.protocol_security_invariant,
        summary=skeptic.summary or drafter.summary,
        before_after_behavior=skeptic.before_after_behavior or drafter.before_after_behavior,
        root_cause=skeptic.root_cause or drafter.root_cause,
        walkthrough=skeptic.walkthrough or drafter.walkthrough,
        fix_pattern=skeptic.fix_pattern or drafter.fix_pattern,
        how_it_was_fixed=skeptic.how_it_was_fixed or drafter.how_it_was_fixed,
        why_it_matters=skeptic.why_it_matters or drafter.why_it_matters,
        evidence_notes=skeptic.evidence_notes or drafter.evidence_notes or mapper.evidence_notes,
        affected_code_paths=mapper.affected_code_paths,
        verification_notes=[*mapper.verification_notes, *skeptic.verification_notes],
    )


def run_validator(
    bundle: dict[str, Any],
    client: LLMClient,
) -> ValidationResult:
    raw = client.complete_json(
        VALIDATOR_INSTRUCTIONS,
        _json_prompt(
            "Validate whether this generated finding belongs in a security-fix corpus.",
            bundle,
        ),
    )
    return normalize_validation_result(raw)
