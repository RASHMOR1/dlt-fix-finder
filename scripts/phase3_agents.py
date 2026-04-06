#!/usr/bin/env python3
"""Optional agent-backed helpers for phase 3 finding generation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol


JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)

MAPPER_INSTRUCTIONS = """You are the Mapper agent for vulnerability-fix analysis.

Your job is to map the commit into the correct project subsystem and bug shape before anyone writes prose.

Rules:
- Use only the provided commit, patch evidence, and project context.
- Prefer conservative labels over dramatic ones.
- Do not claim exploitability unless the code clearly supports it.
- If the patch looks like an API or state-representation cleanup, say so plainly.
- Return JSON only.

Return an object with these keys:
- subsystem: short slug
- bug_class: short slug
- confidence: one of low, medium, high
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
- Return JSON only.

Return an object with these keys:
- summary
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
- Preserve useful grounded explanation when possible.
- Return JSON only.

Return an object with these keys:
- subsystem
- bug_class
- confidence: one of low, medium, high
- summary
- root_cause
- walkthrough: array of step strings
- fix_pattern
- how_it_was_fixed
- why_it_matters: array of short bullet strings
- evidence_notes
- verification_notes: array of short strings
"""


@dataclass
class AgentRunConfig:
    provider: str = "openai"
    model: str = "gpt-5"
    strict: bool = False


@dataclass
class AgentFinding:
    subsystem: str | None = None
    bug_class: str | None = None
    confidence: str | None = None
    summary: str | None = None
    root_cause: str | None = None
    walkthrough: list[str] = field(default_factory=list)
    fix_pattern: str | None = None
    how_it_was_fixed: str | None = None
    why_it_matters: list[str] = field(default_factory=list)
    evidence_notes: str | None = None
    affected_code_paths: list[dict[str, Any]] = field(default_factory=list)
    verification_notes: list[str] = field(default_factory=list)


class LLMClient(Protocol):
    def complete_json(self, instructions: str, input_text: str) -> dict[str, Any]:
        ...


class OpenAIResponsesClient:
    """Minimal JSON-oriented wrapper around the OpenAI Responses API."""

    def __init__(self, model: str) -> None:
        from openai import OpenAI

        self._client = OpenAI()
        self._model = model

    def complete_json(self, instructions: str, input_text: str) -> dict[str, Any]:
        response = self._client.responses.create(
            model=self._model,
            instructions=instructions,
            input=input_text,
        )
        return parse_json_output(response.output_text)


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


def normalize_mapper_output(payload: dict[str, Any]) -> AgentFinding:
    return AgentFinding(
        subsystem=_clean_text(payload.get("subsystem")) or None,
        bug_class=_clean_text(payload.get("bug_class")) or None,
        confidence=_clean_text(payload.get("confidence")) or None,
        evidence_notes=_clean_text(payload.get("rationale")) or None,
        affected_code_paths=_clean_paths(payload.get("affected_code_paths")),
        verification_notes=_clean_list(payload.get("claim_boundaries")),
    )


def normalize_drafter_output(payload: dict[str, Any]) -> AgentFinding:
    return AgentFinding(
        summary=_clean_text(payload.get("summary")) or None,
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
        summary=_clean_text(payload.get("summary")) or None,
        root_cause=_clean_text(payload.get("root_cause")) or None,
        walkthrough=_clean_list(payload.get("walkthrough")),
        fix_pattern=_clean_text(payload.get("fix_pattern")) or None,
        how_it_was_fixed=_clean_text(payload.get("how_it_was_fixed")) or None,
        why_it_matters=_clean_list(payload.get("why_it_matters")),
        evidence_notes=_clean_text(payload.get("evidence_notes")) or None,
        verification_notes=_clean_list(payload.get("verification_notes")),
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
        summary=skeptic.summary or drafter.summary,
        root_cause=skeptic.root_cause or drafter.root_cause,
        walkthrough=skeptic.walkthrough or drafter.walkthrough,
        fix_pattern=skeptic.fix_pattern or drafter.fix_pattern,
        how_it_was_fixed=skeptic.how_it_was_fixed or drafter.how_it_was_fixed,
        why_it_matters=skeptic.why_it_matters or drafter.why_it_matters,
        evidence_notes=skeptic.evidence_notes or drafter.evidence_notes or mapper.evidence_notes,
        affected_code_paths=mapper.affected_code_paths,
        verification_notes=[*mapper.verification_notes, *skeptic.verification_notes],
    )
