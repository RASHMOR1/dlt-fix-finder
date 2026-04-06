#!/usr/bin/env python3
"""Validate phase 3 findings before treating them as a security corpus."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

import generate_findings
import phase3_agents
import rank_fix_commits


FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n?(.*)\Z", re.DOTALL)
GIT_SOURCE_REF_RE = re.compile(r"git:([0-9a-f]{7,40})")
VALIDATION_SECTION_MARKER = "\n# Validation Notes\n"
KEPT_BUCKET = "kept"
REJECTED_BUCKET = "rejected"
VALIDATION_FRONTMATTER_KEYS = (
    "validation_status",
    "security_verdict",
    "validated_as",
    "keep_in_security_corpus",
)


@dataclass
class FindingDocument:
    path: Path
    relative_path: Path
    frontmatter_text: str
    body: str
    commit_sha: str
    raw_markdown: str


@dataclass
class ValidatedFindingDocument:
    source_path: Path
    relative_path: Path
    markdown: str
    validation: phase3_agents.ValidationResult
    commit_sha: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Path to the git repository")
    parser.add_argument("--findings-dir", default="findings", help="Directory containing phase 3 Markdown findings")
    parser.add_argument("--out-dir", default="validated-findings", help="Directory where phase 4 validated findings will be written")
    parser.add_argument("--report-file", help="Optional JSON report path; defaults to .dlt-fix-finder/phase4-validation.json under the repo")
    parser.add_argument("--candidate-file", help="Optional phase 2 candidate JSON used to recover classification metadata")
    parser.add_argument("--limit", type=int, default=0, help="Maximum number of findings to validate; use 0 for no limit")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing validated finding files")
    parser.add_argument(
        "--jobs",
        type=int,
        default=generate_findings.DEFAULT_PHASE3_JOBS,
        help="Number of findings to validate concurrently. Use 1 to disable parallelism.",
    )
    parser.add_argument(
        "--context-depth",
        choices=("shallow", "deep"),
        default=generate_findings.DEFAULT_CONTEXT_DEPTH,
        help="How much neighboring project context phase 4 should gather while validating a finding.",
    )
    parser.add_argument("--agent-model", default="gpt-5", help="Model name for the phase 4 validator")
    parser.add_argument(
        "--agent-strict",
        action="store_true",
        help="Fail the run immediately if a validator step errors instead of recording a failed validation result.",
    )
    return parser.parse_args()


def parse_frontmatter(markdown: str) -> tuple[str, str]:
    match = FRONTMATTER_RE.match(markdown)
    if not match:
        raise ValueError("finding markdown is missing YAML frontmatter")
    return match.group(1), match.group(2)


def extract_commit_sha(frontmatter_text: str) -> str:
    match = GIT_SOURCE_REF_RE.search(frontmatter_text)
    if not match:
        raise ValueError("finding frontmatter is missing a git source ref")
    return match.group(1)


def load_finding_document(path: Path, findings_dir: Path) -> FindingDocument:
    raw_markdown = path.read_text(encoding="utf-8")
    frontmatter_text, body = parse_frontmatter(raw_markdown)
    return FindingDocument(
        path=path,
        relative_path=path.relative_to(findings_dir),
        frontmatter_text=frontmatter_text,
        body=body,
        commit_sha=extract_commit_sha(frontmatter_text),
        raw_markdown=raw_markdown,
    )


def load_finding_documents(findings_dir: Path, limit: int = 0) -> list[FindingDocument]:
    paths = sorted(path for path in findings_dir.rglob("*.md") if path.is_file())
    if limit > 0:
        paths = paths[:limit]
    return [load_finding_document(path, findings_dir) for path in paths]


def validation_bucket(validation: phase3_agents.ValidationResult) -> str:
    return KEPT_BUCKET if validation.keep_in_security_corpus else REJECTED_BUCKET


def validated_target_path(
    out_dir: Path,
    relative_path: Path,
    validation: phase3_agents.ValidationResult,
) -> Path:
    return out_dir / validation_bucket(validation) / relative_path


def candidate_validated_paths(out_dir: Path, relative_path: Path) -> list[Path]:
    return [out_dir / KEPT_BUCKET / relative_path, out_dir / REJECTED_BUCKET / relative_path]


def remove_stale_bucket_copy(out_dir: Path, result: ValidatedFindingDocument) -> None:
    target = validated_target_path(out_dir, result.relative_path, result.validation)
    for candidate in candidate_validated_paths(out_dir, result.relative_path):
        if candidate == target:
            continue
        if candidate.exists():
            candidate.unlink()


def load_candidate_lookup(candidate_file: str | None) -> dict[str, dict[str, Any]]:
    if not candidate_file:
        return {}
    payload = json.loads(Path(candidate_file).read_text(encoding="utf-8"))
    items = payload.get("classified_candidates")
    if items is None:
        items = payload.get("candidates", [])
    return {item["sha"]: item for item in items if item.get("sha")}


def commit_from_candidate(item: dict[str, Any]) -> rank_fix_commits.RankedCommit:
    return rank_fix_commits.RankedCommit(
        **{
            key: value
            for key, value in item.items()
            if key in rank_fix_commits.RankedCommit.__dataclass_fields__
        }
    )


def load_commit_for_validation(
    repo: Path,
    commit_sha: str,
    candidate_lookup: dict[str, dict[str, Any]],
) -> tuple[rank_fix_commits.RankedCommit, dict[str, Any] | None]:
    candidate_item = candidate_lookup.get(commit_sha)
    if candidate_item is not None:
        return commit_from_candidate(candidate_item), candidate_item
    return rank_fix_commits.analyze_commit(repo, commit_sha), None


def build_validation_bundle(
    repo: Path,
    document: FindingDocument,
    commit: rank_fix_commits.RankedCommit,
    candidate_item: dict[str, Any] | None,
    evidences: list[rank_fix_commits.HunkEvidence],
    project_context: generate_findings.ProjectContext,
) -> dict[str, Any]:
    bundle = {
        "project": repo.name,
        "finding": {
            "path": document.relative_path.as_posix(),
            "markdown": document.raw_markdown,
        },
        "commit": {
            "sha": commit.sha,
            "short_sha": commit.short_sha,
            "date": commit.date,
            "subject": commit.subject,
            "body": rank_fix_commits.load_body(repo, commit.sha),
            "files": commit.files,
            "reasons": commit.reasons,
        },
        "evidence": [
            {
                "file": evidence.file,
                "line": evidence.new_start,
                "header": evidence.header,
                "score": evidence.score,
                "reasons": evidence.reasons,
                "before": evidence.before,
                "after": evidence.after,
                "changed_lines": evidence.changed_lines,
            }
            for evidence in evidences
        ],
        "project_context": {
            "context_depth": project_context.context_depth,
            "primary_directories": project_context.primary_directories,
            "identifiers": project_context.identifiers,
            "trace_identifiers": project_context.trace_identifiers,
            "changed_contexts": [
                {
                    "file": snippet.file,
                    "line": snippet.line,
                    "header": snippet.header,
                    "excerpt": snippet.excerpt,
                }
                for snippet in project_context.changed_contexts
            ],
            "related_contexts": [
                {
                    "file": snippet.file,
                    "line": snippet.line,
                    "header": snippet.header,
                    "excerpt": snippet.excerpt,
                }
                for snippet in project_context.related_contexts
            ],
            "traced_contexts": [
                {
                    "file": snippet.file,
                    "line": snippet.line,
                    "header": snippet.header,
                    "excerpt": snippet.excerpt,
                }
                for snippet in project_context.traced_contexts
            ],
            "related_test_files": project_context.related_test_files,
        },
    }
    if candidate_item is not None:
        bundle["phase2"] = {
            "classification": candidate_item.get("classification"),
            "accepted": candidate_item.get("accepted"),
            "classification_rationale": candidate_item.get("classification_rationale"),
        }
    return bundle


def format_numbered_section(items: list[str]) -> list[str]:
    cleaned = [generate_findings.clean_text(item) for item in items if generate_findings.clean_text(item)]
    return [f"{index}. {item}" for index, item in enumerate(cleaned, start=1)]


def strip_existing_validation_section(body: str) -> str:
    marker_index = body.find(VALIDATION_SECTION_MARKER)
    if marker_index == -1:
        return body.rstrip()
    return body[:marker_index].rstrip()


def format_frontmatter_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def update_frontmatter(frontmatter_text: str, validation: phase3_agents.ValidationResult) -> str:
    lines = []
    for line in frontmatter_text.splitlines():
        stripped = line.strip()
        if any(stripped.startswith(f"{key}:") for key in VALIDATION_FRONTMATTER_KEYS):
            continue
        lines.append(line)
    lines.extend(
        [
            f"validation_status: {format_frontmatter_value(validation.validation_status)}",
            f"security_verdict: {format_frontmatter_value(validation.security_verdict)}",
            f"validated_as: {format_frontmatter_value(validation.validated_as)}",
            f"keep_in_security_corpus: {format_frontmatter_value(validation.keep_in_security_corpus)}",
        ]
    )
    return "\n".join(lines)


def build_validation_notes(validation: phase3_agents.ValidationResult) -> str:
    lines = [
        "# Validation Notes",
        "",
        f"Validation status: `{validation.validation_status}`",
        f"Security verdict: `{validation.security_verdict}`",
        f"Validated as: `{validation.validated_as}`",
        f"Keep in security corpus: `{str(validation.keep_in_security_corpus).lower()}`",
        "",
        validation.rationale or "The validator did not return additional rationale.",
    ]
    if validation.security_evidence:
        lines.extend(["", "## Security Evidence", "", *format_numbered_section(validation.security_evidence)])
    if validation.missing_evidence:
        lines.extend(["", "## Missing Evidence", "", *format_numbered_section(validation.missing_evidence)])
    if validation.claim_boundaries:
        lines.extend(["", "## Claim Boundaries", "", *format_numbered_section(validation.claim_boundaries)])
    return "\n".join(lines).rstrip()


def build_validated_markdown(
    document: FindingDocument,
    validation: phase3_agents.ValidationResult,
) -> str:
    frontmatter_text = update_frontmatter(document.frontmatter_text, validation)
    body = strip_existing_validation_section(document.body)
    validation_notes = build_validation_notes(validation)
    return f"---\n{frontmatter_text}\n---\n\n{body}\n\n{validation_notes}\n"


def validation_failure_result(exc: Exception) -> phase3_agents.ValidationResult:
    return phase3_agents.ValidationResult(
        validation_status="failed",
        security_verdict="unclear",
        validated_as="unclear",
        keep_in_security_corpus=False,
        rationale=(
            "Phase 4 validation did not complete successfully, so the finding was not kept in the "
            f"security corpus automatically: {generate_findings.clean_text(str(exc))}."
        ),
        claim_boundaries=["The validator failed before it could establish a grounded security verdict."],
    )


def validate_finding_document(
    repo: Path,
    document: FindingDocument,
    candidate_lookup: dict[str, dict[str, Any]],
    context_depth: str,
    llm_client: phase3_agents.LLMClient | None,
    agent_config: phase3_agents.AgentRunConfig | None,
) -> ValidatedFindingDocument:
    commit, candidate_item = load_commit_for_validation(repo, document.commit_sha, candidate_lookup)
    evidence_limit = 4 if context_depth == "deep" else 3
    evidences = generate_findings.select_phase3_evidences(repo, commit.sha, limit=evidence_limit)
    project_context = generate_findings.build_project_context(repo, commit, evidences, context_depth=context_depth)
    bundle = build_validation_bundle(repo, document, commit, candidate_item, evidences, project_context)
    client = llm_client if llm_client is not None else phase3_agents.CodexExecClient(model=(agent_config.model if agent_config else "gpt-5"))
    try:
        validation = phase3_agents.run_validator(bundle, client)
    except Exception as exc:
        strict = agent_config.strict if agent_config else False
        if strict:
            raise
        validation = validation_failure_result(exc)
    return ValidatedFindingDocument(
        source_path=document.path,
        relative_path=document.relative_path,
        markdown=build_validated_markdown(document, validation),
        validation=validation,
        commit_sha=document.commit_sha,
    )


def iter_validated_finding_documents(
    repo: Path,
    documents: list[FindingDocument],
    candidate_lookup: dict[str, dict[str, Any]],
    context_depth: str,
    jobs: int,
    llm_client: phase3_agents.LLMClient | None,
    agent_config: phase3_agents.AgentRunConfig | None,
):
    if not documents:
        return

    worker_count = generate_findings.resolve_phase3_jobs(jobs, len(documents))
    shared_client = llm_client if llm_client is not None else phase3_agents.CodexExecClient(model=(agent_config.model if agent_config else "gpt-5"))
    validate_one = partial(
        validate_finding_document,
        repo,
        candidate_lookup=candidate_lookup,
        context_depth=context_depth,
        llm_client=shared_client,
        agent_config=agent_config,
    )

    if worker_count == 1:
        for document in documents:
            yield validate_one(document)
        return

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures: list[Future[ValidatedFindingDocument]] = [
            executor.submit(validate_one, document) for document in documents
        ]
        for future in as_completed(futures):
            yield future.result()


def build_report_payload(
    repo: Path,
    findings_dir: Path,
    out_dir: Path,
    results: list[ValidatedFindingDocument],
) -> dict[str, Any]:
    verdict_counts = Counter(result.validation.security_verdict for result in results)
    status_counts = Counter(result.validation.validation_status for result in results)
    validated_as_counts = Counter(result.validation.validated_as for result in results)
    kept_count = sum(result.validation.keep_in_security_corpus for result in results)
    bucket_counts = Counter(validation_bucket(result.validation) for result in results)
    return {
        "repo": repo.name,
        "phase": "4",
        "source_findings_dir": str(findings_dir),
        "validated_findings_dir": str(out_dir),
        "summary": {
            "total": len(results),
            "kept_in_security_corpus": kept_count,
            "verdict_counts": dict(sorted(verdict_counts.items())),
            "validated_as_counts": dict(sorted(validated_as_counts.items())),
            "status_counts": dict(sorted(status_counts.items())),
            "bucket_counts": dict(sorted(bucket_counts.items())),
        },
        "validated_findings": [
            {
                "source_path": result.source_path.as_posix(),
                "bucket": validation_bucket(result.validation),
                "target_path": validated_target_path(out_dir, result.relative_path, result.validation).as_posix(),
                "commit_sha": result.commit_sha,
                "validation_status": result.validation.validation_status,
                "security_verdict": result.validation.security_verdict,
                "validated_as": result.validation.validated_as,
                "keep_in_security_corpus": result.validation.keep_in_security_corpus,
                "rationale": result.validation.rationale,
                "security_evidence": result.validation.security_evidence,
                "missing_evidence": result.validation.missing_evidence,
                "claim_boundaries": result.validation.claim_boundaries,
            }
            for result in results
        ],
    }


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()
    findings_dir = Path(args.findings_dir)
    if not findings_dir.is_absolute():
        findings_dir = repo / findings_dir
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = repo / out_dir
    report_file = Path(args.report_file) if args.report_file else repo / ".dlt-fix-finder" / "phase4-validation.json"
    if not report_file.is_absolute():
        report_file = repo / report_file

    try:
        rank_fix_commits.run_git(repo, "rev-parse", "--show-toplevel")
    except Exception:
        print(f"{repo} is not a git repository")
        return 2

    if not findings_dir.exists():
        print(f"{findings_dir} does not exist")
        return 2

    findings = load_finding_documents(findings_dir, limit=args.limit)
    candidate_lookup = load_candidate_lookup(args.candidate_file)
    agent_config = phase3_agents.AgentRunConfig(model=args.agent_model, strict=args.agent_strict)

    pending_documents = []
    skipped = 0
    for document in findings:
        if any(path.exists() for path in candidate_validated_paths(out_dir, document.relative_path)) and not args.overwrite:
            skipped += 1
            continue
        pending_documents.append(document)

    out_dir.mkdir(parents=True, exist_ok=True)
    validated_results: list[ValidatedFindingDocument] = []
    written = 0
    for result in iter_validated_finding_documents(
        repo,
        pending_documents,
        candidate_lookup,
        context_depth=args.context_depth,
        jobs=args.jobs,
        llm_client=None,
        agent_config=agent_config,
    ):
        target = validated_target_path(out_dir, result.relative_path, result.validation)
        target.parent.mkdir(parents=True, exist_ok=True)
        remove_stale_bucket_copy(out_dir, result)
        target.write_text(result.markdown, encoding="utf-8")
        validated_results.append(result)
        written += 1
        print(target)

    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(
        json.dumps(build_report_payload(repo, findings_dir, out_dir, validated_results), indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {written} validated finding file(s) to {out_dir}")
    print(f"Wrote phase 4 report to {report_file}")
    if skipped:
        print(f"Skipped {skipped} existing validated finding file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
