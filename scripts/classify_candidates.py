#!/usr/bin/env python3
"""Classify phase 1 candidates before finding generation."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

import rank_fix_commits


CODE_SECURITY_REASONS = {
    "diff changes access control or privilege checks",
    "diff changes cryptographic or replay-sensitive logic",
    "diff changes resource-control logic",
    "diff changes consensus or validator logic",
}

PATH_SECURITY_REASONS = {
    "touches a critical implementation path",
    "touches a sensitive subsystem",
}

NEGATIVE_HINTS = {
    "message looks like a feature addition",
    "message looks like feature work",
    "message looks like a migration or codec upgrade",
    "message looks like performance or pruning work",
    "message looks like cleanup or maintenance",
    "message looks like a broad architectural change",
    "message points to cleanup or workflow work",
    "commit looks more like product or maintenance work than a targeted vulnerability fix",
    "touches only tooling, examples, or support code",
    "touches only frontend or UI code",
    "security language appears only in commit text without implementation evidence",
    "security language is not corroborated by implementation signals",
    "message looks like a frontend or UI change",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-file", required=True, help="Phase 1 JSON candidate file")
    parser.add_argument("--out-file", required=True, help="Where to write the classified candidate file")
    parser.add_argument("--limit", type=int, default=0, help="Maximum number of classified candidates to keep; use 0 for no limit")
    return parser.parse_args()


def implementation_files_for(commit: rank_fix_commits.RankedCommit) -> list[str]:
    if commit.implementation_files:
        return commit.implementation_files
    return [path for path in commit.source_files if rank_fix_commits.is_implementation_file(path)]


def classify_candidate(commit: rank_fix_commits.RankedCommit) -> tuple[str, bool, str]:
    reasons = set(commit.reasons)
    subject = commit.subject.lower()
    implementation_files = implementation_files_for(commit)

    code_security_count = sum(reason in CODE_SECURITY_REASONS for reason in reasons)
    path_security_count = sum(reason in PATH_SECURITY_REASONS for reason in reasons)
    negative_signal_count = sum(reason in NEGATIVE_HINTS for reason in reasons)
    explicit_fix = "message says the commit is a fix or hardening change" in reasons
    explicit_security = "message uses explicit security language" in reasons
    has_tests = bool(commit.test_files)
    has_grounded_source = bool(implementation_files) and (code_security_count > 0 or path_security_count > 0 or has_tests)

    if negative_signal_count >= 2 and not explicit_security:
        return (
            "feature-or-maintenance",
            False,
            "The commit still looks more like feature, migration, workflow, or maintenance work than a focused security patch.",
        )

    if not implementation_files and not has_tests:
        return (
            "feature-or-maintenance",
            False,
            "The changed files look like tooling or support code rather than grounded implementation evidence for a security finding.",
        )

    if explicit_security and code_security_count >= 1 and bool(implementation_files):
        return (
            "security-fix",
            True,
            "The commit uses explicit security language and the implementation diff also changes a security-relevant code path.",
        )

    if explicit_fix and code_security_count >= 1 and (path_security_count >= 1 or has_tests):
        return (
            "security-hardening",
            True,
            "The commit looks like a focused hardening change with grounded implementation signals in a sensitive area.",
        )

    if code_security_count >= 2 and bool(implementation_files) and has_tests:
        return (
            "security-hardening",
            True,
            "The implementation diff changes multiple security-sensitive behaviors and includes nearby regression coverage.",
        )

    if explicit_fix and path_security_count >= 1 and bool(implementation_files) and has_tests:
        return (
            "security-hardening",
            True,
            "The patch looks like a focused fix in a sensitive implementation path and is supported by test updates.",
        )

    if explicit_fix and not has_grounded_source:
        return (
            "unclear",
            False,
            "The commit claims to be a fix, but the ranked evidence is not grounded strongly enough in implementation changes to accept automatically.",
        )

    if has_grounded_source:
        return (
            "unclear",
            False,
            "The commit touches a sensitive implementation path, but it lacks enough explicit fix evidence to accept automatically.",
        )

    if "bug" in subject or "regression" in subject or "panic" in subject or "crash" in subject:
        return (
            "correctness-or-reliability",
            False,
            "The commit looks more like a correctness or reliability fix than a clearly security-motivated patch.",
        )

    return (
        "feature-or-maintenance",
        False,
        "The commit does not show enough grounded security-specific evidence to keep for finding generation.",
    )


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.candidate_file).read_text(encoding="utf-8"))
    commits = [rank_fix_commits.RankedCommit(**item) for item in payload.get("candidates", [])]

    classified = []
    for commit in commits:
        classification, accepted, rationale = classify_candidate(commit)
        classified.append(
            {
                **asdict(commit),
                "classification": classification,
                "accepted": accepted,
                "classification_rationale": rationale,
            }
        )

    if args.limit > 0:
        classified = classified[: args.limit]

    out_payload = {
        "repo": payload.get("repo"),
        "phase": "1.5",
        "source_candidate_file": str(Path(args.candidate_file).resolve()),
        "classified_candidates": classified,
    }
    out_path = Path(args.out_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out_payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(classified)} classified candidate(s) to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
