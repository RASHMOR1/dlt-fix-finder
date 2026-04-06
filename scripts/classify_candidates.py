#!/usr/bin/env python3
"""Classify phase 1 candidates before finding generation."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

import rank_fix_commits


SECURITY_REASONS = {
    "message uses explicit security language",
    "diff changes access control or privilege checks",
    "diff changes cryptographic or replay-sensitive logic",
    "diff changes resource-control logic",
    "diff changes consensus or validator logic",
}

NEGATIVE_HINTS = {
    "message looks like a feature addition",
    "message looks like feature work",
    "message looks like a migration or codec upgrade",
    "message looks like performance or pruning work",
    "message looks like cleanup or maintenance",
    "message looks like a broad architectural change",
    "commit looks more like product or maintenance work than a targeted vulnerability fix",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-file", required=True, help="Phase 1 JSON candidate file")
    parser.add_argument("--out-file", required=True, help="Where to write the classified candidate file")
    parser.add_argument("--limit", type=int, default=0, help="Maximum number of classified candidates to keep; use 0 for no limit")
    return parser.parse_args()


def classify_candidate(commit: rank_fix_commits.RankedCommit) -> tuple[str, bool, str]:
    reasons = set(commit.reasons)
    subject = commit.subject.lower()

    security_signal_count = sum(reason in SECURITY_REASONS for reason in reasons)
    negative_signal_count = sum(reason in NEGATIVE_HINTS for reason in reasons)
    explicit_fix = "message says the commit is a fix or hardening change" in reasons
    has_tests = bool(commit.test_files)
    explicit_security = "message uses explicit security language" in reasons

    if negative_signal_count >= 2 and not explicit_security:
        return (
            "feature-or-maintenance",
            False,
            "The commit looks more like feature, migration, performance, or maintenance work than a focused security fix.",
        )

    if explicit_security and security_signal_count >= 2:
        return (
            "security-fix",
            True,
            "The commit uses explicit security language and also changes security-sensitive logic.",
        )

    if explicit_fix and has_tests and security_signal_count >= 2:
        return (
            "security-fix",
            True,
            "The commit looks like a focused fix with regression coverage in a security-sensitive area.",
        )

    if explicit_fix and security_signal_count >= 1:
        return (
            "security-hardening",
            True,
            "The commit appears to harden a sensitive subsystem, but the exploit path is not explicit.",
        )

    if security_signal_count >= 2 and negative_signal_count == 0:
        return (
            "unclear",
            False,
            "The commit touches sensitive logic, but it lacks enough explicit fix evidence to accept automatically.",
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
        "The commit does not show enough security-specific evidence to keep for finding generation.",
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
