#!/usr/bin/env python3
"""Generate RAG-ready Markdown findings from likely fix commits."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

import rank_fix_commits


SUBSYSTEM_RULES = [
    ("p2p-networking", ("p2p", "network", "peer", "handshake", "mempool", "rpc")),
    ("consensus", ("consensus", "quorum", "vote", "epoch", "fork", "final")),
    ("validator-ops", ("validator", "slashing", "signer", "keystore")),
    ("storage", ("storage", "state", "snapshot", "db", "database", "wal")),
    ("cryptography", ("crypto", "signature", "verify", "hash", "nonce", "replay")),
    ("access-control", ("auth", "access", "permission", "role", "admin", "multisig")),
]

BUG_CLASS_RULES = [
    ("resource-exhaustion", ("dos", "denial of service", "queue", "buffer", "throttle", "backpressure", "ratelimit", "rate limit")),
    ("access-control", ("auth", "permission", "role", "admin", "multisig", "authorize", "privilege")),
    ("replay-or-signature-validation", ("signature", "verify", "nonce", "replay", "ecdsa", "ed25519", "secp256k1")),
    ("consensus-safety", ("consensus", "quorum", "fork", "finaliz", "checkpoint", "vote")),
    ("liveness-failure", ("stall", "halt", "deadlock", "timeout", "retry", "panic", "crash")),
    ("state-corruption", ("snapshot", "restore", "state", "db", "database", "serialize", "deserialize", "corrupt")),
    ("input-validation", ("validate", "sanitize", "decode", "encode", "parse")),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Path to the git repository")
    parser.add_argument("--out-dir", default="findings", help="Directory where Markdown findings will be written")
    parser.add_argument("--limit", type=int, default=0, help="Maximum number of findings to generate; use 0 for no limit")
    parser.add_argument("--min-score", type=int, default=8, help="Minimum score required to generate a finding")
    parser.add_argument("--rev-range", default="--all", help="Revision set to scan, for example --all or origin/main..HEAD")
    parser.add_argument("--include-merges", action="store_true", help="Include merge commits")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing finding files")
    parser.add_argument("--candidate-file", help="Optional JSON file from phase 1 ranking; if provided, phase 2 uses it instead of rescanning")
    parser.add_argument("--include-unaccepted", action="store_true", help="Generate findings for all candidates in the candidate file, not only accepted ones")
    return parser.parse_args()


def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def slugify(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-") or "finding"


def signal_text(commit: rank_fix_commits.RankedCommit, repo: Path) -> str:
    body = rank_fix_commits.load_body(repo, commit.sha)
    return clean_text(" ".join([commit.subject, body, *commit.files])).lower()


def infer_domain(files: list[str]) -> str:
    lowered = " ".join(path.lower() for path in files)
    if any(term in lowered for term in ("validator", "slashing", "signer", "keystore")):
        return "validator-ops"
    if any(term in lowered for term in ("storage", "state", "snapshot", "db", "database", "wal", "crypto", "signature", "hash")):
        return "infrastructure"
    return "blockchain-core"


def infer_subsystem(commit: rank_fix_commits.RankedCommit, text: str) -> str:
    haystack = (" ".join(commit.files) + " " + text).lower()
    for subsystem, terms in SUBSYSTEM_RULES:
        score = sum(1 for term in terms if term in haystack)
        if score > 0:
            return subsystem
    return "core-logic"


def infer_bug_class(text: str) -> str:
    for bug_class, terms in BUG_CLASS_RULES:
        score = sum(1 for term in terms if term in text)
        if score > 0:
            return bug_class
    return "hardening-or-correctness-fix"


def infer_impact_types(text: str, bug_class: str) -> list[str]:
    if bug_class == "resource-exhaustion":
        return ["remote-dos"]
    if bug_class == "access-control":
        return ["privilege-misuse"]
    if bug_class == "replay-or-signature-validation":
        return ["request-forgery-or-replay"]
    if bug_class == "consensus-safety":
        return ["consensus-failure"]
    if bug_class == "liveness-failure":
        return ["liveness"]
    if bug_class == "state-corruption":
        return ["state-integrity"]
    return ["correctness-or-hardening"]


def infer_tags(domain: str, subsystem: str, bug_class: str, impacts: list[str], files: list[str]) -> list[str]:
    tags = [domain, subsystem, bug_class, *impacts]
    lowered = " ".join(files).lower()
    for term in ("p2p", "queue", "validator", "consensus", "snapshot", "rpc", "multisig", "signature", "replay", "database"):
        if term in lowered:
            tags.append(term)
    return list(dict.fromkeys(slugify(tag) for tag in tags if tag))[:8]


def infer_confidence(commit: rank_fix_commits.RankedCommit) -> str:
    if "message uses explicit security language" in commit.reasons and commit.test_files:
        return "high"
    if commit.band in {"high", "medium"}:
        return "medium"
    return "low"


def infer_source_quality(commit: rank_fix_commits.RankedCommit) -> str:
    if "message uses explicit security language" in commit.reasons:
        return "high"
    return "medium"


def summarize_subject(subject: str) -> str:
    subject = re.sub(r"^(fix|patch|hotfix|security|bugfix):\s*", "", subject, flags=re.IGNORECASE)
    subject = clean_text(subject)
    return subject[:1].upper() + subject[1:] if subject else "Patch-level behavior change"


def infer_summary(project: str, subsystem: str, bug_class: str, subject: str) -> str:
    issue = summarize_subject(subject)
    if bug_class == "resource-exhaustion":
        return f"{issue} appears to address a {subsystem} weakness where malformed or excessive activity could consume resources and degrade service availability in {project}."
    if bug_class == "access-control":
        return f"{issue} appears to tighten authorization in the {subsystem} path so sensitive behavior is less likely to execute without the right checks in {project}."
    if bug_class == "replay-or-signature-validation":
        return f"{issue} appears to harden signature or replay-sensitive handling in the {subsystem} path, reducing the chance of invalid requests being accepted in {project}."
    if bug_class == "consensus-safety":
        return f"{issue} appears to correct a consensus-sensitive path in {project}, reducing the chance of disagreement, unsafe state transitions, or protocol instability."
    if bug_class == "liveness-failure":
        return f"{issue} appears to address a liveness issue in the {subsystem} path where certain conditions could cause stalling, crashes, or degraded progress in {project}."
    return f"{issue} looks like a focused hardening fix in the {subsystem} area of {project}. The patch likely closes a reliability or safety weakness rather than adding a new feature."


def infer_root_cause(bug_class: str, subsystem: str) -> str:
    if bug_class == "resource-exhaustion":
        return f"The likely root cause was insufficient bounds or early rejection in the {subsystem} path, allowing work, messages, or buffers to grow faster than they were safely processed."
    if bug_class == "access-control":
        return f"The likely root cause was weak authorization boundaries in the {subsystem} logic, where sensitive actions were not tightly gated before execution."
    if bug_class == "replay-or-signature-validation":
        return f"The likely root cause was incomplete validation of signed or replay-sensitive inputs in the {subsystem} path before state-changing behavior occurred."
    if bug_class == "consensus-safety":
        return f"The likely root cause was a broken or under-enforced invariant in the {subsystem} logic, where edge-case state transitions could diverge from expected protocol rules."
    if bug_class == "liveness-failure":
        return f"The likely root cause was brittle failure handling in the {subsystem} path, where retries, panics, lock behavior, or timeouts could interrupt progress under edge conditions."
    if bug_class == "state-corruption":
        return f"The likely root cause was unsafe state handling in the {subsystem} area, especially around persistence, serialization, or recovery behavior."
    if bug_class == "input-validation":
        return f"The likely root cause was missing or delayed input validation in the {subsystem} path before deeper processing occurred."
    return f"The likely root cause was an under-protected code path in the {subsystem} area, where assumptions about input, state, or execution flow were not enforced strongly enough."


def infer_fix_pattern(text: str, bug_class: str, subsystem: str) -> str:
    parts: list[str] = []
    if any(term in text for term in ("limit", "bound", "queue", "buffer", "throttle", "backpressure", "ratelimit", "rate limit")):
        parts.append("added stronger bounds or backpressure")
    if any(term in text for term in ("validate", "verify", "sanitize", "decode", "parse")):
        parts.append("moved validation earlier in the flow")
    if any(term in text for term in ("auth", "permission", "role", "admin", "multisig", "threshold")):
        parts.append("tightened authorization checks")
    if any(term in text for term in ("retry", "timeout", "panic", "unwrap", "expect")):
        parts.append("improved failure handling")
    if any(term in text for term in ("snapshot", "restore", "serialize", "deserialize", "state", "database")):
        parts.append("strengthened state handling invariants")
    if not parts:
        fallback = {
            "resource-exhaustion": "introduced capacity controls and earlier rejection",
            "access-control": "introduced explicit permission gates",
            "replay-or-signature-validation": "hardened validation before accepting sensitive inputs",
            "consensus-safety": f"tightened critical checks in the {subsystem} path",
        }
        parts.append(fallback.get(bug_class, f"tightened the critical path in the {subsystem} area"))
    if len(parts) == 1:
        return f"The fix {parts[0]}."
    return f"The fix {', '.join(parts[:-1])}, and {parts[-1]}."


def infer_why_it_matters(subsystem: str, bug_class: str) -> str:
    if bug_class == "resource-exhaustion":
        return f"Projects with similar {subsystem} paths should be checked for unbounded queues, delayed validation, and weak capacity controls because those patterns often turn malformed traffic into availability risk."
    if bug_class == "access-control":
        return f"Projects with similar {subsystem} logic should be reviewed for hidden privileged paths, missing authorization checks, and assumptions that trusted callers will always behave correctly."
    if bug_class == "replay-or-signature-validation":
        return f"Projects with similar {subsystem} logic should be checked for signature validation gaps, nonce handling mistakes, and replay windows that can make invalid requests look legitimate."
    if bug_class == "consensus-safety":
        return f"Projects with similar {subsystem} logic should be reviewed for edge-case state transitions, quorum assumptions, and recovery paths that could break consensus invariants under stress."
    if bug_class == "liveness-failure":
        return f"Projects with similar {subsystem} logic should be reviewed for retry storms, lock contention, panic paths, and timeout handling that can quietly degrade network progress."
    return f"Projects with similar {subsystem} paths should be reviewed for the same invariant gap, especially where small validation or state-handling mistakes could create broader operational risk."


def infer_evidence_notes(commit: rank_fix_commits.RankedCommit) -> str:
    cues = [f"commit '{clean_text(commit.subject)}'"]
    if commit.test_files:
        cues.append("nearby test changes")
    cues.append("the changed implementation paths")
    note = "This finding was inferred from " + ", ".join(cues[:-1]) + f", and {cues[-1]}."
    if commit.band != "high":
        note += " Exploitability is not explicitly confirmed and should be treated as an informed inference."
    else:
        note += " The patch looks high-signal, but the exact exploit path should still be confirmed during review."
    return note


def is_bootstrap_like(commit: rank_fix_commits.RankedCommit) -> bool:
    subject = commit.subject.lower()
    noisy_words = ("initial", "bootstrap", "import", "scaffold", "scaffolding", "first commit")
    if any(word in subject for word in noisy_words):
        return True
    if len(commit.files) > 20 and "message uses explicit security language" not in commit.reasons:
        return True
    return False


def load_ranked_commits(repo: Path, args: argparse.Namespace) -> list[rank_fix_commits.RankedCommit]:
    if args.candidate_file:
        payload = json.loads(Path(args.candidate_file).read_text(encoding="utf-8"))
        items = payload.get("classified_candidates")
        if items is None:
            items = payload.get("candidates", [])
        if not args.include_unaccepted:
            items = [item for item in items if item.get("accepted", True)]
        ranked = [
            rank_fix_commits.RankedCommit(
                **{
                    key: value
                    for key, value in item.items()
                    if key in rank_fix_commits.RankedCommit.__dataclass_fields__
                }
            )
            for item in items
        ]
        ranked = [item for item in ranked if not is_bootstrap_like(item)]
        if args.limit > 0:
            ranked = ranked[: args.limit]
        return ranked

    commits = rank_fix_commits.list_commits(repo, args.rev_range, args.include_merges)
    ranked = [rank_fix_commits.analyze_commit(repo, sha) for sha in commits]
    ranked.sort(key=lambda item: (item.score, item.date, item.sha), reverse=True)
    ranked = [item for item in ranked if item.score >= args.min_score and not is_bootstrap_like(item)]
    if args.limit > 0:
        ranked = ranked[: args.limit]
    return ranked


def build_markdown(repo: Path, commit: rank_fix_commits.RankedCommit) -> str:
    text = signal_text(commit, repo)
    project = slugify(repo.name)
    domain = infer_domain(commit.files)
    subsystem = infer_subsystem(commit, text)
    bug_class = infer_bug_class(text)
    impacts = infer_impact_types(text, bug_class)
    confidence = infer_confidence(commit)
    source_quality = infer_source_quality(commit)
    tags = infer_tags(domain, subsystem, bug_class, impacts, commit.files)
    summary = infer_summary(project, subsystem, bug_class, commit.subject)
    root_cause = infer_root_cause(bug_class, subsystem)
    fix_pattern = infer_fix_pattern(text, bug_class, subsystem)
    why_it_matters = infer_why_it_matters(subsystem, bug_class)
    evidence_notes = infer_evidence_notes(commit)

    lines = [
        "---",
        f"case_id: case_{commit.date.replace('-', '')}_{commit.short_sha}",
        f"project: {project}",
        f"domain: {domain}",
        f"subsystem: {subsystem}",
        f"bug_class: {bug_class}",
        "impact_type:",
    ]
    lines.extend(f"  - {impact}" for impact in impacts)
    lines.extend([
        f"confidence: {confidence}",
        f"source_quality: {source_quality}",
        "tags:",
    ])
    lines.extend(f"  - {tag}" for tag in tags)
    lines.extend([
        f"date: {commit.date}",
        "source_refs:",
        f"  - git:{commit.sha}",
        "---",
        "",
        "# Summary",
        "",
        summary,
        "",
        "# Root Cause",
        "",
        root_cause,
        "",
        "# Fix Pattern",
        "",
        fix_pattern,
        "",
        "# Why It Matters",
        "",
        why_it_matters,
        "",
        "# Evidence Notes",
        "",
        evidence_notes,
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = repo / out_dir

    try:
        rank_fix_commits.run_git(repo, "rev-parse", "--show-toplevel")
    except subprocess.CalledProcessError:
        print(f"{repo} is not a git repository")
        return 2

    ranked = load_ranked_commits(repo, args)

    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for commit in ranked:
        text = signal_text(commit, repo)
        subsystem = infer_subsystem(commit, text)
        filename = f"{commit.date}-{slugify(repo.name)}-{slugify(subsystem)}-{commit.short_sha}.md"
        target = out_dir / filename
        if target.exists() and not args.overwrite:
            continue
        target.write_text(build_markdown(repo, commit), encoding="utf-8")
        written += 1
        print(target)

    print(f"Wrote {written} finding file(s) to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
