#!/usr/bin/env python3
"""Generate richer Markdown findings from likely fix commits."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import phase3_agents
import rank_fix_commits


SUBSYSTEM_RULES = [
    ("staking", ("staking", "stake", "escrow", "delegat", "debond", "accountinfo")),
    ("rpc-client-api", ("grpc", "request", "response", "marshal", "unmarshal", "protobuf", "cbor")),
    ("p2p-networking", ("p2p", "network", "peer", "handshake", "mempool")),
    ("consensus", ("consensus", "quorum", "vote", "epoch", "fork", "final")),
    ("transaction-processing", ("transaction", "tx", "blobtx", "evm", "ethereum", "decode", "unpack", "signature", "rawsignaturevalues", "asethereumdata")),
    ("validator-ops", ("validator", "slashing", "signer", "keystore")),
    ("storage", ("storage", "state", "snapshot", "db", "database", "wal")),
    ("cryptography", ("crypto", "signature", "verify", "hash", "nonce", "replay")),
    ("access-control", ("auth", "access", "permission", "role", "admin", "multisig")),
]

BUG_CLASS_RULES = [
    ("resource-exhaustion", ("dos", "denial of service", "queue", "buffer", "throttle", "backpressure", "ratelimit", "rate limit")),
    ("access-control", ("auth", "permission", "role", "admin", "multisig", "authorize", "privilege")),
    ("replay-or-signature-validation", ("signature", "verify", "nonce", "replay", "ecdsa", "ed25519", "secp256k1")),
    ("serialization-or-state-representation", ("marshal", "unmarshal", "cbor", "protobuf", "proto", "request", "response", "grpc")),
    ("accounting-or-state-drift", ("balance", "collateral", "reserve", "opening_amount", "opening_size", "funding", "settlement", "accounting", "supply", "mint", "burn", "valuation")),
    ("consensus-safety", ("consensus", "quorum", "fork", "finaliz", "checkpoint", "vote")),
    ("liveness-failure", ("stall", "halt", "deadlock", "timeout", "retry", "panic", "crash")),
    ("state-corruption", ("snapshot", "restore", "state", "db", "database", "serialize", "deserialize", "corrupt")),
    ("input-validation", ("validate", "sanitize", "decode", "encode", "parse")),
]

COMPOUND_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:(?:::|\.)[A-Za-z_][A-Za-z0-9_]*)+")
SIMPLE_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b")
IDENTIFIER_STOPWORDS = {
    "true",
    "false",
    "return",
    "public",
    "private",
    "internal",
    "let",
    "mut",
    "self",
    "this",
    "bool",
    "uint",
    "u64",
    "u128",
    "i64",
    "string",
    "bytes",
    "address",
    "decimal",
    "struct",
    "package",
    "client",
    "server",
    "request",
    "response",
    "context",
    "google",
    "github",
    "grpc",
    "node",
    "main",
    "while",
    "else",
    "then",
    "func",
    "nil",
    "err",
    "line",
}
BOILERPLATE_PREFIXES = (
    "package ",
    "import ",
    "from ",
    "use ",
    "#include ",
    "module ",
    "namespace ",
)
FEATURE_REASON_FRAGMENTS = ("feature", "architectural", "plumbing", "migration")
STRONG_SECURITY_REASONS = {
    "message uses explicit security language",
    "message names a failure mode",
    "diff changes access control or privilege checks",
    "diff changes cryptographic or replay-sensitive logic",
    "diff changes consensus or validator logic",
    "diff changes runtime guards or failure handling",
    "diff changes resource-control logic",
}
ACCOUNTING_LIFECYCLE_TERMS = (
    "close",
    "closed",
    "clear",
    "cleared",
    "destroy",
    "destroyed",
    "remove",
    "removed",
    "delete",
    "deleted",
    "liquidat",
    "opening_amount",
    "opening_size",
    "decrease",
    "increase",
    "settlement",
)
BLOCK_HEADER_PATTERNS = (
    re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\b"),
    re.compile(r"^\s*func\b"),
    re.compile(r"^\s*def\b"),
    re.compile(r"^\s*(?:class|interface|enum|trait|impl)\b"),
    re.compile(r"^\s*type\s+[A-Za-z_][A-Za-z0-9_]*\s+struct\b"),
    re.compile(r"^\s*function\b"),
)


@dataclass
class ContextSnippet:
    file: str
    line: int
    header: str
    excerpt: str
    kind: str
    identifiers: list[str] = field(default_factory=list)


@dataclass
class ProjectContext:
    primary_directories: list[str]
    changed_contexts: list[ContextSnippet]
    related_contexts: list[ContextSnippet]
    related_test_files: list[str]
    identifiers: list[str]


@dataclass
class RenderedFinding:
    markdown: str
    subsystem: str
    bug_class: str
    confidence: str
    source_quality: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Path to the git repository")
    parser.add_argument("--out-dir", default="findings", help="Directory where Markdown findings will be written")
    parser.add_argument("--limit", type=int, default=0, help="Maximum number of findings to generate; use 0 for no limit")
    parser.add_argument("--min-score", type=int, default=8, help="Minimum score required to generate a finding")
    parser.add_argument("--rev-range", default="--all", help="Revision set to scan, for example --all or origin/main..HEAD")
    parser.add_argument("--include-merges", action="store_true", help="Include merge commits")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing finding files")
    parser.add_argument("--candidate-file", help="Optional JSON file from phase 1 or phase 2; if provided, phase 3 uses it instead of rescanning")
    parser.add_argument("--include-unaccepted", action="store_true", help="Generate findings for all candidates in the candidate file, not only accepted ones")
    parser.add_argument(
        "--agent-mode",
        choices=("heuristic", "mapper-drafter-skeptic"),
        default="heuristic",
        help="Phase 3 rendering mode. 'mapper-drafter-skeptic' uses separate LLM passes on top of the project-context system.",
    )
    parser.add_argument(
        "--agent-provider",
        choices=("openai",),
        default="openai",
        help="LLM provider used for agent-backed phase 3.",
    )
    parser.add_argument(
        "--agent-model",
        default="gpt-5",
        help="Model name for agent-backed phase 3.",
    )
    parser.add_argument(
        "--agent-strict",
        action="store_true",
        help="Fail instead of falling back to heuristic rendering if an agent step errors.",
    )
    return parser.parse_args()


def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def slugify(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-") or "finding"


def best_keyword_match(text: str, rules: list[tuple[str, tuple[str, ...]]], default: str, min_score: int = 1) -> str:
    haystack = text.lower()
    best_label = default
    best_score = 0
    for label, terms in rules:
        score = sum(term in haystack for term in terms)
        if score > best_score:
            best_label = label
            best_score = score
    if best_score < min_score:
        return default
    return best_label


def build_grounded_text(commit: rank_fix_commits.RankedCommit, evidences: list[rank_fix_commits.HunkEvidence]) -> str:
    if evidences:
        return clean_text(" ".join([evidence.file + " " + evidence.signal_text for evidence in evidences])).lower()
    return clean_text(" ".join(commit.implementation_files or commit.source_files)).lower()


def load_parent_sha(repo: Path, sha: str) -> str | None:
    try:
        parent = rank_fix_commits.run_git(repo, "rev-parse", f"{sha}^").strip()
    except subprocess.CalledProcessError:
        return None
    return parent or None


def load_file_at_revision(repo: Path, sha: str | None, path: str) -> str:
    if not sha:
        return ""
    try:
        return rank_fix_commits.run_git(repo, "show", f"{sha}:{path}")
    except subprocess.CalledProcessError:
        return ""


def list_tree_files(repo: Path, sha: str, prefix: str) -> list[str]:
    try:
        output = rank_fix_commits.run_git(repo, "ls-tree", "-r", "--name-only", sha, "--", prefix)
    except subprocess.CalledProcessError:
        return []
    return [line for line in output.splitlines() if line.strip()]


def file_directory_hints(path: str) -> list[str]:
    parent = Path(path).parent
    parts = parent.parts
    hints: list[str] = []
    if not parts or str(parent) == ".":
        return []
    hints.append(parent.as_posix())
    if len(parts) >= 3:
        hints.append(Path(*parts[:-1]).as_posix())
    return list(dict.fromkeys(hints))


def find_block_start(lines: list[str], target_index: int) -> int:
    lower_bound = max(0, target_index - 60)
    for index in range(target_index, lower_bound - 1, -1):
        if any(pattern.search(lines[index]) for pattern in BLOCK_HEADER_PATTERNS):
            return index
    return max(0, target_index - 6)


def extract_context_snippet(text: str, line_no: int, file: str, kind: str) -> ContextSnippet | None:
    if not text:
        return None
    lines = text.splitlines()
    if not lines:
        return None
    target_index = min(max(line_no - 1, 0), len(lines) - 1)
    start = find_block_start(lines, target_index)
    end = min(len(lines), max(target_index + 8, start + 14))
    excerpt = "\n".join(lines[start:end]).strip()
    if not excerpt:
        return None
    header = clean_text(lines[start]) if lines[start].strip() else f"{file}:{line_no}"
    identifiers = collect_identifiers_from_texts([excerpt], limit=6)
    return ContextSnippet(
        file=file,
        line=start + 1,
        header=header,
        excerpt=excerpt,
        kind=kind,
        identifiers=identifiers,
    )


def collect_identifiers_from_texts(texts: list[str], limit: int = 8) -> list[str]:
    counter: Counter[str] = Counter()
    for text in texts:
        for token in COMPOUND_IDENTIFIER_RE.findall(text):
            if identifier_is_noise(token):
                continue
            counter[token] += 3
        for token in SIMPLE_IDENTIFIER_RE.findall(text):
            if token.isupper() or identifier_is_noise(token):
                continue
            counter[token] += 1
    return [token for token, _ in counter.most_common(limit)]


def choose_context_line(text: str, identifiers: list[str]) -> int:
    lines = text.splitlines()
    lowered_identifiers = [identifier.lower() for identifier in identifiers if identifier]
    for index, line in enumerate(lines, start=1):
        lowered = line.lower()
        if any(identifier in lowered for identifier in lowered_identifiers):
            return index
    for index, line in enumerate(lines, start=1):
        if any(pattern.search(line) for pattern in BLOCK_HEADER_PATTERNS):
            return index
    return 1


def score_related_file(path: str, changed_files: set[str], directory_hints: set[str], identifiers: list[str], content: str) -> int:
    if path in changed_files:
        return -999
    score = 0
    lowered_path = path.lower()
    basename = Path(path).stem.lower()
    if str(Path(path).parent) in {str(Path(changed).parent) for changed in changed_files}:
        score += 4
    if any(hint and hint.lower() in lowered_path for hint in directory_hints):
        score += 3
    for identifier in identifiers[:5]:
        lowered_identifier = identifier.lower()
        if lowered_identifier in basename:
            score += 2
        if lowered_identifier in content.lower():
            score += 1
    if rank_fix_commits.is_test_file(path):
        score += 1
    if basename in {"main", "init", "common", "util", "utils"}:
        score -= 3
    return score


def collect_related_contexts(
    repo: Path,
    sha: str,
    evidences: list[rank_fix_commits.HunkEvidence],
    identifiers: list[str],
    limit: int = 2,
) -> tuple[list[ContextSnippet], list[str]]:
    changed_files = {evidence.file for evidence in evidences}
    directory_hints = {hint for evidence in evidences for hint in file_directory_hints(evidence.file)}
    candidate_paths: list[str] = []
    for hint in sorted(directory_hints):
        candidate_paths.extend(list_tree_files(repo, sha, hint))
    ordered_candidates = list(dict.fromkeys(candidate_paths))

    scored_paths: list[tuple[int, str, str]] = []
    for path in ordered_candidates:
        if not rank_fix_commits.is_source_file(path):
            continue
        content = load_file_at_revision(repo, sha, path)
        if not content:
            continue
        score = score_related_file(path, changed_files, directory_hints, identifiers, content)
        if score <= 0:
            continue
        scored_paths.append((score, path, content))

    scored_paths.sort(key=lambda item: (item[0], item[1]), reverse=True)
    related_contexts: list[ContextSnippet] = []
    related_tests: list[str] = []
    for _, path, content in scored_paths:
        if path in changed_files:
            continue
        if rank_fix_commits.is_test_file(path):
            related_tests.append(path)
            continue
        if len(related_contexts) >= limit:
            continue
        context_line = choose_context_line(content, identifiers)
        snippet = extract_context_snippet(content, context_line, path, "related")
        if not snippet:
            continue
        related_contexts.append(snippet)

    return related_contexts[:limit], list(dict.fromkeys(related_tests))[:2]


def build_project_context(
    repo: Path,
    commit: rank_fix_commits.RankedCommit,
    evidences: list[rank_fix_commits.HunkEvidence],
) -> ProjectContext:
    parent_sha = load_parent_sha(repo, commit.sha)
    changed_contexts: list[ContextSnippet] = []
    context_texts: list[str] = []
    primary_directories = list(
        dict.fromkeys(
            hint
            for evidence in evidences
            for hint in file_directory_hints(evidence.file)
            if "/" in hint or hint in {"x", "go", "src", "pkg", "internal", "cmd"}
        )
    )[:4]

    for evidence in evidences:
        after_text = load_file_at_revision(repo, commit.sha, evidence.file)
        snippet = extract_context_snippet(after_text, evidence.new_start, evidence.file, "changed")
        if snippet:
            changed_contexts.append(snippet)
            context_texts.append(snippet.excerpt)
        before_text = load_file_at_revision(repo, parent_sha, evidence.file)
        if before_text:
            before_snippet = extract_context_snippet(before_text, max(evidence.old_start, 1), evidence.file, "before")
            if before_snippet:
                context_texts.append(before_snippet.excerpt)

    identifiers = list(
        dict.fromkeys(
            collect_identifier_hints(evidences)
            + collect_identifiers_from_texts(context_texts, limit=10)
        )
    )[:10]
    related_contexts, related_tests = collect_related_contexts(repo, commit.sha, evidences, identifiers, limit=2)
    all_identifiers = list(
        dict.fromkeys(
            identifiers
            + [identifier for snippet in changed_contexts for identifier in snippet.identifiers]
            + [identifier for snippet in related_contexts for identifier in snippet.identifiers]
        )
    )[:10]

    return ProjectContext(
        primary_directories=primary_directories,
        changed_contexts=changed_contexts,
        related_contexts=related_contexts,
        related_test_files=related_tests,
        identifiers=all_identifiers,
    )


def project_context_text(project_context: ProjectContext) -> str:
    parts = [*project_context.primary_directories, *project_context.identifiers]
    parts.extend(snippet.file for snippet in project_context.changed_contexts)
    parts.extend(snippet.file for snippet in project_context.related_contexts)
    parts.extend(snippet.excerpt for snippet in project_context.changed_contexts[:2])
    parts.extend(snippet.excerpt for snippet in project_context.related_contexts[:2])
    return clean_text(" ".join(parts)).lower()


def valid_subsystems() -> set[str]:
    return {label for label, _ in SUBSYSTEM_RULES} | {"core-logic"}


def valid_bug_classes() -> set[str]:
    return {label for label, _ in BUG_CLASS_RULES} | {"hardening-or-correctness-fix"}


def normalize_agent_subsystem(value: str | None, fallback: str) -> str:
    cleaned = slugify(value or "")
    return cleaned if cleaned in valid_subsystems() else fallback


def normalize_agent_bug_class(value: str | None, fallback: str) -> str:
    cleaned = slugify(value or "")
    return cleaned if cleaned in valid_bug_classes() else fallback


def normalize_agent_confidence(value: str | None, fallback: str) -> str:
    cleaned = clean_text(value or "").lower()
    return cleaned if cleaned in {"low", "medium", "high"} else fallback


def format_numbered_section(items: list[str], fallback: str) -> str:
    cleaned = [clean_text(item) for item in items if clean_text(item)]
    if not cleaned:
        return fallback
    return "\n\n".join(f"{index}. {item}" for index, item in enumerate(cleaned, start=1))


def build_agent_bundle(
    repo: Path,
    commit: rank_fix_commits.RankedCommit,
    evidences: list[rank_fix_commits.HunkEvidence],
    project_context: ProjectContext,
    heuristic_subsystem: str,
    heuristic_bug_class: str,
    heuristic_confidence: str,
    heuristic_source_quality: str,
    heuristic_fix_pattern: str,
    heuristic_impact: str,
    heuristic_overview: str,
    heuristic_root_cause: str,
) -> dict[str, Any]:
    return {
        "project": repo.name,
        "commit": {
            "sha": commit.sha,
            "short_sha": commit.short_sha,
            "date": commit.date,
            "subject": commit.subject,
            "body": rank_fix_commits.load_body(repo, commit.sha),
            "files": commit.files,
            "reasons": commit.reasons,
        },
        "heuristic_baseline": {
            "subsystem": heuristic_subsystem,
            "bug_class": heuristic_bug_class,
            "confidence": heuristic_confidence,
            "source_quality": heuristic_source_quality,
            "overview": heuristic_overview,
            "root_cause": heuristic_root_cause,
            "fix_pattern": heuristic_fix_pattern,
            "why_it_matters": heuristic_impact,
        },
        "evidence": [
            {
                "file": evidence.file,
                "line": evidence.new_start,
                "score": evidence.score,
                "reasons": evidence.reasons,
                "before": evidence.before,
                "after": evidence.after,
                "changed_lines": evidence.changed_lines,
            }
            for evidence in evidences
        ],
        "project_context": {
            "primary_directories": project_context.primary_directories,
            "identifiers": project_context.identifiers,
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
            "related_test_files": project_context.related_test_files,
        },
    }


def build_affected_code_paths_from_agent(
    agent_paths: list[dict[str, Any]],
    fallback: str,
) -> str:
    if not agent_paths:
        return fallback
    lines = [
        "| File | Lines | Role |",
        "| --- | --- | --- |",
    ]
    for item in agent_paths:
        file = clean_text(str(item.get("file", "")))
        if not file:
            continue
        line = item.get("line", 1)
        try:
            line_value = int(line)
        except (TypeError, ValueError):
            line_value = 1
        role = clean_text(str(item.get("role", ""))) or "related code path"
        lines.append(f"| {file} | {line_value} | {role} |")
    return "\n".join(lines) if len(lines) > 2 else fallback


def infer_domain(files: list[str]) -> str:
    lowered = " ".join(path.lower() for path in files)
    if any(term in lowered for term in ("validator", "slashing", "signer", "keystore")):
        return "validator-ops"
    if any(term in lowered for term in ("storage", "state", "snapshot", "db", "database", "wal", "crypto", "signature", "hash", "evm")):
        return "infrastructure"
    return "blockchain-core"


def infer_subsystem(
    commit: rank_fix_commits.RankedCommit,
    grounded_text: str,
    evidences: list[rank_fix_commits.HunkEvidence],
    project_context: ProjectContext,
) -> str:
    parts = [grounded_text, project_context_text(project_context), " ".join(commit.files)]
    parts.extend(evidence.file for evidence in evidences)
    parts.extend(snippet.file for snippet in project_context.related_contexts)
    combined = " ".join(parts).lower()
    scores = {label: sum(term in combined for term in terms) for label, terms in SUBSYSTEM_RULES}
    file_text = " ".join(commit.files).lower()
    if scores.get("staking", 0) >= 2 and any(term in file_text for term in ("staking", "/stake", "stake/")):
        return "staking"
    best_label = "core-logic"
    best_score = 0
    for label, score in scores.items():
        if score > best_score:
            best_label = label
            best_score = score
    if best_score < 2:
        return "core-logic"
    return best_label


def infer_bug_class(
    commit: rank_fix_commits.RankedCommit,
    grounded_text: str,
    evidences: list[rank_fix_commits.HunkEvidence],
    project_context: ProjectContext,
) -> str:
    combined = " ".join([grounded_text, project_context_text(project_context), commit.subject.lower(), " ".join(commit.files).lower()])
    if is_panic_on_untrusted_input(combined):
        return "liveness-failure"

    accounting_score = sum(term in combined for term in dict(BUG_CLASS_RULES)["accounting-or-state-drift"])
    representation_score = sum(term in combined for term in dict(BUG_CLASS_RULES)["serialization-or-state-representation"])
    lifecycle_score = sum(term in combined for term in ACCOUNTING_LIFECYCLE_TERMS)
    strong_security_signal = has_strong_security_signal(commit, combined, evidences)

    if representation_score >= 3 and (accounting_score < 3 or lifecycle_score == 0) and not strong_security_signal:
        return "serialization-or-state-representation"
    if accounting_score >= 3 and lifecycle_score >= 1:
        return "accounting-or-state-drift"
    return best_keyword_match(combined, BUG_CLASS_RULES, "hardening-or-correctness-fix", min_score=2)


def infer_impact_types(bug_class: str) -> list[str]:
    if bug_class == "resource-exhaustion":
        return ["remote-dos"]
    if bug_class == "access-control":
        return ["privilege-misuse"]
    if bug_class == "replay-or-signature-validation":
        return ["request-forgery-or-replay"]
    if bug_class == "serialization-or-state-representation":
        return ["state-consistency", "client-view-divergence"]
    if bug_class == "accounting-or-state-drift":
        return ["state-accounting", "economic-distortion"]
    if bug_class == "consensus-safety":
        return ["consensus-failure"]
    if bug_class == "liveness-failure":
        return ["liveness"]
    if bug_class == "state-corruption":
        return ["state-integrity"]
    return ["correctness-or-hardening"]


def infer_tags(
    domain: str,
    subsystem: str,
    bug_class: str,
    impacts: list[str],
    evidences: list[rank_fix_commits.HunkEvidence],
    files: list[str],
    project_context: ProjectContext,
) -> list[str]:
    tags = [domain, subsystem, bug_class, *impacts]
    lowered = f'{" ".join(files).lower()} {project_context_text(project_context)}'
    for evidence in evidences:
        lowered = f"{lowered} {evidence.file.lower()} {evidence.signal_text}"
    for term in ("p2p", "queue", "validator", "consensus", "snapshot", "rpc", "multisig", "signature", "replay", "database", "funding", "collateral", "settlement"):
        if term in lowered:
            tags.append(term)
    return list(dict.fromkeys(slugify(tag) for tag in tags if tag))[:10]


def infer_confidence(commit: rank_fix_commits.RankedCommit, evidences: list[rank_fix_commits.HunkEvidence]) -> str:
    max_score = max((evidence.score for evidence in evidences), default=0)
    max_quality = max((evidence_quality_score(evidence) for evidence in evidences), default=0)
    if max_score >= 7 and max_quality >= 16 and len(evidences) >= 2 and commit.test_files and not commit_looks_feature_like(commit):
        return "high"
    if max_score >= 5 and max_quality >= 10 and not commit_looks_feature_like(commit):
        return "medium"
    if max_score >= 3 or commit.band in {"high", "medium"}:
        return "medium"
    return "low"


def infer_source_quality(commit: rank_fix_commits.RankedCommit, evidences: list[rank_fix_commits.HunkEvidence]) -> str:
    max_score = max((evidence.score for evidence in evidences), default=0)
    max_quality = max((evidence_quality_score(evidence) for evidence in evidences), default=0)
    if max_score >= 7 and max_quality >= 16 and len(evidences) >= 2:
        return "high"
    if max_score >= 3 and max_quality >= 8:
        return "medium"
    if commit.implementation_files:
        return "medium"
    return "low"


def summarize_subject(subject: str) -> str:
    subject = re.sub(r"^(fix|patch|hotfix|security|bugfix):\s*", "", subject, flags=re.IGNORECASE)
    subject = clean_text(subject)
    return subject[:1].upper() + subject[1:] if subject else "Patch-level behavior change"


def collect_identifier_hints(evidences: list[rank_fix_commits.HunkEvidence]) -> list[str]:
    counter: Counter[str] = Counter()
    for evidence in evidences:
        text = "\n".join([evidence.before, evidence.after, *evidence.changed_lines])
        for token in COMPOUND_IDENTIFIER_RE.findall(text):
            if identifier_is_noise(token):
                continue
            counter[token] += 3
        for token in SIMPLE_IDENTIFIER_RE.findall(text):
            lowered = token.lower()
            if lowered in IDENTIFIER_STOPWORDS or identifier_is_noise(token):
                continue
            if token.isupper():
                continue
            counter[token] += 1
    return [token for token, _ in counter.most_common(6)]


def format_identifier_list(identifiers: list[str], limit: int = 3) -> str:
    chosen = [f"`{name}`" for name in identifiers[:limit]]
    if not chosen:
        return ""
    if len(chosen) == 1:
        return chosen[0]
    return ", ".join(chosen[:-1]) + f", and {chosen[-1]}"


def guess_code_language(path: str) -> str:
    suffix = Path(path).suffix.lower()
    return {
        ".go": "go",
        ".rs": "rust",
        ".py": "python",
        ".ts": "ts",
        ".js": "javascript",
        ".java": "java",
        ".kt": "kotlin",
        ".c": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
    }.get(suffix, "text")


def is_panic_on_untrusted_input(grounded_text: str) -> bool:
    panic_terms = ("panic", "overflow", "mustfrombig", "must_from_big")
    input_terms = ("decode", "unpack", "blobtx", "txdata", "transaction", "signature", "ethereumdata", "asethereumdata")
    return any(term in grounded_text for term in panic_terms) and any(term in grounded_text for term in input_terms)


def identifiers_for_evidence(evidence: rank_fix_commits.HunkEvidence) -> list[str]:
    text = "\n".join([evidence.before, evidence.after, *evidence.changed_lines])
    counter: Counter[str] = Counter()
    for token in COMPOUND_IDENTIFIER_RE.findall(text):
        if identifier_is_noise(token):
            continue
        counter[token] += 3
    for token in SIMPLE_IDENTIFIER_RE.findall(text):
        lowered = token.lower()
        if lowered in IDENTIFIER_STOPWORDS or token.isupper() or identifier_is_noise(token):
            continue
        counter[token] += 1
    return [token for token, _ in counter.most_common(3)]


def identifier_is_noise(token: str) -> bool:
    lowered = token.lower()
    if lowered in IDENTIFIER_STOPWORDS:
        return True
    if lowered.startswith(("github.", "google.", "golang.")):
        return True
    if "." in lowered and "/" not in lowered and all(part.islower() for part in lowered.split(".") if part):
        return True
    return False


def is_boilerplate_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if stripped in {"{", "}", "(", ")", "[", "]", "import ("}:
        return True
    if stripped.startswith(BOILERPLATE_PREFIXES):
        return True
    if re.fullmatch(r'"[^"]+"', stripped):
        return True
    return False


def semantic_lines(lines: list[str]) -> list[str]:
    return [line.strip() for line in lines if line.strip() and not is_boilerplate_line(line)]


def snippet_semantic_lines(text: str) -> list[str]:
    return semantic_lines(text.splitlines())


def evidence_quality_score(evidence: rank_fix_commits.HunkEvidence) -> int:
    before_semantic = snippet_semantic_lines(evidence.before)
    after_semantic = snippet_semantic_lines(evidence.after)
    changed_semantic = semantic_lines(evidence.changed_lines)
    score = evidence.score * 2 + min(4, len(changed_semantic))
    if before_semantic and after_semantic:
        score += 4
    if len(changed_semantic) >= 2:
        score += 2
    if evidence.new_start <= 3 and not before_semantic:
        score -= 6
    if not changed_semantic:
        score -= 5
    if before_semantic or after_semantic:
        boilerplate_ratio = (len(evidence.changed_lines) - len(changed_semantic)) / max(len(evidence.changed_lines), 1)
        if boilerplate_ratio >= 0.75:
            score -= 4
    return score


def select_phase3_evidences(repo: Path, sha: str, limit: int = 3) -> list[rank_fix_commits.HunkEvidence]:
    candidates = rank_fix_commits.collect_ranked_evidence(repo, sha, limit=0)
    if not candidates:
        return []

    scored = sorted(
        candidates,
        key=lambda evidence: (
            evidence_quality_score(evidence),
            evidence.score,
            len(snippet_semantic_lines(evidence.after)) + len(snippet_semantic_lines(evidence.before)),
            evidence.file,
        ),
        reverse=True,
    )
    meaningful = [evidence for evidence in scored if evidence_quality_score(evidence) > 0]
    chosen = meaningful or scored
    if limit > 0:
        return chosen[:limit]
    return chosen


def commit_looks_feature_like(commit: rank_fix_commits.RankedCommit) -> bool:
    lowered_subject = commit.subject.lower()
    if any(fragment in lowered_subject for fragment in ("add ", "introduce", "new ", "backend", "support")):
        return True
    return any(any(fragment in reason for fragment in FEATURE_REASON_FRAGMENTS) for reason in commit.reasons)


def has_strong_security_signal(
    commit: rank_fix_commits.RankedCommit,
    grounded_text: str,
    evidences: list[rank_fix_commits.HunkEvidence],
) -> bool:
    if is_panic_on_untrusted_input(grounded_text):
        return True
    if any(reason in STRONG_SECURITY_REASONS for reason in commit.reasons):
        return True
    for evidence in evidences:
        if evidence.score >= 7 and any(reason in STRONG_SECURITY_REASONS for reason in evidence.reasons):
            return True
    return False


def short_code(text: str, limit: int = 88) -> str:
    collapsed = clean_text(text).replace("`", "'")
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3].rstrip() + "..."


def observed_change_parts(evidence: rank_fix_commits.HunkEvidence) -> tuple[list[str], list[str]]:
    before_lines = snippet_semantic_lines(evidence.before)
    after_lines = snippet_semantic_lines(evidence.after)
    removed = [line for line in before_lines if line not in after_lines]
    added = [line for line in after_lines if line not in before_lines]
    return removed[:2], added[:2]


def summarize_observed_change(evidence: rank_fix_commits.HunkEvidence) -> str:
    removed, added = observed_change_parts(evidence)
    if removed and added:
        return f"In `{evidence.file}`, the patch replaces `{short_code(removed[0])}` with `{short_code(added[0])}`."
    if added:
        return f"In `{evidence.file}`, the patch adds `{short_code(added[0])}`."
    if removed:
        return f"In `{evidence.file}`, the patch removes `{short_code(removed[0])}`."
    return f"In `{evidence.file}`, the patch changes a sensitive implementation path."


def summarize_observed_patch(evidences: list[rank_fix_commits.HunkEvidence]) -> str:
    facts = [summarize_observed_change(evidence) for evidence in evidences[:2]]
    return " ".join(facts)


def build_observed_patch_facts(evidences: list[rank_fix_commits.HunkEvidence]) -> str:
    if not evidences:
        return "The generator could not extract a grounded implementation hunk, so no patch facts were reconstructed automatically."
    lines = [f"{index}. {summarize_observed_change(evidence)}" for index, evidence in enumerate(evidences, start=1)]
    return "\n\n".join(lines)


def build_project_context_summary(project_context: ProjectContext, subsystem: str) -> str:
    parts: list[str] = []
    if project_context.primary_directories:
        directories = ", ".join(f"`{directory}`" for directory in project_context.primary_directories[:3])
        parts.append(f"The changed code sits primarily in {directories}, which anchors the finding in the `{subsystem}` area of the project.")
    if project_context.related_contexts:
        related_files = ", ".join(f"`{snippet.file}`" for snippet in project_context.related_contexts[:2])
        parts.append(f"Historical context from {related_files} was reviewed at the same commit to understand the surrounding types, RPC boundaries, and data flow.")
    if project_context.identifiers:
        identifier_text = format_identifier_list(project_context.identifiers, limit=4)
        parts.append(f"The strongest project-level identifiers around this patch are {identifier_text}.")
    if project_context.related_test_files:
        tests = ", ".join(f"`{path}`" for path in project_context.related_test_files[:2])
        parts.append(f"Nearby tests or test-like files include {tests}.")
    return " ".join(parts) if parts else "No additional historical project context could be reconstructed automatically."


def verify_bug_class(
    commit: rank_fix_commits.RankedCommit,
    subsystem: str,
    bug_class: str,
    grounded_text: str,
    evidences: list[rank_fix_commits.HunkEvidence],
    project_context: ProjectContext,
) -> tuple[str, list[str]]:
    notes: list[str] = []
    combined = f"{grounded_text} {project_context_text(project_context)}"
    if bug_class == "accounting-or-state-drift":
        accounting_score = sum(term in combined for term in dict(BUG_CLASS_RULES)["accounting-or-state-drift"])
        lifecycle_score = sum(term in combined for term in ACCOUNTING_LIFECYCLE_TERMS)
        representation_score = sum(term in combined for term in dict(BUG_CLASS_RULES)["serialization-or-state-representation"])
        if representation_score > accounting_score and lifecycle_score == 0:
            notes.append("Downgraded accounting-or-state-drift because surrounding project context points more strongly to a representation boundary than to lifecycle accounting.")
            return "serialization-or-state-representation", notes
    if bug_class == "replay-or-signature-validation" and subsystem not in {"cryptography", "transaction-processing"}:
        if not has_strong_security_signal(commit, combined, evidences):
            notes.append("Downgraded replay/signature classification because the wider project context does not show a strong cryptographic control path.")
            return "hardening-or-correctness-fix", notes
    if bug_class == "serialization-or-state-representation" and has_strong_security_signal(commit, combined, evidences):
        notes.append("Retained conservative classification even though the patch touches a sensitive path, because the surrounding code still reads primarily like a representation boundary.")
    return bug_class, notes


def describe_hunk_role(evidence: rank_fix_commits.HunkEvidence, bug_class: str) -> str:
    reasons = set(evidence.reasons)
    lowered = " ".join(evidence.changed_lines).lower()
    if bug_class == "serialization-or-state-representation":
        return "changes how canonical state is encoded, returned, or reconstructed"
    if bug_class == "accounting-or-state-drift":
        return "updates aggregate accounting or lifecycle state"
    if "diff changes access control or privilege checks" in reasons:
        return "changes an authorization or privilege gate"
    if "diff changes cryptographic or replay-sensitive logic" in reasons:
        return "changes signature or replay validation logic"
    if "diff changes resource-control logic" in reasons:
        return "changes bounds, limits, or capacity handling"
    if "diff changes consensus or validator logic" in reasons:
        return "changes a consensus- or validator-sensitive branch"
    if "diff changes state or storage handling" in reasons:
        return "changes persisted or aggregate state handling"
    if "diff changes runtime guards or failure handling" in reasons:
        return "changes the branch that decides whether execution stops or continues"
    if any(term in lowered for term in ("opening_amount", "opening_size", "balance", "collateral", "funding", "reserve")):
        return "changes aggregate state or economic accounting"
    return "changes a sensitive control or state-update path"


def build_overview(
    project: str,
    subsystem: str,
    bug_class: str,
    subject: str,
    body: str,
    grounded_text: str,
    evidences: list[rank_fix_commits.HunkEvidence],
    identifiers: list[str],
    commit: rank_fix_commits.RankedCommit,
    project_context: ProjectContext,
) -> str:
    issue = summarize_subject(subject)
    file_names = [f"`{evidence.file}`" for evidence in evidences[:2]]
    file_context = ""
    if len(file_names) == 1:
        file_context = f" The strongest evidence comes from {file_names[0]}."
    elif len(file_names) >= 2:
        file_context = f" The strongest evidence spans {file_names[0]} and {file_names[1]}."
    identifier_text = format_identifier_list(identifiers)
    identifier_sentence = f" The affected state likely includes {identifier_text}." if identifier_text else ""
    body_hint = f" Commit context: {clean_text(body)}." if clean_text(body) else ""
    observed_summary = summarize_observed_patch(evidences)
    context_hint = ""
    if project_context.related_contexts:
        context_files = ", ".join(f"`{snippet.file}`" for snippet in project_context.related_contexts[:2])
        context_hint = f" Additional project context from {context_files} was used to anchor the surrounding module behavior."

    if is_panic_on_untrusted_input(grounded_text):
        return (
            f"{issue} appears to harden the {subsystem} path of {project} against malformed transaction input."
            f"{file_context}{identifier_sentence} The selected hunks suggest decoded transaction or signature values could previously flow into a panic-prone conversion path without a checked validation step."
            f" In a node context, that shape is consistent with crash-triggering input rather than a simple local parse error.{context_hint}{body_hint}"
        )
    if bug_class == "serialization-or-state-representation":
        return (
            f"{issue} changes how {subsystem} state is represented across a client or RPC boundary in {project}."
            f"{file_context} The visible diff shows a move away from piecemeal field transfer toward a canonical serialized object or shared representation."
            f"{identifier_sentence} That is strong evidence of a state-representation consistency fix, but the patch alone does not prove a deeper cryptographic or economic flaw.{context_hint}{body_hint}"
        )
    if commit_looks_feature_like(commit) and not has_strong_security_signal(commit, grounded_text, evidences):
        return (
            f"{issue} changes a sensitive {subsystem} path of {project}."
            f"{file_context} The safest reading from the visible diff is: {observed_summary}"
            f" The patch may be hardening or correcting behavior, but the exact vulnerability story is not explicit from the patch alone.{context_hint}{body_hint}"
        )
    if bug_class == "accounting-or-state-drift":
        return (
            f"{issue} appears to address an accounting mismatch in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The patch shape suggests one control path can close, clear, or mutate state while a related aggregate is only partially reconciled."
            f" That can leave behind phantom state that no longer matches the live objects on chain or in storage.{context_hint}{body_hint}"
        )
    if bug_class == "access-control":
        return (
            f"{issue} appears to address an authorization weakness in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The selected hunks suggest a privileged action or state-changing path could previously execute without a strong enough gate.{context_hint}{body_hint}"
        )
    if bug_class == "replay-or-signature-validation":
        return (
            f"{issue} appears to harden replay- or signature-sensitive handling in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The patch shape suggests validation now happens earlier or more strictly before a sensitive action is accepted.{context_hint}{body_hint}"
        )
    if bug_class == "resource-exhaustion":
        return (
            f"{issue} appears to tighten bounds or work admission in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The selected hunks suggest malformed, excessive, or delayed-to-validate inputs could previously consume more resources than intended.{context_hint}{body_hint}"
        )
    if bug_class == "consensus-safety":
        return (
            f"{issue} appears to correct a consensus-sensitive edge case in {project}."
            f"{file_context}{identifier_sentence} The selected hunks suggest an invariant could previously be broken across a critical state transition or validation path.{context_hint}{body_hint}"
        )
    if bug_class == "liveness-failure":
        return (
            f"{issue} appears to improve failure handling in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The patch shape suggests certain edge conditions could previously stall progress, panic, or leave the system in a stuck state.{context_hint}{body_hint}"
        )
    if bug_class == "state-corruption":
        return (
            f"{issue} appears to strengthen state integrity in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The selected hunks suggest persisted or derived state could previously become inconsistent with the live runtime state.{context_hint}{body_hint}"
        )
    if bug_class == "input-validation":
        return (
            f"{issue} appears to move or tighten validation in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The selected hunks suggest deeper logic was previously reachable before the relevant input invariants were enforced.{context_hint}{body_hint}"
        )
    return (
        f"{issue} looks like a focused hardening change in the {subsystem} path of {project}."
        f"{file_context}{identifier_sentence} The visible hunks are security-relevant, but the exact exploit path is not explicit enough to name more precisely.{context_hint}{body_hint}"
    )


def build_root_cause(
    subsystem: str,
    bug_class: str,
    grounded_text: str,
    evidences: list[rank_fix_commits.HunkEvidence],
    identifiers: list[str],
    commit: rank_fix_commits.RankedCommit,
    project_context: ProjectContext,
) -> str:
    identifier_text = format_identifier_list(identifiers)
    boundary = ""
    if len(evidences) >= 2:
        boundary = f"The issue appears to sit at the boundary between `{evidences[0].file}` and `{evidences[1].file}`. "
    elif evidences:
        boundary = f"The issue appears to sit inside `{evidences[0].file}`. "

    if is_panic_on_untrusted_input(grounded_text):
        return (
            boundary
            + "The likely root cause was that untrusted decoded values reached a helper that panics on invalid or overflowing input, instead of returning an ordinary error."
            + (f" The risky values appear to include {identifier_text}." if identifier_text else "")
            + " That means malformed transaction data can escape decode-time validation and turn a recoverable input error into process-level instability."
        )
    if bug_class == "serialization-or-state-representation":
        return (
            boundary
            + "The likely root cause was divergent representations of the same state object across the RPC or client boundary."
            + " One side appears to have constructed or returned separately derived fields, while the patched path moves toward shipping and decoding the canonical serialized object instead."
            + " That reduces the chance that clients observe a stale, partial, or differently assembled view of the same on-chain state."
            + (" Related files at this commit reinforce that the affected object is shared across the same subsystem boundary." if project_context.related_contexts else "")
            + " The diff alone does not show a stronger exploit path than representation inconsistency."
        )
    if commit_looks_feature_like(commit) and not has_strong_security_signal(commit, grounded_text, evidences):
        return (
            boundary
            + "The visible diff is not specific enough to prove a detailed exploit chain."
            + " What it does show is a change to a sensitive state or RPC path where the implementation now appears to use a more canonical or centralized representation."
            + " Stronger claims should be confirmed against an issue, advisory, or full manual review."
        )
    if bug_class == "accounting-or-state-drift":
        return (
            boundary
            + "One path appears to decide whether an object is closed, cleared, or otherwise no longer live, while another path still updates aggregate state from partial or stale values."
            + (f" The likely mismatched state includes {identifier_text}." if identifier_text else "")
            + " If the cleanup path removes the original object afterwards, the aggregate state can remain permanently inflated or stale."
        )
    if bug_class == "access-control":
        return boundary + "The likely root cause was that authorization was either missing, delayed, or not centralized before a sensitive state transition."
    if bug_class == "replay-or-signature-validation":
        return boundary + "The likely root cause was incomplete validation of signed or replay-sensitive inputs before state-changing behavior occurred."
    if bug_class == "resource-exhaustion":
        return boundary + "The likely root cause was insufficient bounds or early rejection, allowing work, queue depth, or per-request cost to grow too far before being checked."
    if bug_class == "consensus-safety":
        return boundary + "The likely root cause was an under-enforced invariant in a consensus-critical path, especially across an edge-case state transition."
    if bug_class == "liveness-failure":
        return boundary + "The likely root cause was brittle failure handling, where retries, panics, lock behavior, or timeout handling could interrupt forward progress."
    if bug_class == "state-corruption":
        return boundary + "The likely root cause was inconsistent state mutation across related storage or accounting paths."
    if bug_class == "input-validation":
        return boundary + "The likely root cause was that validation happened too late, after deeper logic had already started operating on untrusted input."
    return boundary + "The likely root cause was an under-protected control path whose invariants were not enforced strongly enough."


def build_walkthrough(
    evidences: list[rank_fix_commits.HunkEvidence],
    bug_class: str,
) -> str:
    if not evidences:
        return "A grounded multi-step walkthrough could not be reconstructed automatically because no implementation hunk was available."

    lines: list[str] = []
    for index, evidence in enumerate(evidences, start=1):
        role = describe_hunk_role(evidence, bug_class)
        identifiers = identifiers_for_evidence(evidence)
        identifier_text = format_identifier_list(identifiers)
        detail_parts = [f"In `{evidence.file}:{evidence.new_start}`, the selected hunk {role}."]
        if identifier_text:
            detail_parts.append(f"Notable identifiers in this step include {identifier_text}.")
        if evidence.reasons:
            detail_parts.append(f"The hunk matched {', '.join(evidence.reasons)}.")
        if index == len(evidences) and len(evidences) > 1:
            detail_parts.append("Taken together, the hunks suggest the fix spans more than one control path rather than a single isolated check.")
        lines.append(f"{index}. {' '.join(detail_parts)}")
    return "\n\n".join(lines)


def build_impact(bug_class: str, subsystem: str, grounded_text: str, identifiers: list[str]) -> str:
    identifier_text = format_identifier_list(identifiers)
    if is_panic_on_untrusted_input(grounded_text):
        return "\n\n".join(
            [
                "1. Malformed transaction input can trigger a panic during node-side decoding or transaction construction, turning a validation bug into a denial-of-service condition.",
                f"2. Because the crash happens in a shared {subsystem} path, the impact is broader than one failed transaction: block processing or mempool handling can be interrupted before the node can reject the input cleanly.",
                f"3. Similar paths that decode untrusted values into helpers like {identifier_text or '`Must*` conversion helpers'} should be reviewed for panic-on-error behavior and converted to checked failures.",
            ]
        )
    if bug_class == "serialization-or-state-representation":
        return "\n\n".join(
            [
                "1. Clients, CLIs, or downstream services can observe a stale or partial view of state when the server and client reconstruct the same object from different field sets.",
                "2. A canonical serialized object reduces the risk that one side silently omits derived balances, counters, or metadata that another side assumes are authoritative.",
                "3. The diff alone does not prove an exploitable security issue, but it does highlight a consistency boundary where incorrect data flow can spread across tooling and operator workflows.",
            ]
        )
    if bug_class == "accounting-or-state-drift":
        return "\n\n".join(
            [
                "1. Downstream accounting can drift from reality. Once aggregate state no longer matches live objects, later calculations operate on phantom state.",
                f"2. Any logic that reuses the affected {subsystem} counters or balances can inherit the error. This is especially relevant when fields like {identifier_text or '`aggregate counters`'} feed valuation, fee, funding, or capacity checks.",
                "3. The bug can become sticky or irreversible if later cleanup paths only destroy the original object and never revisit the stale aggregate state.",
                "4. The risk is amplified during stress because forced-close, liquidation, or partial-decrease paths are usually hottest exactly when state needs to stay accurate.",
            ]
        )
    if bug_class == "access-control":
        return "\n\n".join(
            [
                "1. A caller may be able to trigger sensitive behavior without the intended privilege checks.",
                "2. Once the state-changing path is reachable, later checks or cleanup logic may not be enough to undo the side effects safely.",
                f"3. Similar {subsystem} paths should be reviewed for hidden assumptions about trusted callers or role propagation.",
            ]
        )
    if bug_class == "replay-or-signature-validation":
        return "\n\n".join(
            [
                "1. Invalid or replayed requests can look legitimate long enough to pass into deeper execution.",
                "2. Any state transition reached before the validation gate is complete can be duplicated or forged.",
                f"3. Similar {subsystem} paths should be reviewed for nonce handling, signer binding, and cross-function replay windows.",
            ]
        )
    if bug_class == "resource-exhaustion":
        return "\n\n".join(
            [
                "1. Malformed or excessive activity can consume more memory, CPU, or queue capacity than intended.",
                "2. Delayed validation means the system pays the cost before it decides the work should have been rejected.",
                f"3. Similar {subsystem} paths should be reviewed for bounds, quotas, and admission control before allocation or buffering occurs.",
            ]
        )
    if bug_class == "consensus-safety":
        return "\n\n".join(
            [
                "1. An under-enforced invariant in a consensus path can lead to divergent state, unsafe transitions, or protocol instability.",
                "2. Bugs in these paths often remain latent until stress, timing edges, or rare orderings trigger them.",
                f"3. Similar {subsystem} logic should be reviewed for edge-case ordering, recovery behavior, and invariant reuse across modules.",
            ]
        )
    if bug_class == "liveness-failure":
        return "\n\n".join(
            [
                "1. Edge cases can cause retries, panics, lock contention, or timeout handling to interrupt progress.",
                "2. The system may remain correct but still become unattractive or unstable operationally because it stops making forward progress.",
                f"3. Similar {subsystem} paths should be reviewed for panic-to-error conversions, retry caps, and failure cleanup.",
            ]
        )
    return "\n\n".join(
        [
            f"1. The selected hunks affect a sensitive {subsystem} path, so even a small invariant mistake can have wider operational consequences.",
            "2. The exact exploitability is not fully explicit from the patch alone, but the control path is important enough to justify follow-up review.",
        ]
    )


def build_affected_code_paths(evidences: list[rank_fix_commits.HunkEvidence], bug_class: str) -> str:
    if not evidences:
        return "| File | Lines | Role |\n| --- | --- | --- |\n| (no grounded evidence) | - | automatic extraction failed |"
    lines = [
        "| File | Lines | Role |",
        "| --- | --- | --- |",
    ]
    for evidence in evidences:
        role = describe_hunk_role(evidence, bug_class)
        lines.append(f"| {evidence.file} | {evidence.new_start} | {role} |")
    return "\n".join(lines)


def build_fix_mechanism(
    bug_class: str,
    subsystem: str,
    grounded_text: str,
    identifiers: list[str],
    project_context: ProjectContext,
) -> str:
    identifier_text = format_identifier_list(identifiers)
    if is_panic_on_untrusted_input(grounded_text):
        return (
            "The patch appears to insert a checked validation or checked conversion step before malformed decoded values reach panic-prone helpers. "
            + "Instead of allowing untrusted signature or transaction fields to flow into `Must*` conversions, the patched path appears to convert that failure into an ordinary error return. "
            + ("The changed code suggests helpers around " + f"{identifier_text} " if identifier_text else "")
            + "now fail closed rather than terminating the process."
        )
    if bug_class == "accounting-or-state-drift":
        return (
            "The patch appears to reconcile aggregate state from the final lifecycle outcome of the position or object, not just from the requested delta. "
            + ("Fields such as " + f"{identifier_text} " if identifier_text else "The affected counters ")
            + "appear to be updated after the close-or-clear decision is known, so the aggregate view stays aligned with the surviving live state."
        )
    if bug_class == "serialization-or-state-representation":
        return (
            "The patch appears to stop reconstructing client-visible state from multiple separately transferred fields and instead move both sides toward the same canonical serialized object."
            + (" Fields such as " + f"{identifier_text} " if identifier_text else " The affected state ")
            + "now appear to flow through one representation, which reduces the chance of server/client drift."
            + (" Related project context suggests the same object is reused in nearby subsystem code rather than being local to one helper." if project_context.related_contexts else "")
        )
    if bug_class == "access-control":
        return "The patch appears to move the authorization gate ahead of the sensitive state transition and to make equivalent paths share the same permission check."
    if bug_class == "replay-or-signature-validation":
        return "The patch appears to validate signer identity, nonce use, or replay-sensitive fields earlier, before the transaction reaches the state-changing path."
    if bug_class == "resource-exhaustion":
        return "The patch appears to move bounds or admission checks earlier, so work is rejected before allocation, enqueueing, or other expensive processing occurs."
    if bug_class == "consensus-safety":
        return "The patch appears to reassert the broken invariant at the state-transition boundary, so the unsafe edge case can no longer progress into the consensus-critical path."
    if bug_class == "liveness-failure":
        return "The patch appears to replace panic-prone or unbounded failure handling with explicit error returns or bounded recovery behavior."
    return f"The patch appears to tighten the critical {subsystem} path so the relevant invariant is enforced before downstream work continues."


def build_fix_pattern(
    bug_class: str,
    subsystem: str,
    grounded_text: str,
) -> str:
    if is_panic_on_untrusted_input(grounded_text):
        return "The fix pattern is to insert checked validation or checked integer conversion before constructing the downstream transaction object, so malformed decoded values fail as ordinary errors instead of panicking."
    if bug_class == "serialization-or-state-representation":
        return "The fix pattern is to send and decode the canonical serialized state object instead of piecing together parallel derived fields on each side of the API boundary."
    if bug_class == "accounting-or-state-drift":
        return f"The fix pattern is to reconcile aggregate {subsystem} state from the final object lifecycle outcome, not from an intermediate or partial delta."
    if bug_class == "access-control":
        return "The fix pattern is to move permission checks ahead of the sensitive state transition and keep equivalent entry points on the same authorization path."
    if bug_class == "replay-or-signature-validation":
        return "The fix pattern is to validate signature- or replay-sensitive fields before the transaction reaches the state-changing path."
    if bug_class == "resource-exhaustion":
        return "The fix pattern is to bound or reject work before buffering, allocation, or expensive processing happens."
    if bug_class == "consensus-safety":
        return "The fix pattern is to reassert the broken invariant at the boundary where the critical state transition occurs."
    if bug_class == "liveness-failure":
        return "The fix pattern is to replace panic-prone or unbounded failure handling with explicit error returns and bounded recovery."
    return f"The fix pattern is to tighten the sensitive {subsystem} control path so the key invariant is enforced before downstream work continues."


def build_code_snippets(evidences: list[rank_fix_commits.HunkEvidence], bug_class: str) -> str:
    if not evidences:
        return "A grounded implementation snippet could not be extracted automatically."

    lines: list[str] = []
    for index, evidence in enumerate(evidences, start=1):
        role = describe_hunk_role(evidence, bug_class)
        language = guess_code_language(evidence.file)
        lines.extend(
            [
                f"## Snippet {index}",
                "",
                f"Context: `{evidence.file}:{evidence.new_start}` ({role})",
                "",
                "Before",
                f"```{language}",
                evidence.before or "(no before snippet captured)",
                "```",
                "After",
                f"```{language}",
                evidence.after or "(no after snippet captured)",
                "```",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def infer_evidence_notes(
    commit: rank_fix_commits.RankedCommit,
    evidences: list[rank_fix_commits.HunkEvidence],
    project_context: ProjectContext,
    verification_notes: list[str],
) -> str:
    if not evidences:
        return "A grounded implementation hunk could not be extracted automatically, so this finding should be treated as low-confidence."

    files = ", ".join(f"`{evidence.file}`" for evidence in evidences)
    reason_pool = []
    for evidence in evidences:
        reason_pool.extend(evidence.reasons)
    reason_text = ", ".join(rank_fix_commits.unique_reasons(reason_pool)) if reason_pool else "no strong keyword signals"
    note = f"This finding is grounded in {files}. The selected hunks were prioritized because they matched: {reason_text}."
    if commit.test_files:
        note += " Nearby test changes increase confidence that the patch targeted a real behavior change."
    if max((evidence.score for evidence in evidences), default=0) < 3:
        note += " The evidence is still weak and should be checked against the full diff."
    if commit_looks_feature_like(commit) and not has_strong_security_signal(commit, build_grounded_text(commit, evidences), evidences):
        note += " The commit subject and patch shape still look partly feature- or API-oriented, so subsystem and bug-class labels should be treated as tentative unless they are confirmed externally."
    if project_context.related_contexts:
        related_files = ", ".join(f"`{snippet.file}`" for snippet in project_context.related_contexts[:2])
        note += f" Phase 3 also reviewed nearby historical project context from {related_files}."
    if verification_notes:
        note += " Verification notes: " + " ".join(verification_notes)
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


def init_agent_client(
    agent_mode: str,
    agent_config: phase3_agents.AgentRunConfig | None,
    llm_client: phase3_agents.LLMClient | None,
) -> phase3_agents.LLMClient | None:
    if agent_mode == "heuristic":
        return None
    if llm_client is not None:
        return llm_client
    config = agent_config or phase3_agents.AgentRunConfig()
    if config.provider != "openai":
        raise ValueError(f"unsupported agent provider: {config.provider}")
    return phase3_agents.OpenAIResponsesClient(model=config.model)


def render_finding(
    repo: Path,
    commit: rank_fix_commits.RankedCommit,
    agent_mode: str = "heuristic",
    llm_client: phase3_agents.LLMClient | None = None,
    agent_config: phase3_agents.AgentRunConfig | None = None,
) -> RenderedFinding:
    evidences = select_phase3_evidences(repo, commit.sha, limit=3)
    project_context = build_project_context(repo, commit, evidences)
    grounded_text = clean_text(f"{build_grounded_text(commit, evidences)} {project_context_text(project_context)}").lower()
    project = slugify(repo.name)
    domain = infer_domain(commit.files)
    subsystem = infer_subsystem(commit, grounded_text, evidences, project_context)
    bug_class = infer_bug_class(commit, grounded_text, evidences, project_context)
    bug_class, verification_notes = verify_bug_class(commit, subsystem, bug_class, grounded_text, evidences, project_context)
    confidence = infer_confidence(commit, evidences)
    source_quality = infer_source_quality(commit, evidences)
    body = rank_fix_commits.load_body(repo, commit.sha)
    identifiers = list(dict.fromkeys(collect_identifier_hints(evidences) + project_context.identifiers))[:8]
    observed_patch_facts = build_observed_patch_facts(evidences)
    evidence_notes = infer_evidence_notes(commit, evidences, project_context, verification_notes)
    overview: str | None = None
    root_cause: str | None = None
    walkthrough: str | None = None
    impact: str | None = None
    affected_code_paths: str | None = None
    fix_pattern: str | None = None
    fix_mechanism: str | None = None
    agent_failure_note = ""
    agent_summary_supplied = False
    agent_root_cause_supplied = False
    agent_walkthrough_supplied = False
    agent_fix_pattern_supplied = False
    agent_fix_mechanism_supplied = False
    agent_impact_supplied = False
    agent_paths_supplied = False

    if agent_mode != "heuristic":
        bundle = build_agent_bundle(
            repo,
            commit,
            evidences,
            project_context,
            subsystem,
            bug_class,
            confidence,
            source_quality,
            fix_pattern,
            impact,
            build_overview(project, subsystem, bug_class, commit.subject, body, grounded_text, evidences, identifiers, commit, project_context),
            build_root_cause(subsystem, bug_class, grounded_text, evidences, identifiers, commit, project_context),
        )
        try:
            client = init_agent_client(agent_mode, agent_config, llm_client)
            assert client is not None
            agent_result = phase3_agents.run_mapper_drafter_skeptic(bundle, client)
            subsystem = normalize_agent_subsystem(agent_result.subsystem, subsystem)
            bug_class = normalize_agent_bug_class(agent_result.bug_class, bug_class)
            confidence = normalize_agent_confidence(agent_result.confidence, confidence)
            if agent_result.summary:
                overview = agent_result.summary
                agent_summary_supplied = True
            if agent_result.root_cause:
                root_cause = agent_result.root_cause
                agent_root_cause_supplied = True
            if agent_result.walkthrough:
                walkthrough = format_numbered_section(agent_result.walkthrough, "")
                agent_walkthrough_supplied = True
            if agent_result.fix_pattern:
                fix_pattern = agent_result.fix_pattern
                agent_fix_pattern_supplied = True
            if agent_result.how_it_was_fixed:
                fix_mechanism = agent_result.how_it_was_fixed
                agent_fix_mechanism_supplied = True
            if agent_result.why_it_matters:
                impact = format_numbered_section(agent_result.why_it_matters, "")
                agent_impact_supplied = True
            if agent_result.affected_code_paths:
                affected_code_paths = build_affected_code_paths_from_agent(agent_result.affected_code_paths, "")
                agent_paths_supplied = True
            evidence_notes = agent_result.evidence_notes or evidence_notes
            if agent_result.verification_notes:
                evidence_notes = f"{evidence_notes} Verification notes: {' '.join(agent_result.verification_notes)}"
        except Exception as exc:
            strict = agent_config.strict if agent_config else False
            if strict:
                raise
            agent_failure_note = f" Agent-backed phase 3 failed and the report fell back to heuristic rendering: {clean_text(str(exc))}."

    project_context_summary = build_project_context_summary(project_context, subsystem)
    fallback_overview = build_overview(project, subsystem, bug_class, commit.subject, body, grounded_text, evidences, identifiers, commit, project_context)
    fallback_root_cause = build_root_cause(subsystem, bug_class, grounded_text, evidences, identifiers, commit, project_context)
    fallback_walkthrough = build_walkthrough(evidences, bug_class)
    fallback_impact = build_impact(bug_class, subsystem, grounded_text, identifiers)
    fallback_affected_code_paths = build_affected_code_paths(evidences, bug_class)
    fallback_fix_pattern = build_fix_pattern(bug_class, subsystem, grounded_text)
    fallback_fix_mechanism = build_fix_mechanism(bug_class, subsystem, grounded_text, identifiers, project_context)
    code_snippets = build_code_snippets(evidences, bug_class)

    if not agent_summary_supplied:
        overview = fallback_overview
    if not agent_root_cause_supplied:
        root_cause = fallback_root_cause
    if not agent_walkthrough_supplied:
        walkthrough = fallback_walkthrough
    if not agent_fix_pattern_supplied:
        fix_pattern = fallback_fix_pattern
    if not agent_fix_mechanism_supplied:
        fix_mechanism = fallback_fix_mechanism
    if not agent_impact_supplied:
        impact = fallback_impact
    if not agent_paths_supplied:
        affected_code_paths = fallback_affected_code_paths

    impacts = infer_impact_types(bug_class)
    tags = infer_tags(domain, subsystem, bug_class, impacts, evidences, commit.files, project_context)
    if agent_mode != "heuristic" and not agent_failure_note:
        evidence_notes = f"{evidence_notes} Agent pipeline used separate mapper, drafter, and skeptic passes."
    if agent_failure_note:
        evidence_notes = f"{evidence_notes}{agent_failure_note}"

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
    lines.extend(
        [
            f"confidence: {confidence}",
            f"source_quality: {source_quality}",
            "tags:",
        ]
    )
    lines.extend(f"  - {tag}" for tag in tags)
    lines.extend(
        [
            f"date: {commit.date}",
            "source_refs:",
            f"  - git:{commit.sha}",
        ]
    )
    for evidence in evidences:
        lines.append(f'  - "{evidence.file}:{evidence.new_start}"')
    lines.extend(
        [
            "---",
            "",
            "# Summary",
            "",
            overview,
            "",
            "## Observed Patch Facts",
            "",
            observed_patch_facts,
            "",
            "## Project Context",
            "",
            project_context_summary,
            "",
            "# Root Cause",
            "",
            root_cause,
            "",
            "## Walkthrough",
            "",
            walkthrough,
            "",
            "## Affected Code Paths",
            "",
            affected_code_paths,
            "",
            "## Code Snippets",
            "",
            code_snippets,
            "",
            "# Fix Pattern",
            "",
            fix_pattern,
            "",
            "## How It Was Fixed",
            "",
            fix_mechanism,
            "",
            "# Why It Matters",
            "",
            impact,
            "",
            "# Evidence Notes",
            "",
            evidence_notes,
            "",
        ]
    )
    return RenderedFinding(
        markdown="\n".join(lines),
        subsystem=subsystem,
        bug_class=bug_class,
        confidence=confidence,
        source_quality=source_quality,
    )


def build_markdown(
    repo: Path,
    commit: rank_fix_commits.RankedCommit,
    agent_mode: str = "heuristic",
    llm_client: phase3_agents.LLMClient | None = None,
    agent_config: phase3_agents.AgentRunConfig | None = None,
) -> str:
    return render_finding(
        repo,
        commit,
        agent_mode=agent_mode,
        llm_client=llm_client,
        agent_config=agent_config,
    ).markdown


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
    agent_config = phase3_agents.AgentRunConfig(
        provider=args.agent_provider,
        model=args.agent_model,
        strict=args.agent_strict,
    )
    llm_client = init_agent_client(args.agent_mode, agent_config, None)

    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for commit in ranked:
        evidences = select_phase3_evidences(repo, commit.sha, limit=3)
        if not evidences and not commit.implementation_files:
            continue
        rendered = render_finding(
            repo,
            commit,
            agent_mode=args.agent_mode,
            llm_client=llm_client,
            agent_config=agent_config,
        )
        subsystem = rendered.subsystem
        filename = f"{commit.date}-{slugify(repo.name)}-{slugify(subsystem)}-{commit.short_sha}.md"
        target = out_dir / filename
        if target.exists() and not args.overwrite:
            continue
        target.write_text(rendered.markdown, encoding="utf-8")
        written += 1
        print(target)

    print(f"Wrote {written} finding file(s) to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
