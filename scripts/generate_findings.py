#!/usr/bin/env python3
"""Generate richer Markdown findings from likely fix commits."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

import rank_fix_commits


SUBSYSTEM_RULES = [
    ("p2p-networking", ("p2p", "network", "peer", "handshake", "mempool", "rpc")),
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
    "while",
    "else",
    "then",
    "func",
    "nil",
    "err",
    "line",
}


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


def best_keyword_match(text: str, rules: list[tuple[str, tuple[str, ...]]], default: str) -> str:
    haystack = text.lower()
    best_label = default
    best_score = 0
    for label, terms in rules:
        score = sum(term in haystack for term in terms)
        if score > best_score:
            best_label = label
            best_score = score
    return best_label


def build_grounded_text(commit: rank_fix_commits.RankedCommit, evidences: list[rank_fix_commits.HunkEvidence]) -> str:
    if evidences:
        return clean_text(" ".join([evidence.file + " " + evidence.signal_text for evidence in evidences])).lower()
    return clean_text(" ".join(commit.implementation_files or commit.source_files)).lower()


def infer_domain(files: list[str]) -> str:
    lowered = " ".join(path.lower() for path in files)
    if any(term in lowered for term in ("validator", "slashing", "signer", "keystore")):
        return "validator-ops"
    if any(term in lowered for term in ("storage", "state", "snapshot", "db", "database", "wal", "crypto", "signature", "hash", "evm")):
        return "infrastructure"
    return "blockchain-core"


def infer_subsystem(commit: rank_fix_commits.RankedCommit, grounded_text: str, evidences: list[rank_fix_commits.HunkEvidence]) -> str:
    parts = [grounded_text, " ".join(commit.files)]
    parts.extend(evidence.file for evidence in evidences)
    return best_keyword_match(" ".join(parts), SUBSYSTEM_RULES, "core-logic")


def infer_bug_class(grounded_text: str) -> str:
    return best_keyword_match(grounded_text, BUG_CLASS_RULES, "hardening-or-correctness-fix")


def infer_impact_types(bug_class: str) -> list[str]:
    if bug_class == "resource-exhaustion":
        return ["remote-dos"]
    if bug_class == "access-control":
        return ["privilege-misuse"]
    if bug_class == "replay-or-signature-validation":
        return ["request-forgery-or-replay"]
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
) -> list[str]:
    tags = [domain, subsystem, bug_class, *impacts]
    lowered = " ".join(files).lower()
    for evidence in evidences:
        lowered = f"{lowered} {evidence.file.lower()} {evidence.signal_text}"
    for term in ("p2p", "queue", "validator", "consensus", "snapshot", "rpc", "multisig", "signature", "replay", "database", "funding", "collateral", "settlement"):
        if term in lowered:
            tags.append(term)
    return list(dict.fromkeys(slugify(tag) for tag in tags if tag))[:10]


def infer_confidence(commit: rank_fix_commits.RankedCommit, evidences: list[rank_fix_commits.HunkEvidence]) -> str:
    max_score = max((evidence.score for evidence in evidences), default=0)
    if max_score >= 7 and len(evidences) >= 2 and commit.test_files:
        return "high"
    if max_score >= 3:
        return "medium"
    if commit.band in {"high", "medium"}:
        return "medium"
    return "low"


def infer_source_quality(commit: rank_fix_commits.RankedCommit, evidences: list[rank_fix_commits.HunkEvidence]) -> str:
    max_score = max((evidence.score for evidence in evidences), default=0)
    if max_score >= 7 and len(evidences) >= 2:
        return "high"
    if max_score >= 1:
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
            counter[token] += 3
        for token in SIMPLE_IDENTIFIER_RE.findall(text):
            lowered = token.lower()
            if lowered in IDENTIFIER_STOPWORDS:
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
        counter[token] += 3
    for token in SIMPLE_IDENTIFIER_RE.findall(text):
        lowered = token.lower()
        if lowered in IDENTIFIER_STOPWORDS or token.isupper():
            continue
        counter[token] += 1
    return [token for token, _ in counter.most_common(3)]


def describe_hunk_role(evidence: rank_fix_commits.HunkEvidence, bug_class: str) -> str:
    reasons = set(evidence.reasons)
    lowered = " ".join(evidence.changed_lines).lower()
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

    if is_panic_on_untrusted_input(grounded_text):
        return (
            f"{issue} appears to harden the {subsystem} path of {project} against malformed transaction input."
            f"{file_context}{identifier_sentence} The selected hunks suggest decoded transaction or signature values could previously flow into a panic-prone conversion path without a checked validation step."
            f" In a node context, that shape is consistent with crash-triggering input rather than a simple local parse error.{body_hint}"
        )
    if bug_class == "accounting-or-state-drift":
        return (
            f"{issue} appears to address an accounting mismatch in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The patch shape suggests one control path can close, clear, or mutate state while a related aggregate is only partially reconciled."
            f" That can leave behind phantom state that no longer matches the live objects on chain or in storage.{body_hint}"
        )
    if bug_class == "access-control":
        return (
            f"{issue} appears to address an authorization weakness in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The selected hunks suggest a privileged action or state-changing path could previously execute without a strong enough gate.{body_hint}"
        )
    if bug_class == "replay-or-signature-validation":
        return (
            f"{issue} appears to harden replay- or signature-sensitive handling in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The patch shape suggests validation now happens earlier or more strictly before a sensitive action is accepted.{body_hint}"
        )
    if bug_class == "resource-exhaustion":
        return (
            f"{issue} appears to tighten bounds or work admission in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The selected hunks suggest malformed, excessive, or delayed-to-validate inputs could previously consume more resources than intended.{body_hint}"
        )
    if bug_class == "consensus-safety":
        return (
            f"{issue} appears to correct a consensus-sensitive edge case in {project}."
            f"{file_context}{identifier_sentence} The selected hunks suggest an invariant could previously be broken across a critical state transition or validation path.{body_hint}"
        )
    if bug_class == "liveness-failure":
        return (
            f"{issue} appears to improve failure handling in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The patch shape suggests certain edge conditions could previously stall progress, panic, or leave the system in a stuck state.{body_hint}"
        )
    if bug_class == "state-corruption":
        return (
            f"{issue} appears to strengthen state integrity in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The selected hunks suggest persisted or derived state could previously become inconsistent with the live runtime state.{body_hint}"
        )
    if bug_class == "input-validation":
        return (
            f"{issue} appears to move or tighten validation in the {subsystem} path of {project}."
            f"{file_context}{identifier_sentence} The selected hunks suggest deeper logic was previously reachable before the relevant input invariants were enforced.{body_hint}"
        )
    return (
        f"{issue} looks like a focused hardening change in the {subsystem} path of {project}."
        f"{file_context}{identifier_sentence} The visible hunks are security-relevant, but the exact exploit path is not explicit enough to name more precisely.{body_hint}"
    )


def build_root_cause(
    subsystem: str,
    bug_class: str,
    grounded_text: str,
    evidences: list[rank_fix_commits.HunkEvidence],
    identifiers: list[str],
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


def infer_evidence_notes(commit: rank_fix_commits.RankedCommit, evidences: list[rank_fix_commits.HunkEvidence]) -> str:
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
    evidences = rank_fix_commits.collect_ranked_evidence(repo, commit.sha, limit=3)
    grounded_text = build_grounded_text(commit, evidences)
    project = slugify(repo.name)
    domain = infer_domain(commit.files)
    subsystem = infer_subsystem(commit, grounded_text, evidences)
    bug_class = infer_bug_class(grounded_text)
    impacts = infer_impact_types(bug_class)
    confidence = infer_confidence(commit, evidences)
    source_quality = infer_source_quality(commit, evidences)
    tags = infer_tags(domain, subsystem, bug_class, impacts, evidences, commit.files)
    body = rank_fix_commits.load_body(repo, commit.sha)
    identifiers = collect_identifier_hints(evidences)
    overview = build_overview(project, subsystem, bug_class, commit.subject, body, grounded_text, evidences, identifiers)
    root_cause = build_root_cause(subsystem, bug_class, grounded_text, evidences, identifiers)
    walkthrough = build_walkthrough(evidences, bug_class)
    impact = build_impact(bug_class, subsystem, grounded_text, identifiers)
    affected_code_paths = build_affected_code_paths(evidences, bug_class)
    fix_pattern = build_fix_pattern(bug_class, subsystem, grounded_text)
    fix_mechanism = build_fix_mechanism(bug_class, subsystem, grounded_text, identifiers)
    code_snippets = build_code_snippets(evidences, bug_class)
    evidence_notes = infer_evidence_notes(commit, evidences)

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
        evidences = rank_fix_commits.collect_ranked_evidence(repo, commit.sha, limit=3)
        if not evidences and not commit.implementation_files:
            continue
        grounded_text = build_grounded_text(commit, evidences)
        subsystem = infer_subsystem(commit, grounded_text, evidences)
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
