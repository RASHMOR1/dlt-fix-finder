#!/usr/bin/env python3
"""Rank commits that look like security, reliability, or hardening fixes in DLT and infrastructure repos."""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path


MESSAGE_RULES = (
    (re.compile(r"\b(security|vulnerability|vuln|exploit|attack|cve)\b", re.IGNORECASE), 8, "message uses explicit security language"),
    (re.compile(r"\b(fix|patch|mitigat|hard(en|ing)|protect|guard|sanitize)\w*", re.IGNORECASE), 2, "message says the commit is a fix or hardening change"),
    (re.compile(r"\b(dos|denial.of.service|panic|crash|overflow|underflow|race|deadlock|corrupt|desync|fork|partition|stall|halt)\w*", re.IGNORECASE), 5, "message names a failure mode"),
    (re.compile(r"\b(auth|authoriz|permission|privilege|multisig|validator|quorum|consensus|signature|handshake|serialization|replay|oracle|vault|funding|collateral|liquidat|settlement)\w*", re.IGNORECASE), 4, "message names a security-sensitive subsystem"),
    (re.compile(r"\b(issue|bug|regression|incident|postmortem)\b", re.IGNORECASE), 1, "message references a bug or issue"),
)

NEGATIVE_MESSAGE_RULES = (
    (re.compile(r"^\s*docs?:", re.IGNORECASE), -4, "message looks like a docs-only change"),
    (re.compile(r"^\s*chore:", re.IGNORECASE), -4, "message looks like maintenance work"),
    (re.compile(r"^\s*ci:", re.IGNORECASE), -3, "message looks like CI-only work"),
    (re.compile(r"^\s*test:", re.IGNORECASE), -3, "message looks like test-only maintenance"),
    (re.compile(r"^\s*refactor:", re.IGNORECASE), -4, "message looks like a refactor"),
    (re.compile(r"^\s*feat(\([^)]+\))?:", re.IGNORECASE), -5, "message looks like a feature addition"),
    (re.compile(r"\b(feature|new api|new rpc|support for|add support|introduce)\b", re.IGNORECASE), -4, "message looks like feature work"),
    (re.compile(r"\b(migrat|migration|codec|protocol upgrade|upgrade to|upgrade .*version|v\d+)\b", re.IGNORECASE), -5, "message looks like a migration or codec upgrade"),
    (re.compile(r"\b(prun|pruning|perf|performance|optimi[sz]|speed[ -]?up|throughput|benchmark)\b", re.IGNORECASE), -5, "message looks like performance or pruning work"),
    (re.compile(r"\b(cleanup|clean up|cleanups?|maintenance|housekeeping|remove dead code|dead code)\b", re.IGNORECASE), -4, "message looks like cleanup or maintenance"),
    (re.compile(r"\b(architecture|architectural|rewrite|rework|overhaul|plumb|plumbing)\b", re.IGNORECASE), -5, "message looks like a broad architectural change"),
    (re.compile(r"\b(readme|typo|format|lint|rename|workflow|triage)\b", re.IGNORECASE), -2, "message points to cleanup or workflow work"),
    (re.compile(r"\b(frontend|front-end|ui|react|nextjs|tailwind|component|modal|button|layout|css)\b", re.IGNORECASE), -4, "message looks like a frontend or UI change"),
)

PATH_RULES = (
    (re.compile(r"(^|/)(src|core|node|protocol|runtime|consensus|network|p2p|rpc|storage|db|state|validator|crypto|cmd|pkg|internal|lib|app|client|server|x)(/|$)", re.IGNORECASE), 3, "touches a critical implementation path"),
    (re.compile(r"(^|/)(auth|access|permission|sign|verify|handshake|peer|mempool|snapshot|fork|quorum|election|slashing|multisig|oracle|vault|market|position|pool|liquidat|funding|collateral|evm|tx|transaction|blob)(/|$)", re.IGNORECASE), 3, "touches a sensitive subsystem"),
    (re.compile(r"(^|/)(test|tests|spec|integration|e2e|fuzz|regression)s?(/|$)", re.IGNORECASE), 1, "updates tests or regression coverage"),
)

CODE_RULES = (
    (re.compile(r"\b(assert|panic!|unwrap\(|expect\(|require\(|revert\()", re.IGNORECASE), 2, "diff changes runtime guards or failure handling"),
    (re.compile(r"\b(auth|authorize|permission|allow|deny|forbid|role|owner|admin|multisig|threshold)\b", re.IGNORECASE), 3, "diff changes access control or privilege checks"),
    (re.compile(r"\b(signature|verify|ecdsa|ed25519|secp256k1|nonce|replay|mac|hash)\b", re.IGNORECASE), 3, "diff changes cryptographic or replay-sensitive logic"),
    (re.compile(r"\b(queue|buffer|bound|limit|throttle|backpressure|timeout|retry|ratelimit|rate_limit)\b", re.IGNORECASE), 3, "diff changes resource-control logic"),
    (re.compile(r"\b(consensus|quorum|validator|vote|epoch|fork|finaliz|checkpoint|slashing)\w*", re.IGNORECASE), 3, "diff changes consensus or validator logic"),
    (re.compile(r"\b(snapshot|restore|serialize|deserialize|decode|encode|merkle|state|db|database|wal|balance|collateral|reserve|opening_amount|opening_size|funding|settlement|accounting)\b", re.IGNORECASE), 2, "diff changes state or storage handling"),
)

SOURCE_SUFFIXES = (
    ".rs",
    ".go",
    ".py",
    ".java",
    ".kt",
    ".scala",
    ".cc",
    ".cpp",
    ".c",
    ".h",
    ".hpp",
    ".ts",
    ".js",
)
DOC_SUFFIXES = (".md", ".rst", ".txt")
TEST_HINTS = ("test/", "tests/", "spec/", "integration", "e2e", "fuzz", "regression", "__tests__")
SOURCE_DIR_HINTS = (
    "src/",
    "core/",
    "node/",
    "protocol/",
    "runtime/",
    "consensus/",
    "network/",
    "p2p/",
    "rpc/",
    "storage/",
    "db/",
    "state/",
    "validator/",
    "crypto/",
    "cmd/",
    "pkg/",
    "internal/",
    "lib/",
    "app/",
    "client/",
    "server/",
    "x/",
)
TOOLING_PATH_HINTS = (
    ".github/",
    ".gitlab/",
    ".circleci/",
    ".devcontainer/",
    "scripts/",
    "script/",
    "tools/",
    "tooling/",
    "hack/",
    "examples/",
    "example/",
    "templates/",
    "template/",
    "bench/",
    "benchmark/",
    "benchmarks/",
)
FRONTEND_SUFFIXES = (".tsx", ".jsx", ".css", ".scss", ".sass", ".less", ".html", ".vue", ".svelte")
FRONTEND_PATH_HINTS = (
    "frontend/",
    "front-end/",
    "ui/",
    "web/",
    "www/",
    "components/",
    "pages/",
    "layouts/",
    "styles/",
    "assets/",
    "public/",
)
STRING_LITERAL_RE = re.compile(
    r"""
    (?:
        \b[rbufRBUTF]*"(?:\\.|[^"\\])*"
      |
        \b[rbufRBUTF]*'(?:\\.|[^'\\])*'
      |
        `[^`]*`
    )
    """,
    re.VERBOSE,
)
HUNK_HEADER_RE = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(?:\s*(.*))?")
CODE_REASON_SET = {reason for _, _, reason in CODE_RULES}


@dataclass
class RankedCommit:
    sha: str
    short_sha: str
    date: str
    author: str
    subject: str
    score: int
    band: str
    reasons: list[str]
    files: list[str]
    source_files: list[str]
    test_files: list[str]
    added_lines: int
    deleted_lines: int
    implementation_files: list[str] = field(default_factory=list)
    tooling_files: list[str] = field(default_factory=list)
    frontend_files: list[str] = field(default_factory=list)
    code_signal_count: int = 0
    path_signal_count: int = 0


@dataclass
class DiffHunk:
    file: str
    old_start: int
    new_start: int
    header: str
    before_lines: list[str]
    after_lines: list[str]
    changed_lines: list[str]


@dataclass
class HunkEvidence:
    file: str
    old_start: int
    new_start: int
    header: str
    before: str
    after: str
    score: int
    reasons: list[str]
    signal_text: str
    changed_lines: list[str] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Path to the git repository")
    parser.add_argument("--limit", type=int, default=0, help="Maximum number of ranked commits to print; use 0 for no limit")
    parser.add_argument("--min-score", type=int, help="Minimum score required to print a commit; if omitted, phase 1 chooses one automatically")
    parser.add_argument("--rev-range", default="--all", help="Revision set to scan, for example --all or origin/main..HEAD")
    parser.add_argument("--include-merges", action="store_true", help="Include merge commits")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--out-file", help="Optional path to write the ranked candidates JSON payload")
    return parser.parse_args()


def run_git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.stdout


def list_commits(repo: Path, rev_range: str, include_merges: bool) -> list[str]:
    args = ["rev-list"]
    if not include_merges:
        args.append("--no-merges")
    args.append(rev_range)
    output = run_git(repo, *args)
    return [line for line in output.splitlines() if line.strip()]


def unique_reasons(reasons: list[str]) -> list[str]:
    ordered: list[str] = []
    seen = set()
    for reason in reasons:
        if reason not in seen:
            ordered.append(reason)
            seen.add(reason)
    return ordered


def path_matches_hints(path: str, hints: tuple[str, ...]) -> bool:
    lowered = path.lower()
    return any(lowered.startswith(hint) or f"/{hint}" in lowered for hint in hints)


def is_source_file(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith(SOURCE_SUFFIXES) or lowered.startswith(SOURCE_DIR_HINTS)


def is_doc_file(path: str) -> bool:
    lowered = path.lower()
    name = lowered.rsplit("/", 1)[-1]
    return lowered.endswith(DOC_SUFFIXES) or name.startswith("readme")


def is_test_file(path: str) -> bool:
    lowered = path.lower()
    return any(hint in lowered for hint in TEST_HINTS)


def is_tooling_file(path: str) -> bool:
    return path_matches_hints(path, TOOLING_PATH_HINTS)


def is_frontend_file(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith(FRONTEND_SUFFIXES) or path_matches_hints(path, FRONTEND_PATH_HINTS)


def is_implementation_file(path: str) -> bool:
    return (
        is_source_file(path)
        and not is_doc_file(path)
        and not is_test_file(path)
        and not is_tooling_file(path)
        and not is_frontend_file(path)
    )


def score_rules(text: str, rules: tuple[tuple[re.Pattern[str], int, str], ...]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    for pattern, weight, reason in rules:
        if pattern.search(text):
            score += weight
            reasons.append(reason)
    return score, reasons


def parse_numstat(repo: Path, sha: str) -> tuple[int, int]:
    output = run_git(repo, "diff-tree", "--root", "--no-commit-id", "--numstat", "-r", sha)
    added = 0
    deleted = 0
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            added += int(parts[0])
            deleted += int(parts[1])
        except ValueError:
            continue
    return added, deleted


def band_for_score(score: int) -> str:
    if score >= 14:
        return "high"
    if score >= 8:
        return "medium"
    if score >= 5:
        return "low"
    return "noise"


def candidate_count_for_threshold(ranked: list[RankedCommit], threshold: int) -> int:
    return sum(item.score >= threshold for item in ranked)


def score_at_fraction_boundary(ranked: list[RankedCommit], fraction: float) -> int:
    index = max(0, min(len(ranked) - 1, math.ceil(len(ranked) * fraction) - 1))
    return ranked[index].score


def score_above_largest_upper_tail_drop(ranked: list[RankedCommit]) -> int | None:
    if len(ranked) < 2:
        return None

    window_size = min(len(ranked), max(12, min(80, math.ceil(len(ranked) * 0.2))))
    best_index = -1
    best_drop = 0
    for index in range(window_size - 1):
        drop = ranked[index].score - ranked[index + 1].score
        if drop > best_drop:
            best_drop = drop
            best_index = index
    if best_drop < 2:
        return None
    return ranked[best_index].score


def threshold_for_candidate_cap(ranked: list[RankedCommit], max_candidates: int) -> int:
    index = max(0, min(len(ranked) - 1, max_candidates - 1))
    score = ranked[index].score
    while index > 0 and ranked[index - 1].score == score:
        index -= 1
    if index == 0:
        return score
    return ranked[index - 1].score


def choose_min_score(ranked: list[RankedCommit], scanned_count: int) -> tuple[int, str]:
    del scanned_count
    if not ranked:
        return 8, "auto defaulted to 8 because no ranked commits were available yet"

    safety_floor = 8
    boundary_fraction = 0.15 if len(ranked) < 500 else 0.12
    boundary_score = score_at_fraction_boundary(ranked, boundary_fraction)
    drop_score = score_above_largest_upper_tail_drop(ranked)
    chosen = max(safety_floor, boundary_score)
    chosen = min(chosen, 20)

    reasons = [
        f"auto-selected {chosen} from score distribution",
        f"using a safety floor of {safety_floor}",
        f"using the top {int(boundary_fraction * 100)}% boundary score of {boundary_score}",
    ]
    if drop_score is not None:
        if drop_score <= chosen + 2:
            chosen = max(chosen, drop_score)
            reasons.append(
                f"nudged the threshold with the largest upper-tail drop score of {drop_score}"
            )
        else:
            reasons.append(
                f"observed a larger upper-tail drop score of {drop_score} but kept recall-first thresholding"
            )
    else:
        reasons.append("no meaningful upper-tail score drop was found")

    min_candidates = min(len(ranked), 50)
    max_candidates = min(len(ranked), 1000)
    kept = candidate_count_for_threshold(ranked, chosen)

    if kept < min_candidates:
        clamp_score = ranked[min_candidates - 1].score
        if clamp_score < chosen:
            chosen = clamp_score
            kept = candidate_count_for_threshold(ranked, chosen)
            reasons.append(
                f"lowered the threshold to {chosen} so the shortlist keeps at least about {min_candidates} candidates"
            )
    elif kept > max_candidates:
        clamp_score = threshold_for_candidate_cap(ranked, max_candidates)
        if clamp_score > chosen:
            chosen = clamp_score
            kept = candidate_count_for_threshold(ranked, chosen)
            reasons.append(
                f"raised the threshold to {chosen} so the shortlist stays under the {max_candidates}-candidate cap"
            )

    chosen = min(chosen, 20)
    reasons.append(f"final shortlist keeps {kept} candidate(s)")
    return chosen, ", ".join(reasons)


def load_metadata(repo: Path, sha: str) -> tuple[str, str, str, str, str]:
    raw = run_git(repo, "show", "--quiet", "--format=%H%x00%h%x00%ad%x00%an%x00%s", "--date=short", sha)
    parts = raw.rstrip("\n").split("\x00")
    if len(parts) != 5:
        raise ValueError(f"unexpected metadata format for commit {sha}")
    return tuple(parts)  # type: ignore[return-value]


def load_body(repo: Path, sha: str) -> str:
    return run_git(repo, "show", "--quiet", "--format=%b", sha).strip()


def load_files(repo: Path, sha: str) -> list[str]:
    output = run_git(repo, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", sha)
    return [line for line in output.splitlines() if line.strip()]


def load_diff_hunks(repo: Path, sha: str, context: int = 2) -> list[DiffHunk]:
    output = run_git(repo, "show", "--format=", f"--unified={context}", "--no-ext-diff", sha)
    hunks: list[DiffHunk] = []
    current_file: str | None = None
    old_start = 1
    new_start = 1
    header = ""
    before_lines: list[str] = []
    after_lines: list[str] = []
    changed_lines: list[str] = []
    in_hunk = False

    def flush_hunk() -> None:
        nonlocal before_lines, after_lines, changed_lines, in_hunk, header
        if current_file is None or (not before_lines and not after_lines and not changed_lines):
            before_lines = []
            after_lines = []
            changed_lines = []
            header = ""
            in_hunk = False
            return
        hunks.append(
            DiffHunk(
                file=current_file,
                old_start=old_start,
                new_start=new_start,
                header=header,
                before_lines=before_lines,
                after_lines=after_lines,
                changed_lines=changed_lines,
            )
        )
        before_lines = []
        after_lines = []
        changed_lines = []
        header = ""
        in_hunk = False

    for line in output.splitlines():
        if line.startswith("diff --git "):
            flush_hunk()
            current_file = None
            continue
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue
        if line.startswith("@@"):
            flush_hunk()
            match = HUNK_HEADER_RE.search(line)
            if not match or current_file is None:
                continue
            old_start = int(match.group(1))
            new_start = int(match.group(2))
            header = (match.group(3) or "").strip()
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith("\\"):
            continue
        if line.startswith("-"):
            before_lines.append(line[1:])
            changed_lines.append(line[1:])
            continue
        if line.startswith("+"):
            after_lines.append(line[1:])
            changed_lines.append(line[1:])
            continue
        if line.startswith(" "):
            snippet = line[1:]
            before_lines.append(snippet)
            after_lines.append(snippet)

    flush_hunk()
    return hunks


def strip_string_literals(text: str) -> str:
    return STRING_LITERAL_RE.sub('""', text)


def normalize_signal_line(line: str) -> str:
    text = strip_string_literals(line)
    for marker in ("//", "#", "--", "/*"):
        if marker in text:
            text = text.split(marker, 1)[0]
    text = text.strip()
    if not text:
        return ""
    if text.startswith(("*", "/*", "*/")):
        return ""
    if re.fullmatch(r"[\W_]+", text):
        return ""
    return text.lower()


def collect_signal_text(lines: list[str]) -> str:
    normalized = [normalize_signal_line(line) for line in lines]
    return " ".join(piece for piece in normalized if piece)


def score_diff_hunks(hunks: list[DiffHunk]) -> tuple[int, list[str], int]:
    signal_text = " ".join(
        collect_signal_text(hunk.changed_lines)
        for hunk in hunks
        if is_implementation_file(hunk.file)
    )
    score, reasons = score_rules(signal_text, CODE_RULES)
    code_signal_count = len({reason for reason in reasons if reason in CODE_REASON_SET})
    return score, reasons, code_signal_count


def collect_ranked_evidence(repo: Path, sha: str, limit: int = 3) -> list[HunkEvidence]:
    implementation_hunks = [hunk for hunk in load_diff_hunks(repo, sha, context=2) if is_implementation_file(hunk.file)]
    if not implementation_hunks:
        return []

    candidates: list[HunkEvidence] = []
    for hunk in implementation_hunks:
        signal_text = collect_signal_text(hunk.changed_lines)
        path_score, path_reasons = score_rules(hunk.file, PATH_RULES)
        code_score, code_reasons = score_rules(signal_text, CODE_RULES)
        score = path_score + code_score + (1 if signal_text else 0)
        reasons = unique_reasons(path_reasons + code_reasons)
        candidates.append(
            HunkEvidence(
                file=hunk.file,
                old_start=hunk.old_start,
                new_start=hunk.new_start,
                header=hunk.header,
                before="\n".join(hunk.before_lines[:8]).strip(),
                after="\n".join(hunk.after_lines[:8]).strip(),
                score=score,
                reasons=reasons,
                signal_text=signal_text,
                changed_lines=hunk.changed_lines[:12],
            )
        )

    candidates.sort(
        key=lambda item: (
            item.score,
            len(item.reasons),
            len(item.after) + len(item.before),
            item.file,
        ),
        reverse=True,
    )
    if limit > 0:
        return candidates[:limit]
    return candidates


def select_primary_evidence(repo: Path, sha: str) -> HunkEvidence | None:
    candidates = collect_ranked_evidence(repo, sha, limit=1)
    if not candidates:
        return None
    return candidates[0]


def analyze_commit(repo: Path, sha: str) -> RankedCommit:
    full_sha, short_sha, date, author, subject = load_metadata(repo, sha)
    body = load_body(repo, sha)
    files = load_files(repo, sha)
    added_lines, deleted_lines = parse_numstat(repo, sha)
    diff_hunks = load_diff_hunks(repo, sha, context=0)

    score = 0
    reasons: list[str] = []

    message_score, message_reasons = score_rules(f"{subject}\n{body}", MESSAGE_RULES)
    score += message_score
    reasons.extend(message_reasons)

    negative_score, negative_reasons = score_rules(f"{subject}\n{body}", NEGATIVE_MESSAGE_RULES)
    score += negative_score
    reasons.extend(negative_reasons)

    source_files = [path for path in files if is_source_file(path)]
    implementation_files = [path for path in files if is_implementation_file(path)]
    test_files = [path for path in files if is_test_file(path)]
    doc_files = [path for path in files if is_doc_file(path)]
    tooling_files = [path for path in files if is_tooling_file(path)]
    frontend_files = [path for path in files if is_frontend_file(path)]

    if implementation_files:
        score += min(8, len(implementation_files) * 2)
        reasons.append("touches implementation code rather than only metadata")

    if implementation_files and len(files) <= 14:
        score += 2
        reasons.append("diff is focused enough for manual fix reconstruction")

    if test_files and implementation_files:
        score += 2
        reasons.append("adds or updates tests beside implementation changes")

    if source_files and not implementation_files and not test_files:
        score -= 5
        reasons.append("touches only tooling, examples, or support code")

    if frontend_files and not implementation_files and not test_files:
        score -= 7
        reasons.append("touches only frontend or UI code")

    if files and len(doc_files) == len(files):
        score -= 6
        reasons.append("touches only documentation files")

    if test_files and len(test_files) == len(files):
        score -= 2
        reasons.append("touches only tests")

    matched_path_reasons = set()
    for path in [*implementation_files, *test_files]:
        for pattern, weight, reason in PATH_RULES:
            if pattern.search(path) and reason not in matched_path_reasons:
                score += weight
                reasons.append(reason)
                matched_path_reasons.add(reason)

    diff_score, diff_reasons, code_signal_count = score_diff_hunks(diff_hunks)
    score += diff_score
    reasons.extend(diff_reasons)

    churn = added_lines + deleted_lines
    if len(files) > 25:
        score -= 4
        reasons.append("broad multi-file diff often indicates refactor or migration noise")

    if len(files) > 60:
        score -= 4
        reasons.append("very large file count makes the commit less likely to be a single focused fix")

    if churn > 2500:
        score -= 4
        reasons.append("very large churn often reflects sweeping changes rather than a targeted fix")

    if (
        any("feature" in reason or "migration" in reason or "performance" in reason or "architectural" in reason or "cleanup" in reason for reason in reasons)
        and "message uses explicit security language" not in reasons
    ):
        score -= 5
        reasons.append("commit looks more like product or maintenance work than a targeted vulnerability fix")

    if "message uses explicit security language" in reasons and not implementation_files and not test_files:
        score -= 6
        reasons.append("security language appears only in commit text without implementation evidence")

    if "message uses explicit security language" in reasons and code_signal_count == 0 and not matched_path_reasons and not test_files:
        score -= 4
        reasons.append("security language is not corroborated by implementation signals")

    if len(files) > 12 and "message says the commit is a fix or hardening change" not in reasons and code_signal_count == 0:
        score -= 3
        reasons.append("larger multi-file change without explicit fix language is less likely to be a focused vuln fix")

    if churn <= 4:
        score -= 1
        reasons.append("very small diff")

    return RankedCommit(
        sha=full_sha,
        short_sha=short_sha,
        date=date,
        author=author,
        subject=subject,
        score=score,
        band=band_for_score(score),
        reasons=unique_reasons(reasons),
        files=files,
        source_files=source_files,
        test_files=test_files,
        added_lines=added_lines,
        deleted_lines=deleted_lines,
        implementation_files=implementation_files,
        tooling_files=tooling_files,
        frontend_files=frontend_files,
        code_signal_count=code_signal_count,
        path_signal_count=len(matched_path_reasons),
    )


def emit_text(commits: list[RankedCommit], scanned_count: int, repo: Path, effective_min_score: int, min_score_reason: str) -> None:
    print(f"Scanned {scanned_count} commits in {repo}")
    print(f"Effective min score: {effective_min_score}")
    print(f"Threshold reason: {min_score_reason}")
    print(f"Ranked {len(commits)} candidate commits")
    print()
    for commit in commits:
        print(f"{commit.short_sha}  score={commit.score}  band={commit.band}  {commit.date}  {commit.subject}")
        print(f"  Author: {commit.author}")
        print(f"  Reasons: {', '.join(commit.reasons)}")
        print(f"  Files: {', '.join(commit.files[:8])}")
        if len(commit.files) > 8:
            print(f"  Files+: {len(commit.files) - 8} more")
        print(f"  Churn: +{commit.added_lines} / -{commit.deleted_lines}")
        print(f"  Review: git -C {repo} show --stat --unified=0 {commit.sha}")
        print()


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()

    try:
        run_git(repo, "rev-parse", "--show-toplevel")
    except subprocess.CalledProcessError:
        print(f"{repo} is not a git repository", file=sys.stderr)
        return 2

    commits = list_commits(repo, args.rev_range, args.include_merges)
    ranked = [analyze_commit(repo, sha) for sha in commits]
    ranked.sort(key=lambda item: (item.score, item.date, item.sha), reverse=True)
    effective_min_score = args.min_score
    min_score_reason = "user supplied --min-score"
    if effective_min_score is None:
        effective_min_score, min_score_reason = choose_min_score(ranked, len(commits))
    ranked = [item for item in ranked if item.score >= effective_min_score]
    if args.limit > 0:
        ranked = ranked[: args.limit]

    payload = {
        "repo": str(repo),
        "scanned_commits": len(commits),
        "rev_range": args.rev_range,
        "min_score": effective_min_score,
        "min_score_reason": min_score_reason,
        "limit": args.limit,
        "include_merges": args.include_merges,
        "candidates": [asdict(item) for item in ranked],
    }

    if args.out_file:
        out_path = Path(args.out_file).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        emit_text(ranked, len(commits), repo, effective_min_score, min_score_reason)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
