from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import classify_candidates
import generate_findings
import phase3_agents
import rank_fix_commits


class GitRepoHarness:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.run("init")

    def run(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return completed.stdout.strip()

    def write(self, relpath: str, content: str) -> None:
        path = self.root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def commit(self, message: str) -> str:
        self.run("add", ".")
        self.run(
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-m",
            message,
        )
        return self.run("rev-parse", "HEAD")


class FakeLLMClient:
    def __init__(self, responses: list[dict]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str]] = []

    def complete_json(self, instructions: str, input_text: str) -> dict:
        self.calls.append((instructions, input_text))
        if not self.responses:
            raise AssertionError("no more fake responses queued")
        return self.responses.pop(0)


class FailingLLMClient:
    def complete_json(self, instructions: str, input_text: str) -> dict:
        raise ValueError("synthetic mapper failure")


class PipelineTests(unittest.TestCase):
    def test_phase3_agent_client_uses_codex_subscription_path(self) -> None:
        fake_client = object()
        with mock.patch.object(generate_findings.phase3_agents, "CodexExecClient", return_value=fake_client) as codex_client:
            client = generate_findings.init_agent_client(
                "mapper-drafter-skeptic",
                phase3_agents.AgentRunConfig(model="gpt-5"),
                None,
            )

        self.assertIs(client, fake_client)
        codex_client.assert_called_once_with(model="gpt-5")

    def test_phase3_codex_client_parses_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            log_path = root / "codex.log"
            codex_path = root / "codex"
            codex_path.write_text(
                f"""#!/usr/bin/env bash
set -euo pipefail

printf '%s\\n' "$*" >> "{log_path}"

if [[ "${{1:-}}" == "login" && "${{2:-}}" == "status" ]]; then
    echo "Logged in using ChatGPT"
    exit 0
fi

if [[ "${{1:-}}" == "exec" ]]; then
    out=""
    while [[ $# -gt 0 ]]; do
        if [[ "$1" == "--output-last-message" ]]; then
            out="$2"
            shift 2
            continue
        fi
        shift
    done
    printf '{{"ok": true, "transport": "codex"}}' > "$out"
    exit 0
fi

echo "unexpected invocation" >&2
exit 1
""",
                encoding="utf-8",
            )
            codex_path.chmod(0o755)

            client = phase3_agents.CodexExecClient(model="gpt-5", codex_path=str(codex_path))
            payload = client.complete_json("Return JSON.", '{"phase":"mapper"}')

            self.assertEqual(payload, {"ok": True, "transport": "codex"})
            log_lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertGreaterEqual(len(log_lines), 2)
            self.assertIn("login status", log_lines[0])
            self.assertIn("exec", log_lines[1])
            self.assertIn('--sandbox read-only', log_lines[1])
            self.assertIn('model_reasoning_effort="high"', log_lines[1])
            self.assertIn("-m gpt-5", log_lines[1])

    def test_phase1_does_not_treat_move_files_as_blockchain_source(self) -> None:
        self.assertFalse(rank_fix_commits.is_source_file("sources/position.move"))

    def test_phase1_ignores_tooling_keyword_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = GitRepoHarness(Path(tmpdir))
            repo.write("README.md", "starter\n")
            repo.commit("bootstrap repo")

            repo.write(
                "scripts/ranker.py",
                """
RULES = [
    "security",
    "signature",
    "consensus",
    "queue",
    "replay",
]


def describe() -> str:
    return "security fix triage workflow"
""".strip()
                + "\n",
            )
            sha = repo.commit("Add 3-phase security fix triage workflow")

            commit = rank_fix_commits.analyze_commit(Path(tmpdir), sha)

            self.assertIn("touches only tooling, examples, or support code", commit.reasons)
            self.assertNotIn("diff changes cryptographic or replay-sensitive logic", commit.reasons)
            self.assertNotIn("diff changes consensus or validator logic", commit.reasons)
            self.assertLess(commit.score, 10)

    def test_phase1_downranks_frontend_only_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = GitRepoHarness(Path(tmpdir))
            repo.write("README.md", "starter\n")
            repo.commit("bootstrap repo")

            repo.write(
                "frontend/src/App.tsx",
                """
export function WalletModal() {
    return <button className="wallet-button">Connect</button>;
}
""".strip()
                + "\n",
            )
            sha = repo.commit("Fix wallet modal layout in frontend")

            commit = rank_fix_commits.analyze_commit(Path(tmpdir), sha)

            self.assertIn("touches only frontend or UI code", commit.reasons)
            self.assertIn("message looks like a frontend or UI change", commit.reasons)
            self.assertLess(commit.score, 10)

    def test_classification_requires_grounded_source_signals(self) -> None:
        commit = rank_fix_commits.RankedCommit(
            sha="a" * 40,
            short_sha="aaaaaaa",
            date="2026-04-06",
            author="Test User",
            subject="Add security fix triage workflow",
            score=12,
            band="medium",
            reasons=[
                "message uses explicit security language",
                "message says the commit is a fix or hardening change",
                "touches only tooling, examples, or support code",
                "security language appears only in commit text without implementation evidence",
            ],
            files=["scripts/tool.py"],
            source_files=["scripts/tool.py"],
            test_files=[],
            added_lines=20,
            deleted_lines=3,
            implementation_files=[],
            tooling_files=["scripts/tool.py"],
            code_signal_count=0,
            path_signal_count=0,
        )

        classification, accepted, rationale = classify_candidates.classify_candidate(commit)

        self.assertEqual(classification, "feature-or-maintenance")
        self.assertFalse(accepted)
        self.assertIn("tooling or support code", rationale)

    def test_phase3_builds_richer_report_from_multiple_evidence_hunks(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = GitRepoHarness(Path(tmpdir))
            repo.write("README.md", "initial\n")
            repo.write(
                "x/evm/types/blob_tx.go",
                """
package ethtx

func (tx *BlobTx) AsEthereumData() *BlobTx {
    v, r, s := tx.GetRawSignatureValues()
    return &BlobTx{
        V: MustFromBig(v),
        R: MustFromBig(r),
        S: MustFromBig(s),
    }
}
""".strip()
                + "\n",
            )
            repo.write(
                "x/evm/types/message_evm_transaction.go",
                """
package evmtypes

func Preprocess(msg *MsgEVMTransaction) error {
    txData, err := UnpackTxData(msg.Data)
    if err != nil {
        return err
    }
    _ = txData.AsEthereumData()
    return nil
}
""".strip()
                + "\n",
            )
            repo.commit("bootstrap repo")

            repo.write("README.md", "security fix notes for BlobTx panic handling\n")
            repo.write(
                "x/evm/types/blob_tx.go",
                """
package ethtx

func (tx *BlobTx) AsEthereumData() (*BlobTx, error) {
    v, r, s, err := tx.GetCheckedSignatureValues()
    if err != nil {
        return nil, err
    }
    return &BlobTx{
        V: v,
        R: r,
        S: s,
    }, nil
}
""".strip()
                + "\n",
            )
            repo.write(
                "x/evm/types/message_evm_transaction.go",
                """
package evmtypes

func Preprocess(msg *MsgEVMTransaction) error {
    txData, err := UnpackTxData(msg.Data)
    if err != nil {
        return err
    }
    ethTxData, err := txData.AsEthereumData()
    if err != nil {
        return err
    }
    _ = ethTxData
    return nil
}
""".strip()
                + "\n",
            )
            sha = repo.commit("Guard BlobTx signature conversion from malformed input")

            commit = rank_fix_commits.analyze_commit(Path(tmpdir), sha)
            evidences = rank_fix_commits.collect_ranked_evidence(Path(tmpdir), sha, limit=3)
            markdown = generate_findings.build_markdown(
                Path(tmpdir),
                commit,
                agent_mode="heuristic",
                context_depth="deep",
            )

            self.assertGreaterEqual(len(evidences), 2)
            self.assertIn("render_mode: heuristic", markdown)
            self.assertIn("context_depth: deep", markdown)
            self.assertIn("# Summary", markdown)
            self.assertIn("## Observed Patch Facts", markdown)
            self.assertIn("## Project Context", markdown)
            self.assertIn("## Before/After Behavior", markdown)
            self.assertIn("# Root Cause", markdown)
            self.assertIn("## Walkthrough", markdown)
            self.assertIn("# Fix Pattern", markdown)
            self.assertIn("# Why It Matters", markdown)
            self.assertIn("## Affected Code Paths", markdown)
            self.assertIn("## How It Was Fixed", markdown)
            self.assertIn("## Code Snippets", markdown)
            self.assertIn("x/evm/types/blob_tx.go", markdown)
            self.assertIn("x/evm/types/message_evm_transaction.go", markdown)
            self.assertIn("MustFromBig", markdown)
            self.assertIn("## Snippet 1", markdown)
            self.assertIn("## Snippet 2", markdown)

    def test_phase3_stays_conservative_for_rpc_state_representation_fix(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = GitRepoHarness(Path(tmpdir))
            repo.write(
                "go/staking/api/account.go",
                """
package api

type Account struct {
    General GeneralAccount
    Escrow EscrowAccount
}
""".strip()
                + "\n",
            )
            repo.write(
                "go/staking/grpc.go",
                """
package staking

func GetAccountInfo(account *Account) *GetAccountInfoResponse {
    return &GetAccountInfoResponse{
        GeneralBalance: account.General.Balance.MarshalBinary(),
        EscrowBalance: account.Escrow.Active.Balance.MarshalBinary(),
    }
}
""".strip()
                + "\n",
            )
            repo.write(
                "go/oasis-node/cmd/stake/stake.go",
                """
package stake

func loadAccount(resp *GetAccountInfoResponse, ai *AccountInfo, id string) error {
    ai.ID = id
    if err := ai.GeneralBalance.UnmarshalBinary(resp.GetGeneralBalance()); err != nil {
        return err
    }
    if err := ai.EscrowBalance.UnmarshalBinary(resp.GetEscrowBalance()); err != nil {
        return err
    }
    return nil
}
""".strip()
                + "\n",
            )
            repo.commit("bootstrap repo")

            repo.write(
                "go/staking/client/client.go",
                """
// Package client implements a gRPC client for the staking service.
package client

import (
    "context"

    "google.golang.org/grpc"
)
""".strip()
                + "\n",
            )
            repo.write(
                "go/staking/grpc.go",
                """
package staking

func GetAccountInfo(account *Account) *GetAccountInfoResponse {
    return &GetAccountInfoResponse{
        Account: cbor.Marshal(account),
    }
}
""".strip()
                + "\n",
            )
            repo.write(
                "go/oasis-node/cmd/stake/stake.go",
                """
package stake

func loadAccount(resp *GetAccountInfoResponse, ai *AccountInfo, id string) error {
    var account Account
    if err := cbor.Unmarshal(resp.GetAccount(), &account); err != nil {
        return err
    }
    ai.ID = id
    ai.GeneralBalance = account.General.Balance
    ai.EscrowBalance = account.Escrow.Active.Balance
    return nil
}
""".strip()
                + "\n",
            )
            sha = repo.commit("Add gRPC client backend")

            commit = rank_fix_commits.analyze_commit(Path(tmpdir), sha)
            markdown = generate_findings.build_markdown(
                Path(tmpdir),
                commit,
                agent_mode="heuristic",
                context_depth="deep",
            )

            self.assertIn("render_mode: heuristic", markdown)
            self.assertIn("context_depth: deep", markdown)
            self.assertIn("subsystem: staking", markdown)
            self.assertIn("bug_class: serialization-or-state-representation", markdown)
            self.assertIn("## Observed Patch Facts", markdown)
            self.assertIn("## Project Context", markdown)
            self.assertIn("## Before/After Behavior", markdown)
            self.assertIn("does not prove a deeper cryptographic or economic flaw", markdown)
            self.assertNotIn("bug_class: accounting-or-state-drift", markdown)
            self.assertNotIn("subsystem: cryptography", markdown)
            self.assertNotIn("google.golang.org", markdown)
            self.assertIn("Account: cbor.Marshal(account)", markdown)
            self.assertIn("cbor.Unmarshal(resp.GetAccount(), &account)", markdown)
            self.assertIn("go/staking/api/account.go", markdown)

    def test_phase3_defaults_to_agent_mode_but_reports_heuristic_on_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = GitRepoHarness(Path(tmpdir))
            repo.write(
                "x/evm/types/blob_tx.go",
                """
package ethtx

func (tx *BlobTx) AsEthereumData() *BlobTx {
    v, r, s := tx.GetRawSignatureValues()
    return &BlobTx{
        V: MustFromBig(v),
        R: MustFromBig(r),
        S: MustFromBig(s),
    }
}
""".strip()
                + "\n",
            )
            repo.commit("bootstrap repo")

            repo.write(
                "x/evm/types/blob_tx.go",
                """
package ethtx

func (tx *BlobTx) AsEthereumData() (*BlobTx, error) {
    v, r, s, err := tx.GetCheckedSignatureValues()
    if err != nil {
        return nil, err
    }
    return &BlobTx{
        V: v,
        R: r,
        S: s,
    }, nil
}
""".strip()
                + "\n",
            )
            sha = repo.commit("Guard BlobTx signature conversion from malformed input")

            commit = rank_fix_commits.analyze_commit(Path(tmpdir), sha)
            markdown = generate_findings.build_markdown(
                Path(tmpdir),
                commit,
                llm_client=FailingLLMClient(),
            )

            self.assertIn("render_mode: heuristic", markdown)
            self.assertIn("context_depth: deep", markdown)
            self.assertIn("## Before/After Behavior", markdown)
            self.assertIn("Agent-backed phase 3 failed and the report fell back to heuristic rendering", markdown)

    def test_phase3_downranks_new_helper_modules_when_business_logic_hunk_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = GitRepoHarness(Path(tmpdir))
            repo.write(
                "stake/dummy/src/stake.rs",
                """
pub fn list_active_escrows_iterator(&self, owner: B256) -> Result<EscrowAccountIterator, Error> {
    unimplemented!();
}
""".strip()
                + "\n",
            )
            repo.commit("bootstrap repo")

            repo.write(
                "stake/dummy/src/stake.rs",
                """
pub fn list_active_escrows_iterator(&self, owner: B256) -> Result<EscrowAccountIterator, Error> {
    let entry = match self.stakes.get(&owner) {
        None => return Ok(EscrowAccountIterator::new(false, owner, B256::zero())),
        Some(e) => e,
    };
    Ok(EscrowAccountIterator::new(true, owner, entry.escrow))
}
""".strip()
                + "\n",
            )
            repo.write(
                "stake/dummy/src/usize_iterable_hashset.rs",
                """
use std::collections::{HashMap, HashSet};

pub struct UsizeIterableHashSet<K> {
    map: HashMap<K, usize>,
    store: Vec<K>,
}
""".strip()
                + "\n",
            )
            repo.write(
                "stake/dummy/src/usize_iterable_hashmap.rs",
                """
use std::collections::{HashMap, HashSet};

pub struct UsizeIterableHashMap<K, V> {
    map: HashMap<K, usize>,
    store: Vec<(K, V)>,
}
""".strip()
                + "\n",
            )
            sha = repo.commit("Towards working tests")

            evidences = generate_findings.select_phase3_evidences(Path(tmpdir), sha, limit=2)

            self.assertGreaterEqual(len(evidences), 1)
            self.assertEqual(evidences[0].file, "stake/dummy/src/stake.rs")
            self.assertNotEqual(evidences[0].file, "stake/dummy/src/usize_iterable_hashset.rs")

    def test_phase3_agent_mode_uses_mapper_drafter_skeptic_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = GitRepoHarness(Path(tmpdir))
            repo.write(
                "go/staking/api/account.go",
                """
package api

type Account struct {
    General GeneralAccount
    Escrow EscrowAccount
}
""".strip()
                + "\n",
            )
            repo.write(
                "go/staking/grpc.go",
                """
package staking

func GetAccountInfo(account *Account) *GetAccountInfoResponse {
    return &GetAccountInfoResponse{
        GeneralBalance: account.General.Balance.MarshalBinary(),
        EscrowBalance: account.Escrow.Active.Balance.MarshalBinary(),
    }
}
""".strip()
                + "\n",
            )
            repo.write(
                "go/oasis-node/cmd/stake/stake.go",
                """
package stake

func loadAccount(resp *GetAccountInfoResponse, ai *AccountInfo, id string) error {
    ai.ID = id
    if err := ai.GeneralBalance.UnmarshalBinary(resp.GetGeneralBalance()); err != nil {
        return err
    }
    if err := ai.EscrowBalance.UnmarshalBinary(resp.GetEscrowBalance()); err != nil {
        return err
    }
    return nil
}
""".strip()
                + "\n",
            )
            repo.commit("bootstrap repo")

            repo.write(
                "go/staking/grpc.go",
                """
package staking

func GetAccountInfo(account *Account) *GetAccountInfoResponse {
    return &GetAccountInfoResponse{
        Account: cbor.Marshal(account),
    }
}
""".strip()
                + "\n",
            )
            repo.write(
                "go/oasis-node/cmd/stake/stake.go",
                """
package stake

func loadAccount(resp *GetAccountInfoResponse, ai *AccountInfo, id string) error {
    var account Account
    if err := cbor.Unmarshal(resp.GetAccount(), &account); err != nil {
        return err
    }
    ai.ID = id
    ai.GeneralBalance = account.General.Balance
    ai.EscrowBalance = account.Escrow.Active.Balance
    return nil
}
""".strip()
                + "\n",
            )
            sha = repo.commit("Add gRPC client backend")

            commit = rank_fix_commits.analyze_commit(Path(tmpdir), sha)
            client = FakeLLMClient(
                [
                    {
                        "subsystem": "staking",
                        "bug_class": "serialization-or-state-representation",
                        "confidence": "medium",
                        "rationale": "The patch moves account transfer toward a canonical representation.",
                        "affected_code_paths": [
                            {"file": "go/staking/grpc.go", "line": 3, "role": "returns the canonical account payload"},
                            {"file": "go/oasis-node/cmd/stake/stake.go", "line": 3, "role": "reconstructs client-visible account state"},
                        ],
                        "claim_boundaries": ["The patch does not prove a cryptographic flaw."],
                    },
                    {
                        "summary": "The patch consolidates staking account transport around a canonical serialized account object instead of separate balance fields.",
                        "before_after_behavior": "Before the patch, the RPC boundary split account data across parallel balance fields. After the patch, the server sends one serialized account object and the client reconstructs balances from that canonical payload.",
                        "root_cause": "The pre-fix RPC boundary encoded overlapping account data through separate fields, which risked server/client representation drift.",
                        "walkthrough": [
                            "The server switches from separate balance fields to a serialized account payload.",
                            "The client decodes the full account object and rebuilds balances from that canonical object.",
                        ],
                        "fix_pattern": "Use a single canonical state representation across the RPC boundary.",
                        "how_it_was_fixed": "Both sides now exchange and decode one account object instead of reconstructing the view from multiple fields.",
                        "why_it_matters": [
                            "Client-visible state stays aligned with the server's canonical account model.",
                            "The patch reduces representation drift without proving a deeper exploit on its own.",
                        ],
                        "evidence_notes": "The draft is grounded in the grpc and stake command paths.",
                    },
                    {
                        "subsystem": "staking",
                        "bug_class": "serialization-or-state-representation",
                        "confidence": "low",
                        "summary": "This looks like a staking RPC state-representation fix, not a cryptography issue.",
                        "before_after_behavior": "Before the patch, the client consumed multiple derived balance fields. After the patch, both sides exchange one marshaled account object and derive balances from the same representation.",
                        "root_cause": "The problem is best understood as divergent account representation across the RPC boundary, not phantom accounting state.",
                        "walkthrough": [
                            "The gRPC server now returns the account as one serialized object.",
                            "The CLI path now decodes that object instead of stitching balances together from parallel fields.",
                        ],
                        "fix_pattern": "Prefer one canonical serialized account object over parallel derived balance fields.",
                        "how_it_was_fixed": "The landed patch marshals the account on the server and unmarshals it on the client.",
                        "why_it_matters": [
                            "It reduces the chance that clients observe a stale or partial account view.",
                            "The code does not show a confirmed economic exploit path.",
                        ],
                        "evidence_notes": "The skeptic kept the explanation conservative and tied to the code evidence.",
                        "verification_notes": [
                            "Removed unsupported cryptography and accounting-drift claims.",
                        ],
                    },
                ]
            )

            markdown = generate_findings.build_markdown(
                Path(tmpdir),
                commit,
                agent_mode="mapper-drafter-skeptic",
                llm_client=client,
            )

            self.assertEqual(len(client.calls), 3)
            self.assertIn("render_mode: mapper-drafter-skeptic", markdown)
            self.assertIn("context_depth: deep", markdown)
            self.assertIn("subsystem: staking", markdown)
            self.assertIn("bug_class: serialization-or-state-representation", markdown)
            self.assertIn("confidence: low", markdown)
            self.assertIn("This looks like a staking RPC state-representation fix, not a cryptography issue.", markdown)
            self.assertIn("Before the patch, the client consumed multiple derived balance fields.", markdown)
            self.assertIn("Prefer one canonical serialized account object over parallel derived balance fields.", markdown)
            self.assertIn("Agent pipeline used separate mapper, drafter, and skeptic passes.", markdown)
            self.assertIn("returns the canonical account payload", markdown)
            self.assertIn("Removed unsupported cryptography and accounting-drift claims.", markdown)

    def test_phase3_agent_mode_falls_back_to_heuristics_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = GitRepoHarness(Path(tmpdir))
            repo.write(
                "x/evm/types/blob_tx.go",
                """
package ethtx

func (tx *BlobTx) AsEthereumData() *BlobTx {
    v, r, s := tx.GetRawSignatureValues()
    return &BlobTx{
        V: MustFromBig(v),
        R: MustFromBig(r),
        S: MustFromBig(s),
    }
}
""".strip()
                + "\n",
            )
            repo.write(
                "x/evm/types/message_evm_transaction.go",
                """
package evmtypes

func Preprocess(msg *MsgEVMTransaction) error {
    txData, err := UnpackTxData(msg.Data)
    if err != nil {
        return err
    }
    _ = txData.AsEthereumData()
    return nil
}
""".strip()
                + "\n",
            )
            repo.commit("bootstrap repo")

            repo.write(
                "x/evm/types/blob_tx.go",
                """
package ethtx

func (tx *BlobTx) AsEthereumData() (*BlobTx, error) {
    v, r, s, err := tx.GetCheckedSignatureValues()
    if err != nil {
        return nil, err
    }
    return &BlobTx{
        V: v,
        R: r,
        S: s,
    }, nil
}
""".strip()
                + "\n",
            )
            repo.write(
                "x/evm/types/message_evm_transaction.go",
                """
package evmtypes

func Preprocess(msg *MsgEVMTransaction) error {
    txData, err := UnpackTxData(msg.Data)
    if err != nil {
        return err
    }
    ethTxData, err := txData.AsEthereumData()
    if err != nil {
        return err
    }
    _ = ethTxData
    return nil
}
""".strip()
                + "\n",
            )
            sha = repo.commit("Guard BlobTx signature conversion from malformed input")

            commit = rank_fix_commits.analyze_commit(Path(tmpdir), sha)
            markdown = generate_findings.build_markdown(
                Path(tmpdir),
                commit,
                agent_mode="mapper-drafter-skeptic",
                llm_client=FailingLLMClient(),
            )

            self.assertIn("render_mode: heuristic", markdown)
            self.assertIn("context_depth: deep", markdown)
            self.assertIn("subsystem: transaction-processing", markdown)
            self.assertIn("Guard BlobTx signature conversion from malformed input appears to harden", markdown)
            self.assertIn("Agent-backed phase 3 failed and the report fell back to heuristic rendering", markdown)


if __name__ == "__main__":
    unittest.main()
