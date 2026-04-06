from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import classify_candidates
import generate_findings
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


class PipelineTests(unittest.TestCase):
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
            markdown = generate_findings.build_markdown(Path(tmpdir), commit)

            self.assertGreaterEqual(len(evidences), 2)
            self.assertIn("# Summary", markdown)
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


if __name__ == "__main__":
    unittest.main()
