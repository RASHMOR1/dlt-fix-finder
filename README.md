# DLT Fix Finder

DLT Fix Finder turns git history into a reusable vulnerability-fix corpus for blockchain, DLT, and adjacent infrastructure projects.

It is meant for repositories such as:

- blockchain nodes
- consensus engines
- p2p networking stacks
- validator tooling
- storage layers
- cryptography libraries
- deployment and ops infrastructure

The core idea is simple:

1. scan commit history
2. rank likely security-fix or hardening commits
3. classify candidates into security-relevant vs noise
4. turn only accepted candidates into human-readable findings
5. feed the resulting Markdown corpus into RAG

## What This Project Does

This starter project now covers three stages:

- `scripts/phase1.sh`
  - runs commit ranking
- `scripts/phase2.sh`
  - classifies phase 1 candidates as `security-fix`, `security-hardening`, `correctness-or-reliability`, `feature-or-maintenance`, or `unclear`
- `scripts/phase3.sh`
  - writes compact Markdown findings in a RAG-friendly format for accepted candidates

Under the hood, those wrappers call:

- `scripts/rank_fix_commits.py`
- `scripts/classify_candidates.py`
- `scripts/generate_findings.py`

The generated findings are designed to be:

- understandable by humans
- compact enough for embeddings
- consistent enough for downstream filtering
- honest about uncertainty

The ranking stage is intentionally stricter now and downranks commits that look like:

- feature work
- migrations and codec upgrades
- pruning and performance work
- broad architectural rewrites
- cleanup and maintenance
- tooling-only or workflow-only changes
- frontend or UI-only changes

It also now prefers grounded implementation signals over raw keyword matches:

- source hunks are scored more heavily than docs, comments, or support files
- string literals and comments are stripped before diff keyword scoring
- findings are generated from the strongest implementation hunk rather than the first diff fragment

## Output Format

Each finding still follows the original top-level framework:

- YAML frontmatter with audit metadata
- `Summary`
- `Root Cause`
- `Fix Pattern`
- `Why It Matters`
- `Evidence Notes`

Within that framework, phase 3 now adds deeper nested detail when the patch supports it:

- `Observed Patch Facts`
- `Project Context`
- `Walkthrough`
- `Affected Code Paths`
- `How It Was Fixed`
- `Code Snippets`

The goal is to keep the notes useful for both retrieval and human review: they remain heuristic, but they now explain the suspected bug shape from multiple source hunks without abandoning the existing report structure.

## Usage

The phase wrappers resolve the project root from their own location, so `dlt-fix-finder` can live anywhere on disk. You can either run them from the project root with `bash scripts/...`, or from another directory by calling them with an absolute or relative path.

### Phase 1: Rank likely fix commits

```bash
cd /path/to/dlt-fix-finder
bash scripts/phase1.sh --repo /path/to/repo
```

If you want to pause here and reuse the exact shortlist later, write it to a file:

```bash
cd /path/to/dlt-fix-finder
bash scripts/phase1.sh \
  --repo /path/to/repo \
  --min-score 8 \
  --out-file /path/to/repo/.dlt-fix-finder/phase1-candidates.json
```

At this point phase 1 is done. You can stop, switch reasoning, review the shortlist, and come back later.

### Phase 2: Classify candidates

```bash
cd /path/to/dlt-fix-finder
bash scripts/phase2.sh \
  --candidate-file /path/to/repo/.dlt-fix-finder/phase1-candidates.json \
  --out-file /path/to/repo/.dlt-fix-finder/phase2-classified.json
```

This creates a review file with:

- `classification`
- `accepted`
- `classification_rationale`

By default:

- `security-fix` and `security-hardening` are accepted
- `correctness-or-reliability`, `feature-or-maintenance`, and `unclear` are not

You can manually edit the JSON before phase 3 if you want to keep or reject individual candidates.

### Phase 3: Generate RAG-ready findings

```bash
cd /path/to/dlt-fix-finder
bash scripts/phase3.sh --repo /path/to/repo
```

If you want phase 2 to use the classified shortlist:

```bash
cd /path/to/dlt-fix-finder
bash scripts/phase3.sh \
  --repo /path/to/repo \
  --candidate-file /path/to/repo/.dlt-fix-finder/phase2-classified.json \
  --out-dir /path/to/repo/findings \
  --overwrite
```

Phase 3 now generates findings only for `accepted` candidates by default.

If you want it to ignore the acceptance gate and generate findings for everything in the candidate file:

```bash
bash scripts/phase3.sh \
  --repo /path/to/repo \
  --candidate-file /path/to/repo/.dlt-fix-finder/phase2-classified.json \
  --include-unaccepted
```

By default, generated Markdown files are written into:

- `/path/to/repo/findings/`

You can choose a different output directory:

```bash
bash scripts/phase3.sh --repo /path/to/repo --out-dir /path/to/output
```

### Phase 3 Render Modes

Phase 3 now defaults to an agent-backed render mode that uses three separate passes:

- `mapper`
  - maps the touched subsystem, bug class, and affected code paths
- `drafter`
  - writes the narrative sections from the grounded evidence
- `skeptic`
  - removes unsupported claims and can downgrade labels or confidence

This mode still uses the same deterministic project-context extraction first. The agents sit on top of that context; they do not replace it.

Phase 3 now uses the local `codex` CLI for agent-backed rendering.

That means the supported agent path is your ChatGPT subscription login through Codex, not an API key. If the Codex client cannot be initialized, or if an agent step fails, phase 3 falls back to the heuristic renderer and records that in the finding frontmatter and evidence notes.

```bash
cd /path/to/dlt-fix-finder
codex login

bash scripts/phase3.sh \
  --repo /path/to/repo \
  --candidate-file /path/to/repo/.dlt-fix-finder/phase2-classified.json \
  --agent-model gpt-5 \
  --context-depth deep \
  --overwrite
```

Available agent flags:

- `--agent-mode heuristic|mapper-drafter-skeptic`
- `--context-depth shallow|deep`
  - `deep` gathers more neighboring files, traces identifiers into the touched subsystem, and writes a more explicit before/after behavior section
- `--agent-model MODEL_NAME`
- `--agent-strict`
  - fail instead of falling back to heuristic rendering if an agent step errors

Each generated finding now records:

- `render_mode`
  - the actual render path used for that file: `heuristic` or `mapper-drafter-skeptic`
- `context_depth`
  - whether the context builder used `shallow` or `deep` project exploration

## Reasoning Workflow

This layout is designed for the workflow you described:

1. run phase 1 with `medium` reasoning
2. stop
3. run phase 2 with `high` reasoning
4. review or edit the accepted list if needed
5. run phase 3 with `high` or `extra high` reasoning

That way you avoid paying for deep reasoning during the broad commit scan.

## Important Note

The generated findings are grounded summaries, not ground-truth vulnerability proofs.

The pipeline is stricter about evidence now:

- phase 2 only accepts commits with grounded implementation signals
- phase 3 only emits findings when it can extract a source-backed hunk to cite
- phase 3 now builds historical project context from the repo at the same commit before writing the finding
- deep mode reads more neighboring subsystem files, traces important identifiers, and reconstructs before/after behavior more explicitly
- generated claims are phrased from the observed hunk and nearby project context, not just the commit subject

If the agent-backed mode runs successfully, the final report is still grounded by the deterministic evidence extractor, and the skeptic pass is meant to reduce overclaiming rather than make the writeup more dramatic.

That means they are useful for:

- corpus building
- audit hypothesis generation
- retrieval during later reviews

But they should still be reviewed before being treated as confirmed cases.

## About Limits

Both scripts now default to `no limit`.

That means:

- phase 1 returns every candidate that passes `--min-score`
- phase 3 generates findings for every accepted candidate it receives

If you want to cap output for a first pass, you can still set `--limit` manually:

```bash
bash scripts/phase1.sh --repo /path/to/repo --min-score 8 --limit 30
bash scripts/phase2.sh --candidate-file /path/to/repo/.dlt-fix-finder/phase1-candidates.json --out-file /path/to/repo/.dlt-fix-finder/phase2-classified.json
bash scripts/phase3.sh --repo /path/to/repo --candidate-file /path/to/repo/.dlt-fix-finder/phase2-classified.json --limit 10
```

## Files

- `scripts/phase1.sh`
- `scripts/phase2.sh`
- `scripts/phase3.sh`
- `scripts/phase3_agents.py`
- `scripts/rank_fix_commits.py`
- `scripts/classify_candidates.py`
- `scripts/generate_findings.py`
- `templates/finding-template.md`
- `examples/example-output.md`
- `pyproject.toml`
