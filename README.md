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
3. turn the strongest candidates into human-readable findings
4. review and refine those findings
5. feed the resulting Markdown corpus into RAG

## What This Project Does

This starter project now covers two stages:

- `scripts/rank_fix_commits.py`
  - finds likely security or hardening fixes from git history
- `scripts/generate_findings.py`
  - writes compact Markdown findings in a RAG-friendly format

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

## Output Format

Each finding is written in the compact style you asked for:

- YAML frontmatter with audit metadata
- `Summary`
- `Root Cause`
- `Fix Pattern`
- `Why It Matters`
- `Evidence Notes`

This keeps the notes readable while still making them strong retrieval documents.

## Usage

### Phase 1: Rank likely fix commits

```bash
cd /workspace/dlt-fix-finder
uv run scripts/rank_fix_commits.py --repo /path/to/repo
```

If you want to pause here and reuse the exact shortlist later, write it to a file:

```bash
cd /workspace/dlt-fix-finder
uv run scripts/rank_fix_commits.py \
  --repo /path/to/repo \
  --min-score 8 \
  --out-file /path/to/repo/.dlt-fix-finder/phase1-candidates.json
```

At this point phase 1 is done. You can stop, switch reasoning, review the shortlist, and come back later.

### Phase 2: Generate RAG-ready findings

```bash
cd /workspace/dlt-fix-finder
uv run scripts/generate_findings.py --repo /path/to/repo
```

If you want phase 2 to use the exact phase 1 shortlist instead of rescanning:

```bash
cd /workspace/dlt-fix-finder
uv run scripts/generate_findings.py \
  --repo /path/to/repo \
  --candidate-file /path/to/repo/.dlt-fix-finder/phase1-candidates.json \
  --out-dir /path/to/repo/findings \
  --overwrite
```

By default, generated Markdown files are written into:

- `/path/to/repo/findings/`

You can choose a different output directory:

```bash
uv run scripts/generate_findings.py --repo /path/to/repo --out-dir /path/to/output
```

## Reasoning Workflow

This layout is designed for the workflow you described:

1. run phase 1 with `medium` reasoning
2. stop
3. switch to `high` or `extra high` reasoning
4. run phase 2 from the saved candidate file

That way you avoid paying for deep reasoning during the broad commit scan.

## Important Note

The generated findings are heuristic summaries, not ground-truth vulnerability proofs.

That means they are useful for:

- corpus building
- audit hypothesis generation
- retrieval during later reviews

But they should still be reviewed before being treated as confirmed cases.

## About Limits

Both scripts now default to `no limit`.

That means:

- phase 1 returns every candidate that passes `--min-score`
- phase 2 generates findings for every candidate it receives

If you want to cap output for a first pass, you can still set `--limit` manually:

```bash
uv run scripts/rank_fix_commits.py --repo /path/to/repo --min-score 8 --limit 30
uv run scripts/generate_findings.py --repo /path/to/repo --candidate-file /path/to/repo/.dlt-fix-finder/phase1-candidates.json --limit 10
```

## Files

- `scripts/rank_fix_commits.py`
- `scripts/generate_findings.py`
- `templates/finding-template.md`
- `examples/example-output.md`
- `pyproject.toml`
