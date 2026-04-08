---
name: dlt-fix-finder
description: Use this skill when the user wants to run or troubleshoot the DLT Fix Finder pipeline across phases 1-4, generate findings from git history, validate findings, or choose between Codex and Claude providers for the AI-backed stages.
---

# DLT Fix Finder

Use this skill to run the existing `dlt-fix-finder` pipeline. Do not reimplement the ranking, classification, finding generation, or validation logic in prompt text. Call the repo scripts.

## When to use

Use this skill when the user wants to:

- run phase 1, 2, 3, or 4
- generate findings from a git repo
- validate generated findings
- use phase 3 or phase 4 with `codex` or `claude`
- understand which command to run next in the pipeline

Do not use this skill for unrelated code review or general security analysis outside the `dlt-fix-finder` workflow.

## Workflow

The normal run order is:

1. phase 1: rank likely fix commits
2. phase 2: classify the phase 1 shortlist
3. phase 3: generate Markdown findings
4. phase 4: validate findings before corpus use

Always prefer the existing wrapper scripts:

- `scripts/phase1.sh`
- `scripts/phase2.sh`
- `scripts/phase3.sh`
- `scripts/phase4.sh`

If the skill is installed outside the repo, use the bundled helper:

```bash
bash scripts/run_phase.sh 1 --repo /path/to/repo
```

The helper script locates the `dlt-fix-finder` repo from:

1. `DLT_FIX_FINDER_ROOT`, if set
2. the current working directory or one of its parents

## Provider rules

Phase 1 and phase 2 are deterministic and do not need an AI provider.

Phase 3 and phase 4 support:

- `--agent-provider auto`
- `--agent-provider codex`
- `--agent-provider claude`

Use the default `auto` provider unless the user clearly wants a specific provider.

Important defaults:

- phase 3 defaults to `--agent-mode mapper-drafter-skeptic`
- phase 3 defaults to provider `auto`
- phase 4 defaults to provider `auto`
- `auto` prefers Claude in Claude sessions and Codex in Codex sessions when the environment can be detected

If the requested provider CLI is unavailable, either:

- switch to `--agent-mode heuristic` for phase 3, or
- explain the missing CLI and ask whether to continue without the AI-backed stage

## Common commands

Phase 1:

```bash
bash scripts/run_phase.sh 1 --repo /path/to/repo --out-file /path/to/repo/.dlt-fix-finder/phase1-candidates.json
```

Phase 2:

```bash
bash scripts/run_phase.sh 2 --candidate-file /path/to/repo/.dlt-fix-finder/phase1-candidates.json --out-file /path/to/repo/.dlt-fix-finder/phase2-classified.json
```

Phase 3 with Codex:

```bash
bash scripts/run_phase.sh 3 --repo /path/to/repo --candidate-file /path/to/repo/.dlt-fix-finder/phase2-classified.json --agent-provider codex
```

Phase 3 with Claude:

```bash
bash scripts/run_phase.sh 3 --repo /path/to/repo --candidate-file /path/to/repo/.dlt-fix-finder/phase2-classified.json --agent-provider claude
```

Phase 4 with Claude:

```bash
bash scripts/run_phase.sh 4 --repo /path/to/repo --findings-dir /path/to/repo/findings --candidate-file /path/to/repo/.dlt-fix-finder/phase2-classified.json --agent-provider claude
```

## Notes

- Read the repo `README.md` if the user asks for deeper phase-by-phase behavior or flag details.
- Keep the skill thin: route work to the scripts, do not duplicate the pipeline logic here.
