#!/usr/bin/env bash
set -euo pipefail

phase="${1:-}"
if [[ -z "${phase}" ]]; then
  echo "usage: bash scripts/run_phase.sh <1|2|3|4> [args...]" >&2
  exit 2
fi
shift || true

find_root() {
  if [[ -n "${DLT_FIX_FINDER_ROOT:-}" ]]; then
    if [[ -f "${DLT_FIX_FINDER_ROOT}/scripts/phase1.sh" ]]; then
      printf '%s\n' "${DLT_FIX_FINDER_ROOT}"
      return 0
    fi
    echo "DLT_FIX_FINDER_ROOT is set but does not point to a dlt-fix-finder repo" >&2
    exit 2
  fi

  local dir="${PWD}"
  while [[ "${dir}" != "/" ]]; do
    if [[ -f "${dir}/scripts/phase1.sh" && -f "${dir}/scripts/phase2.sh" && -f "${dir}/scripts/phase3.sh" && -f "${dir}/scripts/phase4.sh" && -f "${dir}/pyproject.toml" ]]; then
      printf '%s\n' "${dir}"
      return 0
    fi
    dir="$(dirname "${dir}")"
  done

  echo "Could not locate the dlt-fix-finder repo root. Run this from inside the repo, from a child directory of the repo, or set DLT_FIX_FINDER_ROOT." >&2
  exit 2
}

root="$(find_root)"

case "${phase}" in
  1|phase1|phase-1)
    script="${root}/scripts/phase1.sh"
    ;;
  2|phase2|phase-2)
    script="${root}/scripts/phase2.sh"
    ;;
  3|phase3|phase-3)
    script="${root}/scripts/phase3.sh"
    ;;
  4|phase4|phase-4)
    script="${root}/scripts/phase4.sh"
    ;;
  *)
    echo "unknown phase: ${phase}" >&2
    echo "expected one of: 1, 2, 3, 4, phase1, phase2, phase3, phase4" >&2
    exit 2
    ;;
esac

exec bash "${script}" "$@"
