#!/usr/bin/env bash
# Sourced by the demo scripts: sets $PY to a Python interpreter that has the
# project's dependencies installed. Order: active virtualenv / conda env,
# the project's .venv, then python3 / conda installs on this machine.
# Override with: PY=/path/to/python ./demo/present.sh
_kav_has_deps() { "$1" -c "import typer, rich, networkx, sklearn, requests" >/dev/null 2>&1; }

if [[ -z "${PY:-}" ]]; then
  _root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  for cand in \
      "${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python}" \
      "${CONDA_PREFIX:+$CONDA_PREFIX/bin/python}" \
      "$_root/.venv/bin/python" "$_root/venv/bin/python" \
      "$(command -v python3 2>/dev/null)" "$(command -v python 2>/dev/null)" \
      "$HOME/anaconda3/bin/python3" "$HOME/miniconda3/bin/python3" "$HOME/miniforge3/bin/python3" \
      /usr/bin/python3; do
    [[ -n "$cand" && -x "$cand" ]] || continue
    if _kav_has_deps "$cand"; then PY="$cand"; break; fi
  done
fi

if [[ -z "${PY:-}" ]] || ! _kav_has_deps "$PY"; then
  printf '\e[1;31mNo Python with the project dependencies was found.\e[0m\n' >&2
  printf 'Install them once (from the project folder):\n' >&2
  printf '  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt\n' >&2
  printf 'The demo scripts will then use .venv automatically.\n' >&2
  exit 1
fi
export PY
