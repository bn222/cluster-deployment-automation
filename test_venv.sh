#!/bin/bash

set -e

_CDA_USE_VENV=0
if [ -z "${VENV+x}" -a -n "$VIRTUAL_ENV" ] ; then
    printf '%s\n' "INFO: Use existing VENV=\"$VIRTUAL_ENV\""
elif [ -z "${VENV-x}" ]; then
    printf '%s\n' "INFO: Don't use VENV"
else
    _CDA_USE_VENV=1
    if [ -z "$VENV" ] ; then
        VENV=ocp-venv
    fi
    printf '%s\n' "INFO: Use \"$VENV\" virtual environment"
    if [ ! -f "$VENV/bin/activate" ] ; then
        if [ -z "$VENV_PYTHON" ] ; then
            _CDA_VENV_PYTHON=python
        else
            _CDA_VENV_PYTHON="$VENV_PYTHON"
        fi
        "$_CDA_VENV_PYTHON" -m venv "$VENV"
    fi
    source "$VENV/bin/activate"
fi

printf '%s\n' "INFO: python=$(printf '%q' "$(command -v python)")"

python -m ensurepip --upgrade
python -m pip install --upgrade pip
cat ./requirements.txt  | xargs -n1 python -m pip install --upgrade

EXTRA=(
  black==22.12.0
  flake8
  flake8-comprehensions
  mypy
  types-paramiko
  types-PyYAML
  types-requests
)

for p in "${EXTRA[@]}"; do
    python -m pip install --upgrade "$p"
done

if [ "$_CDA_USE_VENV" = 1 ] ; then
    printf '\n'
    printf '%s\n' "INFO: source \"$VENV/bin/activate\""
fi
