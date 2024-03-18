#!/bin/bash

# Usage: setup.sh [--help]
#
# Environment variables:
#   VENV: use the specified Python virtual environment. If empty, don't use a
#     virtual environment and use python/pip from the caller's $PATH. Defaults
#     to $VIRTUAL_ENV or "$BASEDIR/ocp-venv".
#   VENV_PYTHON: the python interpreter to use to create the virtual
#     environment. This only matters, while creating $VENV. If the virtual
#     environment already exists, or if we are called with VENV="" then this has
#     no effect. Aside creating the $VENT, we use python/pip from the $PATH/$VENV.
#   VERBOSE: if set to non-empty, don't hide output of commands.
#
# - If you use VENV, you will need to `source "$VENT/bin/activate" before using cda.py.
# - Sets up bash completion for `oc`. You may want to start a new bash
#   afterwards or source /etc/bash_completion.d/oc_bash_completion.
# - If ~/.ssh/id_ed25519 does not exist, a new key gets generated.
# - The script changes into the top dir of cluster-deployment-automation. All path
#   names ($VENV) are relative to that path.

set -e

die() {
    printf '%s\n' "$*"
    exit 1
}

usage() {
    sed -n '3,/^$/ s/^#\( \(.*\)\)\?$/\2/p' "$0"
}

# Parse command line arguments. None are supported, except --help. We always
# print the usage.
if [ "$#" -ge 1 ] ; then
    usage
    for c ; do
        if [ "$c" != "-h" -a "$c" != "--help" -a "$c" != "help" ] ; then
            printf '\n%s\n' "ERROR: No command line arguments supported. Set environment variables."
            exit 2
        fi
    done
    exit 0
fi

do_cmd() {
    local outfile
    local rc

    if [ -z "$BANNER" ] ; then
        local BANNER="$(printf ' %q' "$@")"
        BANNER="${BANNER:1}"
    fi
    printf '%s\n' "RUN:  $BANNER"

    rc=0
    if [ -z "$VERBOSE" ] ; then
        outfile="$(mktemp --tmpdir cda-setup.XXXXXXX)"
        "$@" &> "$outfile" || rc="$?"
    else
        outfile=
        "$@" || rc="$?"
    fi

    if [ "$rc" -eq 0 ] ; then
        return 0
    fi

    if [ -n "$outfile" ] ; then
        cat "$outfile"
        rm -f "$outfile"
    fi
    die "RUN:  Failure to run command \`$(printf '%q ' "$@")\`"
}

BASEDIR="$(dirname "$0")"
cd "$BASEDIR" || die "Could not change into base directory for \"$0\""
test -f "$BASEDIR/cda.py" || die "Base directory for \"$0\" does not look like cluster-deployment-automation source tree"

[ "$EUID" = 0 ] || die "Must run as root user"

_USE_VENV=0
if [ -z "${VENV+x}" -a -n "$VIRTUAL_ENV" ] ; then
    printf '%s\n' "INFO: Use existing VENV=\"$VIRTUAL_ENV\""
elif [ -z "${VENV-x}" ]; then
    printf '%s\n' "INFO: Don't use VENV"
else
    _USE_VENV=1
    if [ -z "$VENV" ] ; then
        VENV=ocp-venv
    fi
    printf '%s\n' "INFO: Use \"$VENV\" virtual environment"
    if [ ! -f "$VENV/bin/activate" ] ; then
        if [ -z "$VENV_PYTHON" ] ; then
            VENV_PYTHON=python3.11
            if ! command -v "$VENV_PYTHON" &>/dev/null ; then
                do_cmd dnf install -y python3.11
            fi
        fi
        do_cmd "$VENV_PYTHON" -m venv "$VENV"
    fi
    source "$VENV/bin/activate"
fi

printf '%s\n' "INFO: python=$(printf '%q' "$(command -v python)")"

do_cmd python -m ensurepip --upgrade
do_cmd python -m pip install --upgrade pip

BANNER="PYTHON_CMD=python ./dependencies.sh" \
PYTHON_CMD=python \
    do_cmd ./dependencies.sh

do_cmd systemctl enable --now libvirtd

do_cmd usermod -a -G root qemu

if [ ! -f ~/.ssh/id_ed25519 ] ; then
    do_cmd ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519
else
    printf 'SKIP: ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519\n'
fi

setup_oc_completion_bash() {
    oc completion bash > /etc/bash_completion.d/oc_bash_completion
}

BANNER="oc completion bash > /etc/bash_completion.d/oc_bash_completion" \
    do_cmd setup_oc_completion_bash

if [ "$_USE_VENV" = 1 ] ; then
    printf '\n'
    printf '%s\n' "INFO: Use virtual environment: source \"$VENV/bin/activate\""
fi
