#!/usr/bin/env bash
# Install only MailRadar's own files. No packages, service changes or downloads.
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PREFIX=${PREFIX:-/usr/local}
DESTDIR=${DESTDIR:-}

die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
[[ $# -eq 0 ]] || die 'usage: [DESTDIR=/staging] [PREFIX=/usr/local] bash install.sh'
[[ $PREFIX == /* ]] || die 'PREFIX must be an absolute path'
[[ -z $DESTDIR || $DESTDIR == /* ]] || die 'DESTDIR must be empty or an absolute path'
case "/$PREFIX/$DESTDIR/" in
    */../*|*/./*) die 'PREFIX and DESTDIR must not contain dot path components' ;;
esac
command -v python3 >/dev/null 2>&1 || die 'Python 3.9 or newer is required'
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || die 'Python 3.9 or newer is required'
[[ -d $SCRIPT_DIR/mailradar && ! -L $SCRIPT_DIR/mailradar ]] || die 'missing or symlinked package directory'

for source in mail-radar miab-radar mailradar/__init__.py mailradar/cli.py; do
    [[ -f $SCRIPT_DIR/$source && ! -L $SCRIPT_DIR/$source ]] || die "missing or symlinked source: $source"
done

BIN_DIR="${DESTDIR}${PREFIX%/}/bin"
LIB_DIR="${DESTDIR}${PREFIX%/}/lib/mail-radar"

# Refuse symlinks in destination components before creating or replacing files.
check_path() {
    local path=$1 component checked=''
    local -a components
    IFS=/ read -r -a components <<< "$path"
    for component in "${components[@]}"; do
        [[ -n $component ]] || continue
        checked="$checked/$component"
        [[ ! -L $checked ]] || die "refusing symlink destination: $checked"
    done
}

# A timestamp-based .pyc can remain valid after an equal-size source update
# within the same second. Only caches for modules in this installation belong
# to this cleanup; never traverse a cache symlink or remove an unknown tree.
declare -a BYTECODE_FILES=()
collect_bytecode() {
    local module_relative=$1 package_directory bytecode_dir module_name candidate
    package_directory="$LIB_DIR/${module_relative%/*}"
    bytecode_dir="$package_directory/__pycache__"
    module_name=${module_relative##*/}
    module_name=${module_name%.py}
    check_path "$bytecode_dir"
    [[ ! -e $bytecode_dir || -d $bytecode_dir ]] || die "bytecode cache is not a directory: $bytecode_dir"
    for candidate in "$LIB_DIR/${module_relative}c" "$bytecode_dir/$module_name".*.pyc; do
        [[ -e $candidate || -L $candidate ]] || continue
        check_path "$candidate"
        [[ -f $candidate && ! -L $candidate ]] || die "bytecode cache is not a regular file: $candidate"
        BYTECODE_FILES+=("$candidate")
    done
}

check_path "$BIN_DIR"
check_path "$LIB_DIR/mailradar"
for launcher in mail-radar miab-radar; do
    check_path "$BIN_DIR/$launcher"
done

# Collect and validate the complete package before writing installation files.
declare -a MODULES=()
while IFS= read -r -d '' source; do
    [[ ! -L $source ]] || die "refusing symlinked package source: $source"
    relative=${source#"$SCRIPT_DIR/"}
    check_path "$LIB_DIR/$relative"
    collect_bytecode "$relative"
    MODULES+=("$relative")
done < <(find "$SCRIPT_DIR/mailradar" -name '*.py' -print0)
[[ ${#MODULES[@]} -gt 0 ]] || die 'Python package is empty'

umask 022
install -d -m 0755 -- "$BIN_DIR" "$LIB_DIR/mailradar"
for relative in "${MODULES[@]}"; do
    install -d -m 0755 -- "$(dirname -- "$LIB_DIR/$relative")"
    install -m 0644 -- "$SCRIPT_DIR/$relative" "$LIB_DIR/$relative"
done
for launcher in mail-radar miab-radar; do
    install -m 0755 -- "$SCRIPT_DIR/$launcher" "$BIN_DIR/$launcher"
done

# Re-enumerate after copying, including bytecode produced during the install.
BYTECODE_FILES=()
for relative in "${MODULES[@]}"; do
    collect_bytecode "$relative"
done
for bytecode_file in "${BYTECODE_FILES[@]}"; do
    check_path "$bytecode_file"
    [[ -e $bytecode_file || -L $bytecode_file ]] || continue
    [[ -f $bytecode_file && ! -L $bytecode_file ]] || die "bytecode cache changed during installation: $bytecode_file"
    rm -f -- "$bytecode_file"
done
printf 'Installed MailRadar: %s/mail-radar\n' "$BIN_DIR"
printf 'Compatibility command: %s/miab-radar\n' "$BIN_DIR"
