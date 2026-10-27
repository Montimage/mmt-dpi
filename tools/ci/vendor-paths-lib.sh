# shellcheck shell=bash
#
# vendor-paths-lib.sh — the single parser of tools/ci/vendor-paths.txt, the
# list of vendored sources the clean-code metrics exclude. Sourced, not run:
#
#   . "$ROOT/tools/ci/vendor-paths-lib.sh"
#   vendor_paths_load "$VENDOR_LIST" || exit 2
#   for p in "${VENDOR_PATHS[@]}"; do ...; done
#
# VENDOR_LIST is repo-relative: every consumer cd's to the repo root first.
# vendor_paths_load [FILE] fills the global array VENDOR_PATHS with the
# non-blank lines of FILE (default "$VENDOR_LIST") that do not start with #.
# It returns 2, with a message on stderr, when FILE does not exist.

VENDOR_LIST="tools/ci/vendor-paths.txt"
VENDOR_PATHS=()

vendor_paths_load() {
    local file="${1:-$VENDOR_LIST}" p
    VENDOR_PATHS=()
    if [ ! -f "$file" ]; then
        echo "✗ vendored-source list not found: $file" >&2
        return 2
    fi
    while IFS= read -r p || [ -n "$p" ]; do
        case "$p" in ''|'#'*) continue ;; esac
        VENDOR_PATHS+=("$p")
    done < "$file"
}
