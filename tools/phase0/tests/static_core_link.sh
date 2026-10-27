# shellcheck shell=bash
# The *_LDFLAGS arrays below are read by the sourcing script.
# shellcheck disable=SC2034
#
# static_core_link.sh — link a test binary against the static libmmt_core
# (issue #533) or a static protocol plugin (issue #534). Sourced, not run:
#
#   . "$REPO_ROOT/tools/phase0/tests/static_core_link.sh"
#   mmt_static_core_link "$PREFIX/dpi/lib" || exit 2
#   gcc ... -L"$PREFIX/dpi/lib" -lmmt_tcpip "${MMT_STATIC_CORE_LDFLAGS[@]}"
#
# libmmt_core is built with -fvisibility=hidden: libmmt_core.so exports only
# its MMTAPI declarations (scripts/validate-exported-symbols.sh). A test that
# calls a hidden core internal links the archive instead, whole, so every
# object is in the executable whatever the link order. -rdynamic puts the
# executable's default-visibility symbols (the MMTAPI set) in its dynamic
# symbol table, which is where the protocol plugins it dlopen()s, and a
# linked -lmmt_tcpip, resolve the core. Never pass -lmmt_core as well: a
# second core would carry its own copy of every global registry.
#
# mmt_static_core_link LIBDIR fills the global array MMT_STATIC_CORE_LDFLAGS
# with the whole-archive link of LIBDIR/libmmt_core.a, the runtimes the core
# needs (-lstdc++ for hash_utils.cpp, -ldl, -lpthread, -lm) and the flags of
# the profile the archive was built with, read from the runtime symbols its
# objects reference: __asan_ adds -fsanitize=address, __ubsan_
# -fsanitize=undefined, __tsan_ -fsanitize=thread and __gcov_ --coverage. A
# shared core carries those runtimes itself; an executable linking the
# archive has to pull them in. It returns 2, with a message on stderr, when
# the archive is missing.
#
# The protocol plugins are built -fvisibility=hidden too (issue #534): each
# .so exports only init_proto/cleanup_proto and the functions its installed
# headers declare (docs/Exported-Symbols.md). A test that calls a hidden
# plugin internal links that plugin's archive, before the core:
#
#   mmt_static_plugin_link "$PREFIX/dpi/lib" tcpip || exit 2
#   gcc ... "${MMT_STATIC_PLUGIN_LDFLAGS[@]}" -L"$PREFIX/dpi/lib" -lmmt_core
#
# mmt_static_plugin_link LIBDIR NAME... fills the global array
# MMT_STATIC_PLUGIN_LDFLAGS with the whole-archive link of
# LIBDIR/libmmt_NAME.a for each NAME (tcpip, tmobile, business_app, tdicom),
# -Wl,--exclude-libs for that archive, the archive's profile flags (detected
# as above) and -ldl -lpthread -lm. --exclude-libs keeps the archive's
# symbols out of the executable's dynamic symbol table, even under -rdynamic,
# so the plugin the engine dlopen()s from the plugin directory always binds
# to its own copy: the test's direct calls reach the static copy, packet
# processing reaches the plugin's, and neither interposes on the other.
# State a direct call depends on is the static copy's (for example a
# protocol struct its init_proto_*_struct() fills in), so the test
# initialises it through the static copy. It returns 2, with a message on
# stderr, when an archive is missing.

MMT_STATIC_CORE_LDFLAGS=()
MMT_STATIC_PLUGIN_LDFLAGS=()

# _mmt_static_profile_flags ARCHIVE sets _MMT_STATIC_PROFILE_FLAGS to the
# sanitizer/coverage flags of the profile ARCHIVE was built with.
_MMT_STATIC_PROFILE_FLAGS=()
_mmt_static_profile_flags() {
    local syms
    _MMT_STATIC_PROFILE_FLAGS=()
    # nm may warn about members it cannot read (LTO objects without the
    # linker plugin); only the undefined runtime symbols matter here, and an
    # LTO archive is a release build, which references none.
    syms="$(nm --undefined-only "${1}" 2>/dev/null || true)"
    case "${syms}" in *__asan_*)  _MMT_STATIC_PROFILE_FLAGS+=(-fsanitize=address) ;; esac
    case "${syms}" in *__ubsan_*) _MMT_STATIC_PROFILE_FLAGS+=(-fsanitize=undefined) ;; esac
    case "${syms}" in *__tsan_*)  _MMT_STATIC_PROFILE_FLAGS+=(-fsanitize=thread) ;; esac
    case "${syms}" in *__gcov_*)  _MMT_STATIC_PROFILE_FLAGS+=(--coverage) ;; esac
    return 0
}

mmt_static_core_link() {
    local libdir="${1:?mmt_static_core_link needs the SDK library directory}"
    local archive="${libdir}/libmmt_core.a"
    MMT_STATIC_CORE_LDFLAGS=()
    if [ ! -f "${archive}" ]; then
        echo "✗ static core archive not found: ${archive}" >&2
        return 2
    fi
    _mmt_static_profile_flags "${archive}"
    MMT_STATIC_CORE_LDFLAGS=("-Wl,--whole-archive" "${archive}" "-Wl,--no-whole-archive"
                             -rdynamic -lstdc++ -ldl -lpthread -lm
                             ${_MMT_STATIC_PROFILE_FLAGS[@]+"${_MMT_STATIC_PROFILE_FLAGS[@]}"})
    return 0
}

mmt_static_plugin_link() {
    local libdir="${1:?mmt_static_plugin_link needs the SDK library directory}"
    local name archive
    shift
    MMT_STATIC_PLUGIN_LDFLAGS=()
    if [ "$#" -eq 0 ]; then
        echo "✗ mmt_static_plugin_link needs a plugin name (tcpip, tmobile, business_app, tdicom)" >&2
        return 2
    fi
    for name in "$@"; do
        archive="${libdir}/libmmt_${name}.a"
        if [ ! -f "${archive}" ]; then
            echo "✗ static plugin archive not found: ${archive}" >&2
            MMT_STATIC_PLUGIN_LDFLAGS=()
            return 2
        fi
        _mmt_static_profile_flags "${archive}"
        MMT_STATIC_PLUGIN_LDFLAGS+=("-Wl,--whole-archive" "${archive}" "-Wl,--no-whole-archive"
                                    "-Wl,--exclude-libs,libmmt_${name}.a"
                                    ${_MMT_STATIC_PROFILE_FLAGS[@]+"${_MMT_STATIC_PROFILE_FLAGS[@]}"})
    done
    MMT_STATIC_PLUGIN_LDFLAGS+=(-ldl -lpthread -lm)
    return 0
}
