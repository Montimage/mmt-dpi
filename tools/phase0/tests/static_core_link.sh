# shellcheck shell=bash
#
# static_core_link.sh — link a test binary against the static libmmt_core
# (issue #533). Sourced, not run:
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

MMT_STATIC_CORE_LDFLAGS=()

mmt_static_core_link() {
    local libdir="${1:?mmt_static_core_link needs the SDK library directory}"
    local archive="${libdir}/libmmt_core.a" syms
    MMT_STATIC_CORE_LDFLAGS=()
    if [ ! -f "${archive}" ]; then
        echo "✗ static core archive not found: ${archive}" >&2
        return 2
    fi
    # nm may warn about members it cannot read (LTO objects without the
    # linker plugin); only the undefined runtime symbols matter here, and an
    # LTO archive is a release build, which references none.
    syms="$(nm --undefined-only "${archive}" 2>/dev/null || true)"
    MMT_STATIC_CORE_LDFLAGS=("-Wl,--whole-archive" "${archive}" "-Wl,--no-whole-archive"
                             -rdynamic -lstdc++ -ldl -lpthread -lm)
    case "${syms}" in *__asan_*)  MMT_STATIC_CORE_LDFLAGS+=(-fsanitize=address) ;; esac
    case "${syms}" in *__ubsan_*) MMT_STATIC_CORE_LDFLAGS+=(-fsanitize=undefined) ;; esac
    case "${syms}" in *__tsan_*)  MMT_STATIC_CORE_LDFLAGS+=(-fsanitize=thread) ;; esac
    case "${syms}" in *__gcov_*)  MMT_STATIC_CORE_LDFLAGS+=(--coverage) ;; esac
    return 0
}
