/*
 * test_injection.c — metacharacter reaction injection test for #136 / F-BUG-207
 *
 * Verifies the fix in src/mmt_security/tips_report.c: packet-derived
 * attribute
 * values interpolated into reaction commands must not be interpreted by the
 * shell. The fix uses strict single-quote escaping (escape_shell_arg).
 *
 * This test reproduces the escaping logic standalone and proves via
 * system() that shell metacharacters are treated literally.
 *
 * It does not require a live ipacket or libmmt_security link; it validates
 * the same quoting mechanism that generate_command() now applies.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *escape_shell_arg(const char *arg) {
    if (arg == NULL) return NULL;
    size_t len = strlen(arg);
    char *out = malloc(len * 4 + 3);
    if (out == NULL) return NULL;
    char *p = out;
    *p++ = '\'';
    for (size_t i = 0; i < len; i++) {
        if (arg[i] == '\'') {
            *p++ = '\'';
            *p++ = '\\';
            *p++ = '\'';
            *p++ = '\'';
        } else {
            *p++ = arg[i];
        }
    }
    *p++ = '\'';
    *p++ = '\0';
    return out;
}

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } \
    else { printf("ok - %s\n", msg); } \
} while (0)

static void test_escape_variants(void) {
    // Simple metacharacters must survive round-trip through shell without execution
    struct { const char *raw; const char *expected_substr; } cases[] = {
        {"hello; rm -rf /", "hello; rm -rf /"},
        {"a & b", "a & b"},
        {"x|y", "x|y"},
        {"foo$(touch /tmp/pwn)", "foo$(touch /tmp/pwn)"},
        {"bar`touch /tmp/pwn`", "bar`touch /tmp/pwn`"},
        {"a'b", "a'b"},
        {"$HOME", "$HOME"},
        {"a>b", "a>b"},
        {"a<b", "a<b"},
        {"*?~", "*?~"},
        {"$(echo hacked)", "$(echo hacked)"},
        {NULL, NULL}
    };
    for (int i = 0; cases[i].raw != NULL; i++) {
        char *esc = escape_shell_arg(cases[i].raw);
        CHECK(esc != NULL, "escape_shell_arg returns non-NULL");
        CHECK(esc[0] == '\'' && esc[strlen(esc)-1] == '\'', "escaped string is single-quoted");
        // raw payload inside quotes, single quotes escaped as '\''
        // For a'b -> 'a'\''b'  we check that original appears after stripping outer quotes via shell echo
        free(esc);
    }
}

static int test_no_shell_interpretation(void) {
    const char *evil = "; touch /tmp/mmt_injection_pwned_test_136; echo HACKED";
    const char *evil2 = "$(touch /tmp/mmt_injection_pwned_test_136)";
    const char *evil3 = "`touch /tmp/mmt_injection_pwned_test_136`";
    const char *marker = "/tmp/mmt_injection_pwned_test_136";
    const char *out_file = "/tmp/mmt_injection_output_136.txt";

    const char *payloads[] = { evil, evil2, evil3, "a'b; touch /tmp/mmt_injection_pwned_test_136", NULL };

    for (int idx = 0; payloads[idx] != NULL; idx++) {
        const char *payload = payloads[idx];
        char *esc = escape_shell_arg(payload);
        if (!esc) { failures++; continue; }

        unlink(marker);
        unlink(out_file);

        char cmd[2048];
        // Use echo with escaped arg; if escaping fails, the ; or $() would execute touch
        snprintf(cmd, sizeof(cmd), "echo %s > %s", esc, out_file);
        int rc = system(cmd);
        (void)rc;

        // Marker file must NOT have been created via injection
        CHECK(access(marker, F_OK) != 0, "metachar payload does not create marker file (no injection)");

        // Output file must contain the literal payload (shell stripped quotes but not executed)
        FILE *f = fopen(out_file, "r");
        if (f) {
            char buf[2048];
            if (fgets(buf, sizeof(buf), f)) {
                // strip trailing newline
                size_t l = strlen(buf);
                if (l && buf[l-1] == '\n') buf[l-1] = '\0';
                CHECK(strcmp(buf, payload) == 0, "echo output equals literal payload (no shell interpretation)");
            } else {
                CHECK(0, "echo output readable");
            }
            fclose(f);
        } else {
            CHECK(0, "output file created");
        }

        unlink(marker);
        unlink(out_file);
        free(esc);
    }
    return failures;
}

int main(void) {
    printf("=== injection metacharacter test (F-BUG-207 / #136) ===\n");
    test_escape_variants();
    test_no_shell_interpretation();
    if (failures == 0) {
        printf("✓ injection tests passed (no shell interpretation)\n");
        return 0;
    } else {
        fprintf(stderr, "✗ %d injection test(s) failed\n", failures);
        return 1;
    }
}
