/*
 * fi_plugin.c — stub protocol plugins for the plugin-init failure cases of
 * the fault_injection suite (issue #503, F-BUG-006).
 *
 * Built twice by run_tests.sh:
 *   default            init_proto() fails (returns 0);
 *   -DFI_NO_INIT_PROTO  the plugin exports no init_proto() at all.
 * Either one in the plugin directory must make init_extraction() fail.
 */
#ifndef FI_NO_INIT_PROTO
int init_proto(void) { return 0; }
#endif
int cleanup_proto(void) { return 0; }
