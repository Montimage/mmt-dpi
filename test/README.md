# MMT-DPI Test Infrastructure

This directory contains the test infrastructure for the MMT-DPI security and performance improvements project.

## Directory Structure

```
test/
├── unit/           # Unit tests for specific functions/modules
├── integration/    # Integration tests for complete workflows
├── security/       # Security-specific tests (fuzzing, exploit attempts)
├── performance/    # Performance benchmarks
├── pcap_samples/   # Sample packet captures for testing
├── scripts/        # Test automation scripts
└── README.md       # This file
```

## Quick Start

### Build and Test

Run the baseline build and verification:

```bash
./test/scripts/build_and_test.sh
```

This will:
1. Clean build the entire project
2. Verify all libraries are created
3. Log output to `test/build.log`

### Run Examples

Test with example packet captures:

```bash
./test/scripts/run_tests.sh
```

## Test Scripts

### build_and_test.sh

Performs a clean build and validates that all required libraries are created.

**Usage:**
```bash
cd /home/user/mmt-dpi
./test/scripts/build_and_test.sh
```

**Expected Output:**
```
=== Building MMT-DPI ===
...compilation messages...
=== Build successful ===
✓ libmmt_core library created
✓ libmmt_tcpip library created
=== All libraries built successfully ===
```

### run_tests.sh

Runs example programs as integration tests.

**Usage:**
```bash
./test/scripts/run_tests.sh
```

## Adding Tests

### Unit Tests

Create a new test file in `test/unit/`:

```c
// test/unit/test_my_feature.c
#include <stdio.h>
#include <assert.h>

void test_my_feature() {
    // Test implementation
    assert(1 == 1);
    printf("✓ My feature test passed\n");
}

int main() {
    test_my_feature();
    printf("All tests passed\n");
    return 0;
}
```

Compile and run:
```bash
gcc -o test/unit/test_my_feature test/unit/test_my_feature.c \
    -I src/mmt_core/public_include
./test/unit/test_my_feature
```

### Integration Tests

Integration tests should verify complete workflows:

1. Initialize MMT handler
2. Process packets
3. Extract attributes
4. Verify results
5. Cleanup

### Performance Tests

Performance tests should:

1. Measure baseline performance
2. Apply optimization
3. Measure optimized performance
4. Compare and report improvement

Example benchmark structure:
```c
double baseline = benchmark_baseline();
double optimized = benchmark_optimized();
double improvement = optimized / baseline;
printf("Improvement: %.2fx\n", improvement);
```

## Continuous Integration

For CI/CD integration, use:

```bash
# Full build and test
./test/scripts/build_and_test.sh && ./test/scripts/run_tests.sh

# Check exit code
if [ $? -eq 0 ]; then
    echo "All tests passed"
else
    echo "Tests failed"
    exit 1
fi
```

## Test Data

### PCAP Samples

Sample packet captures should be placed in `test/pcap_samples/`:

- `test/pcap_samples/dns_test.pcap` - DNS protocol tests
- `test/pcap_samples/http_test.pcap` - HTTP protocol tests
- `test/pcap_samples/gtp_test.pcap` - GTP protocol tests
- etc.

The existing sample is available at `src/examples/google-fr.pcap`.

## Validation Criteria

### Build Validation

- [ ] All libraries compile without errors
- [ ] No new compiler warnings
- [ ] Library sizes reasonable (no excessive bloat)

### Functional Validation

- [ ] All examples execute successfully
- [ ] Packet processing completes without crashes
- [ ] Output format is correct

### Security Validation

- [ ] No unsafe functions (sprintf, strcpy, strcat)
- [ ] All buffer accesses are bounds-checked
- [ ] Integer overflows are prevented
- [ ] Recursion depth is limited

### Performance Validation

- [ ] Throughput meets or exceeds baseline
- [ ] Memory usage within acceptable limits
- [ ] No memory leaks (verify with valgrind)
- [ ] CPU usage is reasonable

## Troubleshooting

### Build Failures

Check the build log:
```bash
cat test/build.log | grep -i "error:"
```

### Library Not Found

Ensure LD_LIBRARY_PATH includes the library directory:
```bash
export LD_LIBRARY_PATH=/home/user/mmt-dpi/sdk/lib:$LD_LIBRARY_PATH
```

### Test Failures

Run tests with verbose output:
```bash
bash -x ./test/scripts/run_tests.sh
```

## Contact

For questions about the test infrastructure, refer to:
- Implementation Plan: `IMPLEMENTATION_PLAN.md`
- Analysis Report: `MMT-DPI_COMPREHENSIVE_ANALYSIS_REPORT.md`
