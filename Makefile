
# Detect OS automatically
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    ARCH ?= linux
else ifeq ($(UNAME_S),Darwin)
    ARCH ?= osx
else
    ARCH ?= linux  # Default fallback for other Unix-like systems
endif

TOPDIR   ?= $(realpath $(CURDIR))
RULESDIR := $(TOPDIR)/rules

include $(RULESDIR)/arch-$(ARCH).mk

CFLAGS_linux    := -I$(SDKINC) -I$(SDKINC_TCPIP) -fPIC
CFLAGS_windows  := -I$(SDKINC) -I$(SDKINC_TCPIP) -I/opt/windows/32/include/libxml2 -static-libgcc -static-libstdc++
CFLAGS_win32    := $(CFLAGS_windows)
CFLAGS_win64    := $(CFLAGS_windows)

CFLAGS += $(CFLAGS_$(ARCH))

LDFLAGS_linux   := -Wl,--export-dynamic -Wl,--whole-archive $(SDKLIB)/libmmt_core.a -Wl,--no-whole-archive
LDFLAGS_windows := -Wl,--whole-archive $(SDKLIB)/libmmt_core.a -Wl,--no-whole-archive
LDFLAGS_win32   := $(LDFLAGS_windows)
LDFLAGS_win64   := $(LDFLAGS_windows)

LDFLAGS += $(LDFLAGS_$(ARCH))

# =============================================================================
# Code Quality Targets
# =============================================================================

.PHONY: lint format format-check test-unit pre-commit

# Static analysis with cppcheck
lint:
	@echo "Running cppcheck on mmt_core..."
	@cppcheck --enable=warning,style,performance \
		--suppress=missingIncludeSystem \
		--suppress=unusedFunction \
		--inline-suppr \
		-I src/mmt_core/public_include \
		-I src/mmt_core/private_include \
		src/mmt_core/src/ 2>&1 || true
	@echo "Running cppcheck on mmt_tcpip..."
	@cppcheck --enable=warning,style,performance \
		--suppress=missingIncludeSystem \
		--suppress=unusedFunction \
		--inline-suppr \
		-I src/mmt_core/public_include \
		-I src/mmt_tcpip/include \
		src/mmt_tcpip/lib/ 2>&1 || true

# Format code with clang-format
format:
	@echo "Formatting C/C++ files..."
	@find src/mmt_core -name "*.c" -o -name "*.h" | xargs clang-format -i --style=file
	@find src/mmt_tcpip -name "*.c" -o -name "*.h" | xargs clang-format -i --style=file
	@echo "Done."

# Check formatting without modifying files
format-check:
	@echo "Checking code formatting..."
	@find src/mmt_core -name "*.c" -o -name "*.h" | xargs clang-format --dry-run --Werror --style=file || \
		(echo "Formatting issues found. Run 'make format' to fix." && exit 1)
	@echo "Formatting OK."

# Run unit tests
test-unit:
	@echo "Running unit tests..."
	@cd test/unit && \
		for test in test_*; do \
			if [ -x "$$test" ] && [ -f "$$test" ]; then \
				echo "Running $$test..."; \
				./$$test || exit 1; \
			fi \
		done
	@echo "All tests passed."

# Install and run pre-commit hooks
pre-commit:
	@command -v pre-commit >/dev/null 2>&1 || (echo "Installing pre-commit..." && pip install pre-commit)
	@pre-commit install
	@pre-commit run --all-files
