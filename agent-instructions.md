# MMT-DPI Installation Agent Instructions

This document provides comprehensive instructions for an AI agent to perform a complete, from-scratch installation and setup of the MMT-DPI (Montimage Deep Packet Inspection) project. The agent must follow a three-phase execution model with explicit user approval gates between phases.

---

## Table of Contents

1. [Overview](#overview)
2. [Phase 1: Research](#phase-1-research)
3. [Phase 2: Plan](#phase-2-plan)
4. [Phase 3: Execute](#phase-3-execute)
5. [Appendix: Project Reference](#appendix-project-reference)

---

## Overview

**Project**: MMT-DPI (Montimage Deep Packet Inspection)
**Type**: C library for network packet analysis and deep packet inspection
**License**: Apache License 2.0
**Repository**: https://github.com/montimage/mmt-dpi

### Critical Execution Rules

1. **NEVER proceed to the next phase without explicit user approval**
2. **STOP immediately on any failure and report to user**
3. **Request permission before any system-modifying operation**
4. **Document all findings, plans, and execution results**

---

## Phase 1: Research

### Objective

Collect all necessary information about installation and setup requirements before creating a plan.

### 1.1 Information Gathering Tasks

Execute the following tasks to gather project information:

#### Task 1.1.1: Detect Operating System and Environment

```bash
# Determine OS type
uname -s

# Get detailed OS information
cat /etc/os-release 2>/dev/null || sw_vers 2>/dev/null || ver 2>/dev/null

# Check architecture
uname -m

# Check available memory
free -h 2>/dev/null || vm_stat 2>/dev/null

# Check disk space
df -h .
```

**Expected Outputs to Record**:
- Operating System: Linux (Ubuntu/Debian/RHEL/CentOS), macOS, or Windows
- Architecture: x86_64, arm64, i686
- Available memory and disk space

#### Task 1.1.2: Check Compiler Availability

```bash
# Check GCC version
gcc --version 2>/dev/null

# Check G++ version
g++ --version 2>/dev/null

# Check Clang version
clang --version 2>/dev/null

# Check Make version
make --version 2>/dev/null

# Check Git version
git --version 2>/dev/null
```

**Compiler Requirements**:
- GCC 4.9 through 9.x (NOT 10 or newer due to compatibility issues)
- Alternative: Clang or Intel ICC
- GNU Make 3.81 or newer
- Git for version control

#### Task 1.1.3: Check Existing Dependencies

```bash
# Check libxml2
pkg-config --modversion libxml-2.0 2>/dev/null || xml2-config --version 2>/dev/null

# Check libpcap
pkg-config --modversion libpcap 2>/dev/null || pcap-config --version 2>/dev/null

# Check if development headers are installed
ls /usr/include/libxml2/libxml/parser.h 2>/dev/null
ls /usr/include/pcap/pcap.h 2>/dev/null
```

#### Task 1.1.4: Analyze Project Structure

Read and analyze the following files:
- `README.md` - Project overview
- `docs/Compilation-and-Installation-Instructions.md` - Detailed setup guide
- `sdk/Makefile` - Main build file
- `rules/common.mk` - Build configuration
- `rules/project.mk` - Project settings
- `.github/workflows/c-cpp.yml` - CI/CD configuration

**Key Information to Extract**:
- Required dependencies
- Build process steps
- Installation paths
- Optional features
- Platform-specific requirements

#### Task 1.1.5: Check for Existing Installation

```bash
# Check if MMT-DPI is already installed
ls -la /opt/mmt/dpi/ 2>/dev/null

# Check for library configuration
cat /etc/ld.so.conf.d/mmt-dpi.conf 2>/dev/null

# Check if libraries are loadable
ldconfig -p | grep mmt 2>/dev/null
```

### 1.2 Ambiguity Resolution

Identify and document any items requiring user clarification:

| Question | Default | Options |
|----------|---------|---------|
| Installation path | `/opt/mmt` | Custom path possible |
| Enable security features? | No | `ENABLESEC=1` for security/fuzzing |
| Enable debug symbols? | No | `DEBUG=1` for debugging |
| Target architecture | Auto-detect | `linux`, `osx`, `win32`, `win64` |
| Compiler preference | GCC | GCC, Clang, ICC |
| Install examples? | Yes | Can be skipped |
| Use sudo for installation? | Yes | Required for `/opt/mmt` |

### 1.3 Research Documentation

Create a file named `research.md` with the following structure:

```markdown
# MMT-DPI Installation Research

## Date: [CURRENT_DATE]

## 1. System Information

| Property | Value |
|----------|-------|
| Operating System | [detected] |
| Architecture | [detected] |
| Kernel Version | [detected] |
| Available Memory | [detected] |
| Available Disk Space | [detected] |

## 2. Compiler Status

| Compiler | Version | Status |
|----------|---------|--------|
| GCC | [version] | [OK/MISSING/INCOMPATIBLE] |
| G++ | [version] | [OK/MISSING/INCOMPATIBLE] |
| Make | [version] | [OK/MISSING] |
| Git | [version] | [OK/MISSING] |

## 3. Dependency Status

| Dependency | Required | Status | Installation Command |
|------------|----------|--------|---------------------|
| libxml2-dev | YES | [OK/MISSING] | [command] |
| libpcap-dev | For examples | [OK/MISSING] | [command] |
| build-essential | YES | [OK/MISSING] | [command] |

## 4. Existing Installation

- Previous installation detected: [YES/NO]
- Installation path: [path or N/A]
- Library configuration: [configured/not configured]

## 5. Questions for User

1. [List any questions requiring clarification]
2. [Include default recommendation for each]

## 6. Recommendations

- [List recommended installation approach]
- [Note any potential issues]
- [Suggest optimal configuration]
```

### 1.4 User Verification Gate

**Present to User**:

```
=== PHASE 1 COMPLETE: Research Summary ===

System: [OS] [ARCH]
Compiler: [GCC/Clang version]
Dependencies Missing: [list or "None"]
Existing Installation: [Yes/No]

Detailed findings have been documented in: research.md

Questions requiring your input:
1. [Question 1 with default]
2. [Question 2 with default]

Please review research.md and respond with:
- "APPROVED" to proceed to Phase 2 (Planning)
- "MODIFY [instructions]" to adjust the approach
- "ABORT" to cancel installation

>>> WAITING FOR USER APPROVAL <<<
```

**DO NOT PROCEED TO PHASE 2 UNTIL USER EXPLICITLY APPROVES**

---

## Phase 2: Plan

### Objective

Create a comprehensive, detailed installation plan with success criteria and verification methods.

### 2.1 Task Breakdown

Create numbered tasks based on the research phase findings. The following is the complete task template:

#### Standard Installation Tasks (Linux/Ubuntu/Debian)

| # | Task | Success Criterion | Verification Command | Risk Level |
|---|------|-------------------|---------------------|------------|
| 1 | Update package manager | Package lists updated | `apt-get update exit code 0` | LOW |
| 2 | Install build-essential | GCC, G++, Make available | `gcc --version && g++ --version && make --version` | LOW |
| 3 | Install libxml2-dev | libxml2 headers present | `ls /usr/include/libxml2/libxml/parser.h` | LOW |
| 4 | Install libpcap-dev | libpcap headers present | `ls /usr/include/pcap/pcap.h` | LOW |
| 5 | Clone/verify repository | Source code present | `ls sdk/Makefile` | LOW |
| 6 | Build SDK | Libraries compiled | `ls sdk/*.so 2>/dev/null \|\| ls src/*/*.so` | MEDIUM |
| 7 | Install libraries | Files in /opt/mmt | `ls /opt/mmt/dpi/lib/libmmt_core.so` | HIGH |
| 8 | Configure library path | Library path registered | `cat /etc/ld.so.conf.d/mmt-dpi.conf` | HIGH |
| 9 | Run ldconfig | Libraries discoverable | `ldconfig -p \| grep mmt_core` | HIGH |
| 10 | Verify installation | Example compiles and runs | `compile and run proto_attributes_iterator` | MEDIUM |

#### Standard Installation Tasks (macOS)

| # | Task | Success Criterion | Verification Command | Risk Level |
|---|------|-------------------|---------------------|------------|
| 1 | Install Xcode CLI tools | Developer tools present | `xcode-select -p` | LOW |
| 2 | Install Homebrew (if needed) | brew available | `brew --version` | LOW |
| 3 | Install libxml2 | libxml2 available | `brew list libxml2` | LOW |
| 4 | Install libpcap | libpcap available | `brew list libpcap` | LOW |
| 5 | Clone/verify repository | Source code present | `ls sdk/Makefile` | LOW |
| 6 | Build SDK (ARCH=osx) | Libraries compiled | `ls sdk/*.dylib 2>/dev/null` | MEDIUM |
| 7 | Install libraries | Files in /opt/mmt | `ls /opt/mmt/dpi/lib/` | HIGH |
| 8 | Update DYLD_LIBRARY_PATH | Environment configured | `echo $DYLD_LIBRARY_PATH` | MEDIUM |
| 9 | Verify installation | Example compiles and runs | `compile and run proto_attributes_iterator` | MEDIUM |

### 2.2 Detailed Task Specifications

For each task, provide the following specification:

```yaml
Task: [NUMBER] - [NAME]
Description: [Detailed description of what this task does]
Prerequisites: [List of tasks that must complete first]
Risk Level: [LOW/MEDIUM/HIGH]
Requires Permission: [YES for HIGH risk, NO otherwise]

Commands:
  - [command 1]
  - [command 2]

Success Criterion: [What constitutes success]
Verification Method: [Command to verify success]
Expected Output: [What the verification should show]

Rollback Strategy:
  - [How to undo this task if needed]

Potential Errors:
  - [Error 1]: [Resolution]
  - [Error 2]: [Resolution]
```

### 2.3 Complete Task Specifications

#### Task 1: Update Package Manager (Linux)

```yaml
Task: 1 - Update Package Manager
Description: Update system package lists to ensure latest versions are available
Prerequisites: None
Risk Level: LOW
Requires Permission: NO

Commands:
  - sudo apt-get update

Success Criterion: Package lists updated without errors
Verification Method: echo $?
Expected Output: 0

Rollback Strategy:
  - No rollback needed; safe operation

Potential Errors:
  - "Could not get lock": Wait for other package operations or kill stale locks
  - "Failed to fetch": Check internet connection
```

#### Task 2: Install Build Essential

```yaml
Task: 2 - Install Build Essential
Description: Install GCC, G++, Make, and standard build tools
Prerequisites: Task 1
Risk Level: LOW
Requires Permission: NO

Commands:
  - sudo apt-get install -y build-essential git cmake

Success Criterion: All tools installed and accessible
Verification Method: gcc --version && g++ --version && make --version && git --version
Expected Output: Version information for all tools

Rollback Strategy:
  - sudo apt-get remove build-essential git cmake

Potential Errors:
  - "Package not found": Update package lists again
  - "Dependency problems": Run apt-get -f install
```

#### Task 3: Install libxml2-dev

```yaml
Task: 3 - Install libxml2-dev
Description: Install XML parsing library (MANDATORY dependency)
Prerequisites: Task 1
Risk Level: LOW
Requires Permission: NO

Commands:
  - sudo apt-get install -y libxml2-dev

Success Criterion: libxml2 development headers installed
Verification Method: ls /usr/include/libxml2/libxml/parser.h && pkg-config --modversion libxml-2.0
Expected Output: File exists and version number displayed

Rollback Strategy:
  - sudo apt-get remove libxml2-dev

Potential Errors:
  - "Unable to locate package": Check package name (may be libxml2-devel on RHEL)
```

#### Task 4: Install libpcap-dev

```yaml
Task: 4 - Install libpcap-dev
Description: Install packet capture library (required for examples)
Prerequisites: Task 1
Risk Level: LOW
Requires Permission: NO

Commands:
  - sudo apt-get install -y libpcap-dev

Success Criterion: libpcap development headers installed
Verification Method: ls /usr/include/pcap/pcap.h
Expected Output: File exists

Rollback Strategy:
  - sudo apt-get remove libpcap-dev

Potential Errors:
  - "Unable to locate package": Check package name (may be libpcap-devel on RHEL)
```

#### Task 5: Verify Repository

```yaml
Task: 5 - Verify Repository
Description: Ensure source code is present and up-to-date
Prerequisites: Task 2 (git required)
Risk Level: LOW
Requires Permission: NO

Commands:
  - cd /path/to/mmt-dpi
  - git status
  - git log -1 --oneline

Success Criterion: Repository is valid and contains expected files
Verification Method: ls sdk/Makefile && ls src/mmt_core/public_include/mmt_core.h
Expected Output: Both files exist

Rollback Strategy:
  - git reset --hard origin/master (if needed)

Potential Errors:
  - "Not a git repository": Clone repository first
  - "Working tree has changes": Stash or commit changes
```

#### Task 6: Build SDK

```yaml
Task: 6 - Build SDK
Description: Compile all MMT-DPI libraries
Prerequisites: Tasks 2, 3, 4, 5
Risk Level: MEDIUM
Requires Permission: NO

Commands:
  - cd sdk
  - make clean
  - make -j$(nproc)

Success Criterion: All libraries compiled without errors
Verification Method: |
  ls ../src/mmt_core/src/libmmt_core.so && \
  ls ../src/mmt_tcpip/lib/libmmt_tcpip.so && \
  echo "Build successful"
Expected Output: Library files exist, "Build successful"

Rollback Strategy:
  - make clean

Potential Errors:
  - "fatal error: libxml/parser.h: No such file": Install libxml2-dev
  - "undefined reference": Check linker flags and dependencies
  - GCC 10+ errors: Use GCC 9 or earlier, or add -fcommon flag
```

#### Task 7: Install Libraries

```yaml
Task: 7 - Install Libraries
Description: Install compiled libraries to system path
Prerequisites: Task 6
Risk Level: HIGH
Requires Permission: YES

Commands:
  - cd sdk
  - sudo make install

Success Criterion: Libraries installed to /opt/mmt/dpi
Verification Method: |
  ls /opt/mmt/dpi/lib/libmmt_core.so && \
  ls /opt/mmt/dpi/include/mmt_core.h && \
  echo "Installation successful"
Expected Output: Files exist, "Installation successful"

Rollback Strategy:
  - sudo make dist-clean
  - OR: sudo rm -rf /opt/mmt

Potential Errors:
  - "Permission denied": Use sudo
  - "Directory not empty": Previous installation exists; clean first
```

#### Task 8: Configure Library Path

```yaml
Task: 8 - Configure Library Path
Description: Add MMT-DPI library path to system library search path
Prerequisites: Task 7
Risk Level: HIGH
Requires Permission: YES

Commands:
  - echo "/opt/mmt/dpi/lib" | sudo tee /etc/ld.so.conf.d/mmt-dpi.conf

Success Criterion: Library path configuration file created
Verification Method: cat /etc/ld.so.conf.d/mmt-dpi.conf
Expected Output: /opt/mmt/dpi/lib

Rollback Strategy:
  - sudo rm /etc/ld.so.conf.d/mmt-dpi.conf

Potential Errors:
  - "Permission denied": Use sudo
  - "Directory does not exist": Create /etc/ld.so.conf.d/
```

#### Task 9: Run ldconfig

```yaml
Task: 9 - Run ldconfig
Description: Update shared library cache
Prerequisites: Task 8
Risk Level: HIGH
Requires Permission: YES

Commands:
  - sudo ldconfig

Success Criterion: MMT libraries discoverable by system
Verification Method: ldconfig -p | grep libmmt
Expected Output: List of libmmt_*.so libraries

Rollback Strategy:
  - Remove configuration and run ldconfig again

Potential Errors:
  - "ldconfig: Can't create temporary cache file": Permission issue
```

#### Task 10: Verify Installation

```yaml
Task: 10 - Verify Installation
Description: Compile and run example to verify working installation
Prerequisites: Task 9
Risk Level: MEDIUM
Requires Permission: NO

Commands:
  - cd src/examples
  - gcc -o proto_attributes_iterator proto_attributes_iterator.c \
        -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib \
        -lmmt_core -ldl
  - ./proto_attributes_iterator

Success Criterion: Example compiles and lists available protocols
Verification Method: ./proto_attributes_iterator | head -20
Expected Output: List of protocols and attributes

Rollback Strategy:
  - rm proto_attributes_iterator

Potential Errors:
  - "cannot find -lmmt_core": Library path not configured; check ldconfig
  - "error while loading shared libraries": Run ldconfig or set LD_LIBRARY_PATH
```

### 2.4 Permission Gates Summary

The following tasks require explicit user permission before execution:

| Task | Operation | Reason |
|------|-----------|--------|
| 7 | Install Libraries | Writes to system directories (/opt/mmt) |
| 8 | Configure Library Path | Modifies system configuration (/etc/ld.so.conf.d/) |
| 9 | Run ldconfig | Updates system library cache |

### 2.5 Manual Input Requirements

Document any values that require user input:

| Input | Default | Required | Description |
|-------|---------|----------|-------------|
| Installation Path | `/opt/mmt` | No | Where to install libraries |
| Architecture | Auto-detect | No | Target architecture (linux/osx/win32/win64) |
| Security Features | Disabled | No | Set ENABLESEC=1 to enable |
| Debug Mode | Disabled | No | Set DEBUG=1 to enable |

### 2.6 Plan Documentation

Create a file named `plan.md` with the following structure:

```markdown
# MMT-DPI Installation Plan

## Date: [CURRENT_DATE]
## Based on Research: research.md

## Configuration

| Setting | Value |
|---------|-------|
| Installation Path | [/opt/mmt or custom] |
| Architecture | [linux/osx/win32/win64] |
| Security Features | [Enabled/Disabled] |
| Debug Mode | [Enabled/Disabled] |

## Task Sequence

[Include all tasks with full specifications]

## Permission Gates

[List of tasks requiring explicit permission]

## Manual Inputs Required

[List of inputs needed from user]

## Estimated Steps

- Total Tasks: [number]
- Tasks Requiring Permission: [number]
- Manual Inputs: [number]

## Risk Assessment

[Summary of high-risk operations and mitigation strategies]
```

### 2.7 User Verification Gate

**Present to User**:

```
=== PHASE 2 COMPLETE: Installation Plan Summary ===

Configuration:
- Installation Path: [path]
- Architecture: [arch]
- Optional Features: [list]

Total Tasks: [N]
Tasks Requiring Your Permission: [M]

Key Milestones:
1. Dependencies installation (Tasks 1-4)
2. Build compilation (Task 6)
3. System installation (Tasks 7-9) [REQUIRES PERMISSION]
4. Verification (Task 10)

High-Risk Operations:
- Task 7: Writing to /opt/mmt (system directory)
- Task 8: Modifying /etc/ld.so.conf.d/
- Task 9: Updating system library cache

Detailed plan has been documented in: plan.md

Please review plan.md and respond with:
- "APPROVED" to proceed to Phase 3 (Execution)
- "MODIFY [instructions]" to adjust the plan
- "ABORT" to cancel installation

>>> WAITING FOR USER APPROVAL <<<
```

**DO NOT PROCEED TO PHASE 3 UNTIL USER EXPLICITLY APPROVES**

---

## Phase 3: Execute

### Objective

Execute all planned tasks with verification and error handling.

### 3.1 Pre-Execution Checklist

Before starting execution, verify:

- [ ] Research phase completed and approved
- [ ] Plan phase completed and approved
- [ ] All manual inputs collected
- [ ] Permission gates understood
- [ ] User is available for approval requests

**Present to User**:

```
=== PHASE 3: Execution Pre-Check ===

Ready to execute [N] installation tasks.

The following will require your approval during execution:
[List of HIGH risk tasks]

Manual inputs needed:
[List of inputs or "None"]

Type "START" to begin execution or "ABORT" to cancel.

>>> WAITING FOR USER CONFIRMATION <<<
```

### 3.2 Sequential Execution Protocol

For each task in the plan, follow this exact sequence:

```
1. ANNOUNCE the task:
   "Executing Task [N]: [Name]"
   "Success Criterion: [criterion]"

2. CHECK if task requires permission:
   If HIGH risk:
     "This task requires your permission."
     "Command: [command]"
     "Type 'PROCEED' to execute or 'SKIP' to skip."
     >>> WAIT FOR USER RESPONSE <<<

3. EXECUTE the task:
   Run the specified commands

4. VERIFY success:
   Run the verification command
   Compare output to expected result

5. REPORT result:
   If SUCCESS:
     "Task [N] COMPLETED successfully."
     [Show verification output]
   If FAILURE:
     "Task [N] FAILED."
     [Show error details]
     >>> STOP EXECUTION <<<
     [Ask user for decision]

6. PROCEED to next task only if current task succeeded
```

### 3.3 Error Handling Protocol

When a task fails, follow this exact sequence:

```
=== EXECUTION HALTED ===

Task [N] ([Name]) failed verification.

Command executed:
[command]

Expected output:
[expected]

Actual output:
[actual]

Error details:
[error message if any]

Possible causes:
1. [cause 1]
2. [cause 2]

Recommended actions:
1. [action 1]
2. [action 2]

Please choose:
- "RETRY" - Attempt the task again
- "RETRY WITH [modifications]" - Retry with changes
- "SKIP" - Skip this task and continue
- "ABORT" - Stop installation completely

>>> WAITING FOR USER DECISION <<<
```

**NEVER proceed past a failed task without explicit user approval**

### 3.4 Execution Commands Reference

#### Linux (Ubuntu/Debian) Commands

```bash
# Task 1: Update package manager
sudo apt-get update

# Task 2: Install build tools
sudo apt-get install -y build-essential git cmake

# Task 3: Install libxml2-dev
sudo apt-get install -y libxml2-dev

# Task 4: Install libpcap-dev
sudo apt-get install -y libpcap-dev

# Task 5: Verify repository
cd /path/to/mmt-dpi
ls sdk/Makefile

# Task 6: Build SDK
cd sdk
make clean
make -j$(nproc)

# Task 7: Install (REQUIRES PERMISSION)
cd sdk
sudo make install

# Task 8: Configure library path (REQUIRES PERMISSION)
echo "/opt/mmt/dpi/lib" | sudo tee /etc/ld.so.conf.d/mmt-dpi.conf

# Task 9: Update library cache (REQUIRES PERMISSION)
sudo ldconfig

# Task 10: Verify installation
gcc -o /tmp/test_mmt src/examples/proto_attributes_iterator.c \
    -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib \
    -lmmt_core -ldl
/tmp/test_mmt
```

#### Linux (RHEL/CentOS/Fedora) Commands

```bash
# Task 1: Update package manager
sudo yum update -y
# OR for newer versions:
sudo dnf update -y

# Task 2: Install build tools
sudo yum groupinstall -y "Development Tools"
sudo yum install -y git cmake
# OR:
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y git cmake

# Task 3: Install libxml2-dev
sudo yum install -y libxml2-devel
# OR:
sudo dnf install -y libxml2-devel

# Task 4: Install libpcap-dev
sudo yum install -y libpcap-devel
# OR:
sudo dnf install -y libpcap-devel

# Tasks 5-10: Same as Ubuntu
```

#### macOS Commands

```bash
# Task 1: Install Xcode CLI tools
xcode-select --install

# Task 2: Install Homebrew (if not present)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Task 3: Install libxml2
brew install libxml2

# Task 4: Install libpcap
brew install libpcap

# Task 5: Verify repository
cd /path/to/mmt-dpi
ls sdk/Makefile

# Task 6: Build SDK (with OSX architecture)
cd sdk
make clean
make ARCH=osx -j$(sysctl -n hw.ncpu)

# Task 7: Install (REQUIRES PERMISSION)
cd sdk
sudo make install

# Task 8: Configure library path
# macOS uses DYLD_LIBRARY_PATH instead of ldconfig
export DYLD_LIBRARY_PATH=/opt/mmt/dpi/lib:$DYLD_LIBRARY_PATH
# Add to ~/.zshrc or ~/.bash_profile for persistence
echo 'export DYLD_LIBRARY_PATH=/opt/mmt/dpi/lib:$DYLD_LIBRARY_PATH' >> ~/.zshrc

# Task 9: Skip ldconfig (not applicable on macOS)

# Task 10: Verify installation
gcc -o /tmp/test_mmt src/examples/proto_attributes_iterator.c \
    -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib \
    -lmmt_core -ldl
/tmp/test_mmt
```

### 3.5 Verification Commands Summary

| Task | Verification Command | Expected Result |
|------|---------------------|-----------------|
| 1 | `echo $?` | 0 |
| 2 | `gcc --version` | Version displayed |
| 3 | `pkg-config --modversion libxml-2.0` | Version number |
| 4 | `ls /usr/include/pcap/pcap.h` | File exists |
| 5 | `ls sdk/Makefile` | File exists |
| 6 | `ls src/mmt_core/src/libmmt_core.so` | File exists |
| 7 | `ls /opt/mmt/dpi/lib/libmmt_core.so` | File exists |
| 8 | `cat /etc/ld.so.conf.d/mmt-dpi.conf` | Contains path |
| 9 | `ldconfig -p \| grep mmt_core` | Library listed |
| 10 | `./test_mmt \| head -5` | Protocol list |

### 3.6 Completion Report

After all tasks complete, generate a completion report:

```markdown
# MMT-DPI Installation Completion Report

## Date: [CURRENT_DATE]

## Summary

| Metric | Value |
|--------|-------|
| Total Tasks | [N] |
| Completed | [X] |
| Skipped | [Y] |
| Failed | [Z] |
| Overall Status | [SUCCESS/PARTIAL/FAILED] |

## Task Results

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Update Package Manager | [COMPLETED/SKIPPED/FAILED] | |
| 2 | Install Build Tools | [COMPLETED/SKIPPED/FAILED] | |
| ... | ... | ... | ... |

## Installation Paths

| Component | Path |
|-----------|------|
| Libraries | /opt/mmt/dpi/lib/ |
| Headers | /opt/mmt/dpi/include/ |
| Examples | /opt/mmt/examples/ |
| Plugins | /opt/mmt/plugins/ |

## Verification Results

[Output of final verification test]

## Next Steps

1. **Using the library**: Include headers from /opt/mmt/dpi/include/
2. **Linking**: Use -L/opt/mmt/dpi/lib -lmmt_core -lmmt_tcpip
3. **Examples**: See src/examples/ for usage patterns
4. **Documentation**: See docs/ for detailed API reference

## Known Issues

[List any issues encountered during installation]

## Manual Tasks Remaining

[List any tasks that require manual user action, documented in human_tasks.md]
```

### 3.7 Human Tasks Documentation

If any tasks cannot be automated, create `human_tasks.md`:

```markdown
# Manual Tasks Required

The following tasks require manual user action to complete the installation.

## 1. [Task Name]

**Description**: [What needs to be done]

**Steps**:
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Verification**: [How to verify completion]

---

## 2. [Next Task]

...
```

---

## Appendix: Project Reference

### A.1 Project Overview

- **Name**: MMT-DPI (Montimage Deep Packet Inspection)
- **Version**: 1.7.10
- **Type**: C library for network packet analysis
- **License**: Apache License 2.0
- **Website**: http://www.montimage.com

### A.2 Directory Structure

```
mmt-dpi/
├── src/
│   ├── mmt_core/          # Core DPI engine
│   ├── mmt_tcpip/         # TCP/IP protocols
│   ├── mmt_mobile/        # 4G/5G protocols
│   ├── mmt_business_app/  # Business protocols
│   ├── mmt_fuzz_engine/   # Fuzzing (optional)
│   ├── mmt_security/      # Security (optional)
│   └── examples/          # Example programs
├── sdk/                   # Build directory
├── rules/                 # Build system rules
├── docs/                  # Documentation
└── dist/                  # Distribution packages
```

### A.3 Build Options

| Option | Description | Default |
|--------|-------------|---------|
| `ARCH` | Target architecture (linux/osx/win32/win64) | linux |
| `DEBUG` | Enable debug symbols | 0 |
| `ENABLESEC` | Enable security/fuzzing features | 0 |
| `VERBOSE` | Show build commands | 0 |
| `MMT_BASE` | Installation base directory | /opt/mmt |

### A.4 Generated Libraries

| Library | Description |
|---------|-------------|
| libmmt_core.so | Core DPI engine |
| libmmt_tcpip.so | TCP/IP protocol stack |
| libmmt_tmobile.so | 4G/5G mobile protocols |
| libmmt_business_app.so | Business application protocols |
| libmmt_fuzz.so | Fuzzing engine (ENABLESEC=1) |
| libmmt_security.so | Security features (ENABLESEC=1) |

### A.5 Compilation Example

```bash
# Compile with MMT-DPI
gcc -o my_program my_program.c \
    -I /opt/mmt/dpi/include \
    -L /opt/mmt/dpi/lib \
    -lmmt_core -lmmt_tcpip -ldl

# Run with library path (if ldconfig not configured)
LD_LIBRARY_PATH=/opt/mmt/dpi/lib ./my_program
```

### A.6 Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| `cannot find -lmmt_core` | Library path not set | Run ldconfig or set LD_LIBRARY_PATH |
| `libxml/parser.h: No such file` | libxml2-dev not installed | Install libxml2-dev |
| GCC 10+ compilation errors | Compiler incompatibility | Use GCC 9 or add -fcommon flag |
| `Permission denied` during install | Not running as root | Use sudo |
| Examples crash at runtime | Library not in search path | Configure /etc/ld.so.conf.d/ |

### A.7 Useful Commands

```bash
# Check installed version
strings /opt/mmt/dpi/lib/libmmt_core.so | grep VERSION

# List supported protocols
/opt/mmt/examples/proto_attributes_iterator

# Capture live traffic (requires root)
sudo ./extract_all -i eth0

# Analyze pcap file
./extract_all -t capture.pcap

# Uninstall
cd sdk && sudo make dist-clean
```

---

## Document Information

- **Purpose**: AI agent instructions for MMT-DPI installation
- **Target Audience**: AI agents performing automated setup
- **Execution Model**: Three-phase with user approval gates
- **Last Updated**: [Generated automatically]

---

*End of agent-instructions.md*
