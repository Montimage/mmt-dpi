# Contributing to MMT-DPI

Thank you for your interest in contributing to MMT-DPI! This guide will help you get started.

## How to Contribute

1. **Fork** the repository
2. **Create a feature branch** from `main` (`git checkout -b feat/your-feature`)
3. **Make your changes** and test them
4. **Commit** using [Conventional Commits](#commit-conventions)
5. **Open a Pull Request** against `main`

## Development Setup

### Prerequisites

- GCC (4.9 to 9.x)
- GNU Make, CMake
- `libxml2-dev`, `libpcap-dev`

### Build from Source

```bash
git clone https://github.com/Montimage/mmt-dpi.git
cd mmt-dpi

# Install dependencies (Debian/Ubuntu)
sudo apt-get install build-essential gcc make cmake libxml2-dev libpcap-dev

# Build
cd sdk
make -j$(nproc)

# Install locally
sudo make install

# Run tests
make test
```

### Verify Your Changes

After building, test with the included examples:

```bash
cd src/examples
gcc -o extract_all extract_all.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
./extract_all -t /path/to/capture.pcap
```

## Branching Strategy

- `main` - Stable release branch (protected)
- `dev` - Development integration branch
- `feat/*` - Feature branches
- `hotfix/*` - Hotfix branches

Always branch from `main` for new features and bug fixes.

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <description>

[optional body]
```

**Types:**
- `feat` - New feature or protocol support
- `fix` - Bug fix
- `docs` - Documentation changes
- `refactor` - Code restructuring without behavior change
- `test` - Adding or updating tests
- `build` - Build system or dependency changes
- `perf` - Performance improvements

**Examples:**
```
feat: Add QUIC IETF RFC 9000 classification
fix: Resolve memory leak in FTP protocol handler
docs: Update compilation instructions for ARM
```

## Pull Request Process

1. Ensure your code compiles without warnings on Linux (`make`)
2. Run the test suite (`make test` in the `sdk/` directory)
3. Update documentation if you changed APIs or added protocols
4. Fill out the PR template completely
5. Request review from at least one maintainer

PRs require **1 approving review** before merging.

## Coding Standards

- Follow the existing C code style in the project
- Use 4-space indentation (no tabs)
- Keep functions focused and reasonably sized
- Add comments for non-obvious logic
- Use the existing macro and type conventions (`uint32_t`, `mmt_handler_t`, etc.)
- Avoid compiler-specific extensions when possible

## Adding a New Protocol

See the [Add New Protocol](docs/Add-New-Protocol.md) guide for detailed instructions on implementing protocol classification and attribute extraction.

## Testing

- Test your changes against pcap files with relevant traffic
- Verify with Valgrind for memory leaks: `valgrind --leak-check=full ./your_test`
- Ensure no regressions in existing protocol classification

## Reporting Issues

- Use the [Bug Report](https://github.com/Montimage/mmt-dpi/issues/new?template=bug_report.md) template for bugs
- Use the [Feature Request](https://github.com/Montimage/mmt-dpi/issues/new?template=feature_request.md) template for enhancements
- Include pcap samples (if possible) when reporting classification issues

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
