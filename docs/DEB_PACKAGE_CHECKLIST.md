---
layout: default
title: ".deb Package Build & apt Repository Setup Checklist"
---

# .deb Package Build & apt Repository Setup Checklist

> **Status note (2026-09-16, issue #249):** the build report below describes the
> `mmt-dpi 1.7.10-3ab25616` package — recorded before the current `1.8.0`
> release (`rules/common.mk:1`), which added the DICOM plugin library
> `libmmt_tdicom.so` that this report originally omitted. The library list
> under *Package Info* has since been annotated, but the authoritative package
> contents and dependency set are now derived from the built `.so` files at
> package-build time (`tools/ci/shlib-deps.sh`, verified per artifact by
> `tools/ci/check-package-deps.sh --verify-package`), not maintained here.

## Build Testing Results

**Status:** ✓ Package builds successfully

**Package Info:**
- Name: `mmt-dpi`
- Version: `1.7.10-3ab25616`
- Architecture: `aarch64` (dynamically detected from `uname -m`)
- Size: ~1.5 MB
- Libraries: `libmmt_core.so`, `libmmt_tcpip.so`, `libmmt_tmobile.so`, `libmmt_business_app.so`, `libmmt_tdicom.so` — plus `libmmt_fuzz.so` and `libmmt_security.so` when built with `ENABLESEC=1` (as the release packages now are, issue #219)

## Issues Fixed

1. **Architecture Detection**: Changed from `all` to dynamic `$(shell uname -m)` to properly detect the system architecture (arm64/aarch64, x86_64, etc.)

2. **Dependencies**: `Depends:` is derived at package-build time from the `NEEDED` entries `objdump -p` reports for the shipped `.so` files — `tools/ci/shlib-deps.sh` maps each soname to its Debian package (issue #219). The toolchain floor (issue #218) survives in that output as `libc6 (>= 2.34), libstdc++6 (>= 11)` — the constants come from `rules/common.mk` (`MMT_GLIBC_MIN`, `MMT_LIBSTDCXX_MIN`). `libpcap`/`libnghttp2` are gone (nothing links them); `libxml2` appears when the package is built with `ENABLESEC=1`. Verify with `bash tools/ci/check-package-deps.sh --verify-package <pkg>.deb`.

3. **Post-install Script**: Added `postinst` to run `ldconfig` after installation

4. **Pre-remove Script**: Added `prerm` to remove ldconfig entry before removal

5. **Fixed control file formatting** (removed extra spaces)

---

## Testing Checklist

### Build Verification

- [ ] Build .deb package: `make -C sdk VERSION=<version> GIT_VERSION=$(git log --format="%h" -n 1) deb`
- [ ] Verify package integrity: `dpkg-deb -I mmt-dpi_*.deb`
- [ ] List package contents: `dpkg-deb -c mmt-dpi_*.deb`
- [ ] Extract and inspect control files: `dpkg-deb -e mmt-dpi_*.deb /tmp/control`

### Pre-Installation Checks

- [ ] Verify system architecture compatibility (aarch64 vs x86_64)
- [ ] Ensure `libc6 >= 2.34` and `libstdc++6 >= 11` are available: `dpkg -l libc6 libstdc++6`
- [ ] Check available disk space in `/opt/mmt` (requires ~50MB)

### Installation Testing

- [ ] Install package: `sudo dpkg -i mmt-dpi_*.deb`
- [ ] Verify installation: `dpkg -l mmt-dpi`
- [ ] Check libraries are registered: `ldconfig -p | grep mmt`
- [ ] Verify symlinks: `ls -la /opt/mmt/dpi/lib/`

### Functional Testing

- [ ] Test library loading with a sample application
- [ ] Verify plugin loading from `/opt/mmt/plugins/`
- [ ] Test header file accessibility from `/opt/mmt/dpi/include/`

### Removal Testing

- [ ] Uninstall: `sudo dpkg -r mmt-dpi`
- [ ] Verify ldconfig entry removed: `cat /etc/ld.so.conf.d/mmt-dpi.conf` (should fail)
- [ ] Run ldconfig to update: `sudo ldconfig`

---

## apt Repository Setup Checklist

### Option 1: Debian Repository (apt-get)

#### 1. Create Repository Structure

```bash
# Create repository directory
mkdir -p /var/www/html/mmt-dpi/debian/dists/stable/main/binary-aarch64

# Copy .deb file
cp mmt-dpi_*.deb /var/www/html/mmt-dpi/debian/pool/main/
```

#### 2. Generate Packages File

```bash
# Install dpkg-dev if not present
sudo apt install dpkg-dev

# Generate Packages file
cd /var/www/html/mmt-dpi/debian/dists/stable/main/binary-aarch64
dpkg-scanpackages ../../../../pool /dev/null > Packages

# Compress
gzip -k Packages
```

#### 3. Generate Release File

```bash
cd /var/www/html/mmt-dpi/debian/dists/stable

# Create Release file
cat > Release << EOF
Origin: Montimage
Label: mmt-dpi
Suite: stable
Codename: stable
Architectures: aarch64
Components: main
Description: MMT-DPI Repository
EOF

# Sign the Release file (optional but recommended)
gpg --detach-sign -o Release.gpg Release
```

#### 4. Client Configuration

Add to `/etc/apt/sources.list` or `/etc/apt/sources.list.d/mmt-dpi.list`:

```
deb [arch=aarch64] http://your-server/mmt-dpi/debian stable main
```

Add GPG key (if signed):

```bash
wget -O - http://your-server/mmt-dpi/gpg-key | sudo apt-key add -
```

Update and install:

```bash
sudo apt update
sudo apt install mmt-dpi
```

---

### Option 2: Simple APT Mirror (apt-ftparchive)

```bash
# Create structure
mkdir -p /var/www/html/mmt-dpi/pool/main
mkdir -p /var/www/html/mmt-dpi/dists/stable/main/binary-aarch64

# Copy deb file
cp mmt-dpi_*.deb /var/www/html/mmt-dpi/pool/main/

# Generate metadata
cd /var/www/html/mmt-dpi
apt-ftparchive packages pool/main > dists/stable/main/binary-aarch64/Packages

# Generate Release
apt-ftparchive release dists/stable > dists/stable/Release
```

---

### Option 3: Using reprepro (Recommended for Production)

```bash
# Install reprepro
sudo apt install reprepro

# Create configuration
mkdir -p /var/www/html/mmt-dpi/conf

cat > /var/www/html/mmt-dpi/conf/distributions << EOF
Origin: Montimage
Label: mmt-dpi
Codename: stable
Architectures: aarch64 source
Components: main
Description: MMT-DPI Repository
SignWith: yes
EOF

# Add package
reprepro -V /var/www/html/mmt-dpi includedeb stable mmt-dpi_*.deb
```

---

### Architecture Considerations

| Architecture | uname -m | deb Architecture |
|--------------|----------|------------------|
| 64-bit ARM | aarch64 | aarch64 |
| 64-bit x86 | x86_64 | amd64 |
| 32-bit x86 | i386 | i386 |

**Recommendation:** Build separate .deb files for each target architecture and maintain an `apt-architectures` line in the Release file:

```
Architectures: aarch64 amd64 i386
```

---

### Automated Build Integration

Add to CI/CD pipeline:

```yaml
# .gitlab-ci.yml example
deploy-deb:
  stage: deploy
  script:
    - make -C sdk VERSION=$CI_COMMIT_TAG GIT_VERSION=$(git log --format="%h" -n 1) deb
    - reprepro -V /path/to/repo includedeb stable sdk/mmt-dpi_*.deb
  only:
    - tags
```

---

### Verification Commands

```bash
# Check package metadata
dpkg-deb -I mmt-dpi_*.deb

# Check for missing dependencies
dpkg-deb -I mmt-dpi_*.deb | grep -i depends

# List all files in package
dpkg-deb -c mmt-dpi_*.deb

# Verify conffiles (if any)
dpkg-deb -I mmt-dpi_*.deb conffiles

# Test installation without actually installing
dpkg-deb -x mmt-dpi_*.deb /tmp/test-install
dpkg-deb -e mmt-dpi_*.deb /tmp/test-control
```

---

### Troubleshooting

**Issue:** `dpkg: error: architecture 'aarch64' not allowed`

**Solution:** Add architecture to dpkg:

```bash
sudo dpkg --add-architecture aarch64
sudo apt update
```

**Issue:** `ldconfig` not finding libraries

**Solution:** Verify `/etc/ld.so.conf.d/mmt-dpi.conf` exists and contains `/opt/mmt/dpi/lib`

**Issue:** Missing symbols when linking

**Solution:** Ensure all dependencies are installed:
```bash
sudo apt install libc6-dev
```

---

## Files to Include in Repository

```
/var/www/html/mmt-dpi/
├── conf/
│   └── distributions       (reprepro config)
├── pool/
│   └── main/
│       └── mmt-dpi_*.deb   (package files)
├── dists/
│   └── stable/
│       ├── main/
│       │   └── binary-aarch64/
│       │       ├── Packages
│       │       └── Packages.gz
│       ├── Release
│       └── Release.gpg     (if signed)
└── index.html              (optional - simple web page)
```

---

## Next Steps

1. [ ] Build package for additional architectures (x86_64, i386)
2. [ ] Set up web server for package hosting
3. [ ] Configure apt sources on test clients
4. [ ] Test full installation flow
5. [ ] Document versioning strategy
6. [ ] Set up automated builds for releases
