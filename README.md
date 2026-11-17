# BusyBox with Native Android Systems Engineering Engines

A high-performance fork of **BusyBox** carrying the complete, authentic 25-year upstream Git history, extended with native, zero-dependency Android systems engineering applets.

While upstream BusyBox provides the core minimalist POSIX userland, modern Android platform hacking, kernel development, and recovery workflows typically require fragmented third-party binaries (`magiskboot`, `resetprop`, separate Python scripts). This fork integrates these Android engines directly into the BusyBox binary as first-class applets, compiled into a single, fully static musl binary for AArch64 and x86_64.

---

## Key Feature Applets

### 1. `aimg` — Android Boot & Recovery Image Engine
A fast, C-native implementation for inspecting, unpacking, repacking, and patching Android boot, recovery, and vendor images across all Android boot header revisions (Header v0 through Header v4).

* **Header Compatibility**: Full support for Header v0/v1/v2 (legacy split images), Header v3 (Android 11/12+ SAR), and Header v4 (Android 13+ with bootconfig).
* **In-Memory Buffer Engine**: Modifies kernel command lines, ramdisk `prop.default`, and `bootconfig` buffers in-place without unpack/repack cycles.
* **Production & Debug Flag Mutation**:
  * `aimg --build-status <boot.img|--live>`: Audits whether the image or running system is configured as `user`, `userdebug`, or `eng`.
  * `aimg --set-build-type <boot.img|--live> <user|userdebug|eng> [out.img]`: Flips build type invariants across cmdline, ramdisk properties, and bootconfig in one pass.
  * `aimg --set-debuggable <1|0>`: Toggles `ro.debuggable` and `ro.force.debuggable`.
  * `aimg --set-insecure-adb <1|0>`: Disables USB authorization and authentication checks.
* **Direct Block Device Flashing**: Safely writes patched images directly to raw storage nodes (e.g., `/dev/block/by-name/boot_b`) with verified sector alignment and write speed metrics (>1 GB/s).

#### Usage Example:
```bash
# Check build status of a physical partition or file
busybox aimg --build-status /dev/block/by-name/boot_b

# Mutate build flags directly to userdebug and enable root ADB
busybox aimg --set-build-type /dev/block/by-name/boot_b userdebug
busybox aimg --set-debuggable /dev/block/by-name/boot_b 1
busybox aimg --set-insecure-adb /dev/block/by-name/boot_b 1
```

---

### 2. `resetprop` — Native Bionic Shared-Memory Property Mutator
A standalone, libc-independent applet that bypasses Android `/init` write-once restrictions on `ro.*` (read-only) system properties by directly mutating `/dev/__properties__/` in shared memory.

* **Direct Trie Traversal**: Parses the Android property trie and context nodes (`u:object_r:*_prop:s0`) directly via raw filesystem pointers, eliminating dependencies on Android's Bionic libc.
* **Backwards Invariant Resolution**: Employs backwards-scanning offset resolution (`offset_of(name) - 96 = prop_info`) to accurately modify property serials and string buffers without corrupting neighbouring nodes.
* **Automated Root ADB (`--adbd-root`)**:
  * Dynamically flips `ro.debuggable=1`, `ro.secure=0`, and `ro.build.type=userdebug` in shared RAM.
  * Restarts `adbd` seamlessly as UID 0 (`root`), resolving client-side `adb root` terminal hangs without modifying physical partitions.

#### Usage Example:
```bash
# Set a read-only property in memory
busybox resetprop ro.debuggable 1

# Delete a property
busybox resetprop -d ro.some.prop

# Automate root ADB mode (modifies memory trie and restarts adbd as root)
busybox resetprop --adbd-root
```

---

## Build Architecture

* **AArch64 Target**: Built with a dedicated musl toolchain (`aarch64-buildroot-linux-musl-gcc`) producing a 100% statically linked binary with zero dependencies on dynamic loaders (`/lib/ld-linux-*.so`).
* **x86_64 Target**: Builds clean host binaries for desktop testing and image generation.

### Building
```bash
# 1. Build for Android (ARM64 static musl) -> bin/busybox-arm64
make arm64

# 2. Build for Host PC (x86_64 gcc) -> bin/busybox-x86_64
make host

# 3. Build for Container (ARM64 glibc) -> bin/busybox-arm64-glibc
make glibc

# 4. Build all targets
make all-bins
```

---

## License & Upstream Attribution
BusyBox is licensed under the **GNU General Public License, version 2** (GPLv2). See `LICENSE` for the full license text.
Upstream repository: [https://git.busybox.net/busybox](https://git.busybox.net/busybox)
