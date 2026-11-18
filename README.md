# BusyBox for Android Systems Engineering

A specialized BusyBox distribution providing native, zero-dependency tooling for Android low-level systems engineering, boot partition patching, runtime property manipulation, binary analysis, and early-boot kernel module loading.

All applets compile into a single static musl binary for AArch64 (as well as x86_64 host and AArch64 glibc container builds), replacing external standalone dependencies (`magiskboot`, `resetprop`, `patchelf`, `readelf`, `adb`, and ad-hoc shell scripts).

---

## Applet Index

### 1. Boot, Ramdisk & Kernel Module Engines

#### `init_wrapper` (aliases: `init`, `early_init`, `init_wrap`)
Dual-stage Android bootloader wrapper designed to execute as PID 1 (`/init`) in Android ramdisks and intercept second-stage init before SELinux enforcement.

* **First-Stage PID 1 (`/init`)**:
  * Mounts early pseudo-filesystems (`/dev`, `/proc`, `/sys`).
  * **Emergency Safe Mode**: Probes `/dev/input/event*` for `KEY_VOLUMEDOWN` (114). If held, aborts custom module loading to prevent bootloops.
  * **In-Memory Module Loader**: Discovers modules listed in `modules.load` or the rootfs. Supports raw `.ko` and compressed `.ko.gz` / `.ko.xz` archives. Archives are decompressed into anonymous memory and loaded via `sys_finit_module` (or `sys_init_module`) entirely in RAM—zero temporary files written to storage.
  * **Second-Stage Interception**: Patches `/system/bin/init` inside `/init.real` to redirect second-stage execution to `/data/init_wrap`.
  * **Pristine Handoff**: Detaches early mounts via `umount2(..., MNT_DETACH)` and chainloads `/init.real`.

* **Second-Stage Interception (`selinux_setup`)**:
  * Executes before Android init compiles and enforces SELinux policy.
  * **System Payload Staging**: Stages manager payloads (`kroot.apk` as `0644 system:system u:object_r:apk_data_file:s0` and `busybox` as `0755 root:root u:object_r:system_file:s0`) into `/data/system/kroot/`.
  * **PMS Cache Purge**: Clears `/data/system/package_cache/*` and conflicting external userland installs/dalvik caches to force clean PackageManagerService indexing on boot.
  * **Zero Userland Mount Hacks**: Replaces fragile `/sbin` or `/system/xbin` tmpfs mounts with Ring-0 transparent VFS remap rules registered to `/proc/kroot/vfs_remap`.
  * Detaches temporary staging mounts and chainloads `/system/bin/init selinux_setup`.

* **CLI Staging Mode (`--stage`)**:
  ```bash
  # Stage manager APK and BusyBox into /data/system/kroot from recovery installer scripts
  busybox init_wrapper --stage /path/to/kroot.apk /path/to/busybox
  ```

---

#### `aimg`
Universal Android boot, recovery, and vendor image inspection, unpack, repack, and patching suite across Header v0 through v4.

* **Header Support**: Full parsing and rebuilding for Header v0/v1/v2 (legacy split images), Header v3 (Android 11/12+ SAR), and Header v4 (Android 13+ with bootconfig).
* **In-Memory Buffer Mutation**: Modifies kernel command lines, ramdisk properties, and bootconfig sections directly in memory without unpack/repack cycles.
* **Build Flag & Debug Manipulation**:
  * `aimg --build-status <boot.img|--live>`: Audits whether the image/system is `user`, `userdebug`, or `eng`.
  * `aimg --set-build-type <boot.img|--live> <user|userdebug|eng>`: Flips build type across cmdline, ramdisk properties, and bootconfig in one pass.
  * `aimg --set-debuggable <1|0>`: Sets `ro.debuggable` and `ro.force.debuggable`.
  * `aimg --set-insecure-adb <1|0>`: Disables USB adb authorization and authentication checks.
* **Direct Block Flashing**: Flashes patched images directly to raw block partitions (e.g., `/dev/block/by-name/boot_b`) with verified sector alignment and write speed metrics.
* **Extended Patching**: Native AnyKernel3 flashing (`--ak3-flash`), FDT/DTB patcher, AVB hash tree updater, dynamic ELF64 kernel ABI resolution (`--kabi-check`), and OTA `payload.bin` extraction.

```bash
# Check image or live partition build status
busybox aimg --build-status /dev/block/by-name/boot_a

# Convert image to userdebug and enable insecure root adb
busybox aimg --set-build-type /dev/block/by-name/boot_a userdebug
busybox aimg --set-debuggable /dev/block/by-name/boot_a 1
busybox aimg --set-insecure-adb /dev/block/by-name/boot_a 1

# Extract partition from OTA payload.bin
busybox aimg -e payload.bin boot boot.img
```

---

### 2. Binary Engineering, Inspection & In-Memory Execution

#### `fexec` (alias: `memrun`)
Executes binaries directly from anonymous memory file descriptors (`memfd_create` + `fexecve`) without writing executables to storage.

* Supports streaming executables from stdin via `-`.
* Optional memory sealing (`-s`) prevents post-write descriptor modification.
* Custom `argv[0]` spoofing (`-a`).

```bash
# Execute binary streamed over SSH or pipeline directly in RAM
cat my_tool | busybox fexec -s -a "[kworker/u:0]" - arg1 arg2
```

---

#### `readelf`
Standalone on-device ELF binary parser. Displays headers, program headers, sections, symbols, notes, and relocations for ELF32/ELF64 executables, shared libraries, and `.ko` modules.

* `-h`: Display ELF file header.
* `-l`: Display program headers (segments).
* `-S`: Display section headers.
* `-s`, `--dyn-syms`: Display symbol tables (`.symtab`, `.dynsym`).
* `-d`: Display dynamic section tags (`DT_NEEDED`, `DT_RPATH`, `DT_RUNPATH`).
* `-p <sec>` / `-x <sec>`: Dump section contents as strings or hex.

```bash
busybox readelf -h -l -d /system/bin/app_process64
```

---

#### `patchelf` (alias: `termux-elf-cleaner`)
In-place ELF binary modification utility for adjusting dynamic sections, loaders, and segment page-size alignment.

* `--set-interpreter <path>`: Modify `PT_INTERP` dynamic linker path.
* `--set-soname <name>`: Update `DT_SONAME`.
* `--set-rpath <path>` / `--remove-rpath`: Modify or strip `DT_RPATH` / `DT_RUNPATH`.
* `--replace-needed <old> <new>`: Swap shared library dependencies.
* `--page-size <4k|16k|64k>`: Re-align `PT_LOAD` segments for modern Android 16 KB page-size kernels.
* `--clean-for-android`: Strips unsupported dynamic tags for the target Android API level.

```bash
# Re-align native library for Android 15 16KB page-size support
busybox patchelf --page-size 16k libnative.so

# Clean ELF dynamic section for Android target
busybox patchelf --clean-for-android --api-level 30 libcustom.so
```

---

#### `ksyms` (alias: `kallsyms`)
Kernel symbol, struct offset, and hardware boundary inspection tool.

* Dynamic kernel symbol lookup with address resolution.
* Struct member tracing: queries probed struct offsets (`-T, --struct <name>`, `-M, --member <name>`).
* Hardware memory boundaries and cache geometry (`-B`).
* Live vDSO symbol and machine code disassembly (`-v`).
* Syscall timing benchmark measuring cycle latency (`-t`).

```bash
# Query kernel struct member offset
busybox ksyms --struct task_struct --member cred

# Display kernel memory layout boundaries
busybox ksyms -B
```

---

#### `nm`, `objdump`, `strip`, `file`
Standard binary utilities compiled natively:
* **`nm`**: Lists symbol tables from object files, static libraries, and kernel modules.
* **`objdump`**: Disassembles executable sections and inspects raw object contents.
* **`strip`**: Removes symbols, debug sections, and notes (`.comment`, `.note*`, `.eh_frame`).
* **`file`**: Identifies file types and ELF architectures.

---

### 3. Android Platform, SELinux & Diagnostics

#### `resetprop`
Shared-memory Android system property mutator. Manipulates `/dev/__properties__/` trie pages directly, bypassing Android `/init` write-once restrictions on `ro.*` properties without linking against Bionic libc.

* Direct trie traversal across context files (`u:object_r:*_prop:s0`).
* `--adbd-root`: Sets `ro.debuggable=1`, `ro.secure=0`, and `ro.build.type=userdebug` in shared RAM and restarts `adbd` as UID 0 (`root`).

```bash
# Override a read-only property in memory
busybox resetprop ro.build.type userdebug

# Delete a property node
busybox resetprop -d ro.custom.prop

# Switch adbd daemon to root mode
busybox resetprop --adbd-root
```

---

#### `getprop` & `setprop`
Lightweight native implementations for querying and setting Android system properties via Bionic property service sockets.

---

#### `sepolicy`
SELinux policy inspection and live kernel policy injection tool.

* `-l`, `--live`: Read policy from `/sys/fs/selinux/policy` and write modified rules directly to `/sys/fs/selinux/load`.
* Live rule modification: `allow`, `auditallow`, `dontaudit`, `permissive`, `enforce`, `typeattribute`.
* `-d`, `--dump`: Dumps policy statistics (version, types, classes, permissive domains).

```bash
# Add a live SELinux allow rule directly into the running kernel
busybox sepolicy -l allow su init process transition

# Put a domain into permissive mode live
busybox sepolicy -l permissive my_daemon
```

---

#### `getenforce` & `setenforce`
SELinux enforcement mode query and modification utilities linked directly against `libselinux`.

* **`getenforce`**: Queries running kernel SELinux enforcement status (`Enforcing`, `Permissive`, or `Disabled`).
* **`setenforce <1|0|Enforcing|Permissive>`**: Toggles running kernel SELinux mode.
* **`selinuxenabled`**: Returns exit status `0` if SELinux is active in the running kernel, `1` otherwise.

```bash
# Query current SELinux mode
busybox getenforce

# Toggle SELinux to permissive mode
busybox setenforce 0
```

---

#### `sendevent`
Direct Linux input event injector for testing touches, key presses, and hardware button events via `/dev/input/event*`.

```bash
# Inject Power key press (KEY_POWER = 116, EV_KEY = 1)
busybox sendevent /dev/input/event1 1 116 1
busybox sendevent /dev/input/event1 0 0 0
busybox sendevent /dev/input/event1 1 116 0
busybox sendevent /dev/input/event1 0 0 0
```

---

#### `log`
Sends messages directly into Android's kernel/userspace `logcat` buffers.

* `-b <buffer>`: Target buffer (`main`, `radio`, `events`, `system`, `crash`, `kernel`).
* `-p <priority>`: Priority level (`v`, `d`, `i`, `w`, `e`, `f`).
* `-t <tag>`: Custom log tag.

```bash
busybox log -b main -p i -t "early_boot" "Payload staging complete"
```

---

#### `klog`
High-resolution kernel ring-buffer watcher and live stream monitor with microsecond delta-timing, subsystem tag filtering, and ANSI priority coloring.

* Displays delta elapsed time `[ 11.729733 (+ 0.000203s)]` between consecutive kernel messages for latency profiling.
* `-f`, `--follow`: Continuous streaming follow mode via `/proc/kmsg`.
* `-s <subsystems>`: Filter messages matching comma-separated subsystem tags (e.g. `-s sucompat,kroot,binder,init`).
* `-n <lines>`: Display only the trailing N lines of the ring buffer.
* `-c` / `-C`: Force ANSI priority coloring on / off (red for err/crit/emerg, yellow for warning, cyan for info/notice, dim for debug).

```bash
# Follow live kernel log filtering for sucompat and binder events
busybox klog -f -s sucompat,binder

# Inspect last 100 kernel messages with microsecond delta-timing
busybox klog -n 100 -c
```

---

### 4. Zero-Dependency Android Binder IPC Suite

A complete pure C `/dev/binder` driver client suite with zero Android C++ framework dependencies (`libbinder.so`, `libc++.so`, `libutils.so`). Directly drives kernel Binder `ioctl` transactions (`BINDER_WRITE_READ`), parcel wire serialization, reference counting, and IPC handle lifecycles.

#### `servicelist`
Enumerates registered Binder services and resolves their live status, handle assignments, interface descriptors, and IPC round-trip latency.

* `-d <dev>`: Target binder device node (default: `/dev/binder`, supports `/dev/hwbinder`, `/dev/vndbinder`).
* `-i`: Resolve AIDL interface descriptor (e.g., `android.app.IActivityManager`) via `_NTF` (`0x5f4e5446`).
* `-p`: Measure round-trip ping latency in microseconds via `_PNG` (`0x5f504e47`).
* `-a`: Filter alive services only.

```bash
# List all registered Binder services with interface descriptors and ping latency
busybox servicelist -i -p

# Query hardware binder node
busybox servicelist -d /dev/hwbinder -i
```

---

#### `binder_ping`
Probes Binder context manager (`servicemanager` at handle 0) or specific registered services to verify process responsiveness.

* `-d <dev>`: Target binder device node.
* `[service]`: Optional service name. If omitted, pings `servicemanager`. If specified, resolves service handle via `checkService` (opcode 3), acquires handle reference, queries interface descriptor, sends `_PNG`, and reports latency.

```bash
# Ping servicemanager handle 0
busybox binder_ping

# Ping SurfaceFlinger compositor and display latency
busybox binder_ping SurfaceFlinger

# Ping ActivityManager
busybox binder_ping activity
```

---

#### `binder_dump`
Standalone, zero-dependency `dumpsys` replacement. Fetches service diagnostic state by passing `STDOUT_FILENO` as a `BINDER_TYPE_FD` object directly across the Binder driver.

* `-d <dev>`: Target binder device node.
* Zero memory copies or intermediate socket pipes: the kernel translates stdout directly into the target process's file descriptor table (`binder_translate_fd`).
* Supports passing arbitrary dump arguments (e.g. `--proto`, `--brief`, `all`).

```bash
# Dump SurfaceFlinger compositor state directly to stdout
busybox binder_dump SurfaceFlinger

# Dump Android process memory breakdown
busybox binder_dump meminfo

# Pass arguments to service dump
busybox binder_dump activity services
```

---

#### `binder_call`
Low-level interactive AIDL transaction caller. Formats typed parcel arguments, dispatches transactions to arbitrary handles, and decodes transaction reply parcels.

* `-d <dev>`: Target binder device node.
* Argument types:
  * `i32 <val>`: 32-bit signed integer.
  * `i64 <val>`: 64-bit signed integer.
  * `s16 <str>`: UTF-16 String16 (AOSP standard interface token / string).
  * `utf8 <str>`: UTF-8 string.
  * `null`: Null object pointer.
  * `fd <num>`: File descriptor object (`BINDER_TYPE_FD`).
* Automatically decodes AIDL exception status codes (`EX_NONE`, `EX_SECURITY`, `EX_BAD_PARCELABLE`, `EX_ILLEGAL_ARGUMENT`, `EX_NULL_POINTER`, `EX_ILLEGAL_STATE`, `EX_NETWORK_MAIN_THREAD`, `EX_UNSUPPORTED_OPERATION`, `EX_SERVICE_SPECIFIC`).
* Prints formatted hex and ASCII parcel reply dumps with word-aligned offsets.

```bash
# Query servicemanager (handle 0) listServices (opcode 6, dump_priority 15)
busybox binder_call 0 6 i32 15

# Call custom service method with interface token and arguments
busybox binder_call 1 1 s16 "android.os.IBatteryStats" i32 0
```

---

### 5. Networking & Debugging

#### `adb`
Native Android Debug Bridge client with wireless debugging discovery and control.

* Wireless debugging auto-discovery and pairing (`pair`, `connect`, `disconnect`).
* Interactive shell execution (`shell`).
* File synchronization (`push`, `pull`).
* Device key generation (`keygen`).

```bash
# Connect to Android wireless debugging port
busybox adb connect 192.168.1.50:5555

# Execute remote shell
busybox adb shell id
```

---

### 6. Build Targets

The custom build system (`Makefile.custom`) automatically resolves cross-compilation toolchains and sysroots:

```bash
# Android AArch64 (musl static, zero dynamic linker dependencies) -> bin/busybox-arm64
make arm64

# Host PC (x86_64 native) -> bin/busybox-x86_64
make host

# Container AArch64 (GNU glibc dynamic) -> bin/busybox-arm64-glibc
make glibc

# Build all target binaries in one pass
make all-bins
```

---

## License & Attribution

BusyBox is licensed under the **GNU General Public License, version 2** (GPLv2). See `LICENSE` for the complete license text.  
Upstream BusyBox: [https://git.busybox.net/busybox](https://git.busybox.net/busybox)
