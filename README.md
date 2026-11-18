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

#### `simg2img` & `img2simg`
Zero-dependency Android Sparse Image (`0xed26ff3a`) conversion and compression suite.

* **`simg2img <sparse_1> [sparse_2 ...] <out_raw_image>`**:
  * Unpacks Android sparse images into raw partition images (`ext4`, `erofs`, `f2fs`).
  * **Multi-Chunk Fastboot/OTA Concatenation**: Automatically stitches split sparse chunks (e.g., `system.img.sparsechunk.0 .. N`) into a single raw file.
  * **Sparse Hole Optimization**: Uses `lseek()` for `CHUNK_TYPE_DONT_CARE` chunks to create sparse filesystem holes, delivering >5 GB/s decompression speed with zero physical disk block waste.
  * **Block Device Streaming**: Automatically detects block device targets (`/dev/block/by-name/...`) and non-seekable pipes, streaming zero-filled buffers safely.

* **`img2simg [-c] [-v] [-b BLOCK_SIZE] <raw_image> <sparse_image>`**:
  * Compresses raw partition images into Android sparse format for Fastboot / `fastbootd` flashing.
  * **Memory-Bus Block Analysis**: Evaluates 4 KB blocks using 64-bit vector checks to identify unallocated holes (`DONT_CARE`) and repeating words (`FILL`) at >10 GB/s.
  * **Chunk Coalescing**: Merges thousands of identical contiguous blocks into compact 12-byte headers.
  * `-c`: Computes and appends CRC32 checksum chunk.
  * `-v`: Prints verbose block breakdown and compression ratios.
  * `-b <size>`: Custom block size (default: 4096).

```bash
# Decompress split fastboot sparse chunks into raw partition image
busybox simg2img system.img.sparsechunk.* system_raw.img

# Compress raw partition image into Android sparse image with metrics
busybox img2simg -v -c vendor_patched.img vendor.simg
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

### 6. Hardware Bus, Silicon Probing & Linux GPIO (Character Device v2/v1 ABI)

#### `i2c-tools` (`i2cdetect`, `i2cdump`, `i2cget`, `i2cset`, `i2ctransfer`)
Zero-dependency I2C hardware bus inspection suite for direct Qualcomm SoC, PMIC, fuel gauge, and touchscreen debugging over `/dev/i2c-*`.

* **`i2cdetect`**:
  * `-l`: Enumerate all registered I2C adapters and bus numbers (e.g., Qualcomm `Geni-I2C`).
  * `-y [-a] [-q|-r] <bus_num> [first last]`: Non-interactive address scan detecting connected slave devices (`0x03` - `0x77`). Reports active devices with probe addresses or `UU` if already bound by a kernel driver.
  * `-F <bus_num>`: Displays adapter hardware functionality flags (SMBus Quick, Read/Write Byte, Block Data, I2C transfer).
* **`i2cdump`**: Hexdumps device register banks (0x00 - 0xFF) in byte (`b`), word (`w`), or block (`i`) modes.
* **`i2cget`**: Reads single registers or byte arrays directly from target slave addresses.
* **`i2cset`**: Writes single or block values to target registers with optional mask and readback verification.
* **`i2ctransfer`**: Executes atomic multi-message I2C read/write transaction sequences in a single ioctl.

```bash
# List available I2C busses on SoC
busybox i2cdetect -l

# Scan I2C bus 1 for connected PMIC, fuel gauge, and touchscreen chips
busybox i2cdetect -y 1

# Read single byte from PMIC register 0x10 at address 0x56
busybox i2cget -y 1 0x56 0x10

# Hexdump all registers of battery fuel gauge (e.g. SMB1360 / BQ25601 at 0x55)
busybox i2cdump -y 1 0x55 b
```

---

#### `gpio-tools` (`gpiodetect`, `gpioinfo`, `gpioget`, `gpioset`, `gpiomon`)
High-performance character device GPIO controller and line manipulation suite utilizing the modern Linux `/dev/gpiochip*` ioctl ABI with automatic dual-ABI fallback (GPIO v2 ioctls on Linux 5.10+ / mainline, v1 on Linux 4.19 / Android).

* **`gpiodetect`**:
  * Discovers all GPIO chips in `/dev/gpiochip*`.
  * Reports chip device names, controller labels (e.g., `400000.pinctrl`, `1c40000.qcom,spmi:qcom,pm6125@0`), and total line counts.
* **`gpioinfo [gpiochip...] [line...]`**:
  * Displays real-time kernel line state: direction (`input`/`output`), active-low, drive flags (`open-drain`, `open-source`), bias (`pull-up`, `pull-down`), and active kernel consumer labels (`consumer="volume_up"`).
* **`gpioget [-l] <gpiochip> <line...>`**:
  * Reads logical or physical values (`0` or `1`) across one or multiple pins simultaneously in a single atomic ioctl.
  * `-l`: Active-low inversion.
* **`gpiomon [-r] [-f] [-l] [-u [DRV[:DEV]]] <gpiochip> <line>`**:
  * Real-time hardware edge transition monitor with nanosecond timestamp precision.
  * Captures rising (`-r`), falling (`-f`), or both edge transitions with zero CPU polling via kernel event queues.
  * **Dynamic Driver Unbind & Auto-Restore (`-u`)**: Seamlessly unbinds the in-kernel consumer driver (e.g., `gpio-keys`) from `/sys/bus/<bus>/drivers/<driver>/unbind` to release the pin, monitors hardware interrupts, and **automatically restores** the driver binding via signal handlers and `atexit` when monitoring exits. Supports auto-detecting consumer drivers or explicit `[DRIVER[:DEVICE]]` overrides.
* **`gpioset [-l] [-m MS] [-t] <gpiochip> <line=val...>`**:
  * Drives output pins directly from userland with optional active-low (`-l`), state hold duration (`-m`), or continuous toggle square-wave mode (`-t`).

```bash
# Discover all SoC and PMIC GPIO controllers
busybox gpiodetect

# Query line information for SPMI PMIC controller
busybox gpioinfo gpiochip1

# Read SoC GPIO pin values (e.g., lines 0 through 3)
busybox gpioget gpiochip0 0 1 2 3

# Monitor real-time Volume Up button edge interrupts with automatic kernel driver unbind & restore
busybox gpiomon -u gpio-keys gpiochip1 4

# Toggle test pin every 500ms
busybox gpioset -t -m 500 gpiochip0 12=1
```

---

### 7. Mobile Display Switcher & Hardware GPU/Framebuffer Suite (`displayswitch`, `fbswitch`, `fbtools`)

Zero-dependency display environment switcher and direct hardware GPU/framebuffer tool designed for seamless transitions between Android (SurfaceFlinger) and native Linux mobile desktop environments (Xorg, Phoc, Phosh, Wayland).

Inspired by systemd-nspawn container graphics handoff (`nspawn-android.c` / `nspawn-android-hw.h`), `displayswitch` provides deterministic process lifecycle coordination, display lock auditing, SMPTE test pattern rendering, backlight management, and VRAM memory dumping across both modern **DRM/KMS** (`/dev/dri/card0`) and legacy **FBDEV** (`/dev/graphics/fb0`, `/dev/fb0`) pipelines.

* **`displayswitch status` / `info`**:
  * Probes active display pipeline (DRM/KMS dumb buffers, connectors `DSI-1`/`eDP`, or FBDEV resolution, virtual panning, bpp, and VRAM size).
  * Enumerate GPU acceleration device nodes (`/dev/kgsl-3d0` Adreno, `/dev/dri/renderD128`, `/dev/mali0`).
  * Reports screen backlight level and sysfs hardware interface.
  * Audits display device locks (`/proc/*/fd`) identifying the active owner (e.g. `composer-servic`, `surfaceflinger`, `Xorg`).
  * Inspects `system_server`, `surfaceflinger`, and HAL execution states.
* **`displayswitch linux` / `to-linux`**:
  * Halts Android display pipeline (`surfaceflinger`, `vendor.qti.hardware.display.composer`, `vendor.hwcomposer*`, `display-color-hal`, `audioserver`).
  * Awaits clean release of `/dev/dri/card0` / `/dev/graphics/fb0` descriptors.
  * Suspends `system_server` via `SIGSTOP` immediately after display release, preventing the Android Watchdog from aborting and rebooting the device.
  * Configures LCD backlight brightness and unblanks display controller.
  * Clears VRAM to dark slate (`#181818`) and kicks the display controller to hand off a clean frame to Linux Xorg or Wayland compositors (Phoc/Weston).
* **`displayswitch android` / `to-android`**:
  * Terminates Linux desktop compositors (`phoc`, `phosh`, `Xorg`, `squeekboard`).
  * Resumes `system_server` via `SIGCONT`.
  * Restores Hardware Composer HALs and SurfaceFlinger display server.
  * Dismisses lockscreen keyguard, wakes display, and transitions directly to Android Home launcher.
* **`displayswitch test`**:
  * Renders SMPTE 8-color test bars and grayscale ramp directly into hardware VRAM (via DRM dumb buffer or FBDEV mmap).
* **`displayswitch clear [HEX]`**:
  * Fills screen VRAM with a solid hex color (e.g., `000000` black, `FF0000` red, `00FF00` green).
* **`displayswitch kick`**:
  * Triggers immediate hardware display refresh, unblanking, and panning page-flip.
* **`displayswitch backlight [PCT]`**:
  * Reads current backlight brightness percentage or sets target brightness (`0-100%` or raw value).
* **`displayswitch dump [FILE.ppm]`**:
  * Captures live screen VRAM directly to an uncompressed standard PPM (Portable Pixmap) image file.

```bash
# Audit display pipeline, GPU nodes, and process locks
busybox displayswitch status

# Render SMPTE 8-color test pattern directly to physical screen
busybox displayswitch test

# Set screen backlight to 60%
busybox displayswitch backlight 60%

# Clear display to solid navy blue
busybox displayswitch clear 001133

# Transition mobile display environment to Linux desktop
busybox displayswitch linux

# Restore physical screen back to Android UI
busybox displayswitch android

# Dump current framebuffer to image
busybox displayswitch dump /data/local/tmp/screenshot.ppm
```

---

### 8. Pure In-Memory Mobile SoC Silicon Hardware & Machine Engine (`socprobe`, `socreg`, `regprobe`, `pllprobe`)

Zero-dependency silicon hardware diagnostic and machine-code analysis suite designed specifically for restricted environments where `debugfs` is omitted/blocked, `/dev/mem` is denied, and filesystem endpoints (`/proc`, `/sys`) are inaccessible or locked down. Operates with **zero filesystem access** (0 `open()`, 0 `fopen()`, 0 `opendir()`, 0 disk I/O) using pure AArch64 inline assembly, cycle-timing loops, in-memory silicon tables, and instruction disassembly.

* **`socprobe status` / `info`**:
  * Silicon telemetry overview: CPU implementer/part, exception level (`CurrentEL`), hardware crystal frequency (`CNTFRQ_EL0`), live measured core clock, and in-memory MMIO/PMIC register definitions.
* **`socprobe cpu`**:
  * Pure inline assembly register audit with `SIGILL` trap recovery: `MIDR_EL1` (Implementer, Part, Variant, Revision), `MPIDR_EL1` (Cluster/Core affinity), `REVIDR_EL1`, `CTR_EL0` (D-Cache/I-Cache line sizes), `DCZID_EL0`, `ID_AA64ISAR0/1_EL1` (Hardware AES/SHA1/SHA2/CRC32/Atomics), `ID_AA64PFR0_EL1` (AdvSIMD/FP/GIC/CSV2), `ID_AA64MMFR0_EL1` (Physical address width), `CNTFRQ_EL0`, `CNTVCT_EL0`, `CurrentEL`, and `DAIF`.
* **`socprobe pll` / `clocks`**:
  * Hardware crystal oscillator base frequency (`19.200 MHz TCXO`).
  * Real-time CPU core clock frequency measured dynamically via unrolled instruction loop against `CNTVCT_EL0` / `CNTFRQ_EL0` cycle deltas.
  * In-memory Qualcomm GCC PLL network: GPLL0 (600MHz System/NoC), GPLL1 (576MHz Audio/Crypto), GPLL3 (1100MHz Display/CAM), GPLL4 (1600MHz UFS/PCIe), GPLL6 (384MHz Sleep), GPLL7 (533MHz DDR/BIMC), GPLL8 (825MHz GPU).
* **`socprobe pmic`**:
  * Qualcomm SPMI Arbiter architecture: Configuration (`0x01C0A000`), Core (`0x01C40000`), Channel Windows (`0x01E00000`), and Observer Windows (`0x03E00000`).
  * Per-peripheral register specifications: REVID (0x0100), PON reset/power-on control (0x0800), BUA backup battery (0x1000), TSENS on-die temp alarm (0x2400), SMBB charger (0x3100), FG_BATT fuel gauge (0x4000), GPIOs (0xC000), and MPPs (0xD000).
  * 12 core PMIC Buck (SMPS) and LDO voltage regulator rails with step sizes, voltage ranges, and SPMI register addresses.
* **`socprobe volt` / `power`**:
  * PMIC DAC voltage translation equations: Core SMPS (`300mV + step * 5mV`), High-Range Bucks (`600mV + step * 10mV`), Low-Range LDOs (`375mV + step * 12.5mV`), High-Range LDOs (`1750mV + step * 12.5mV`).
  * Instantaneous power dissipation equations (`P = C * V^2 * f` and `P = V * I`).
  * Coulomb counter current sense and ADC equations (`1.49 uV / Rsense` and `152.58 uV ADC`).
  * Active silicon core power estimation profiles (Sleep, LITTLE Eco, BIG Burst, Adreno 3D GPU).
* **`socprobe mmio [filter]`**:
  * In-memory physical MMIO register map covering 56+ hardware silicon blocks: GCC, TLMM, SPMI, QFPROM, PSHOLD, TSENS, SDHC, UFSHC, UFS-ICE, GENI-I2C, DWC3 USB, Adreno GPU, MDSS/DPU, MIPI DSI, LPASS Audio, Crypto Engine, APCS, CPUFreq-HW, CSIPHY, CSID, IFE, BPS, IPE, aDSP, cDSP, mDSP, IPA, SNOC, CNOC, MMNOC, BIMC, CE5 Crypto, BAM DMA, HWKM, UFS ICE, CPR, TSENS ROSC, Soundwire, SLIMbus, and HTP NPU.
* **`socprobe clock` / `clk`**:
  * Qualcomm Global Clock Controller (GCC) & RPM clock tree architecture.
  * Root Clock Generator (RCGR) layout: `CMD_RCGR` (+0x0000: Root enable, frequency switch update, root off status), `CFG_RCGR` (+0x0004: clock source select XO/GPLL, divider ratio, bypass/MND mode), `M_RCGR`, `N_RCGR`, `D_RCGR` fractional multiplier polynomials.
  * Clock Branch Control (CBCR) layout: `CLK_ENABLE`, `CLK_OFF` hardware gate status.
  * Core clock branches: Storage (`GCC_SDCC1/2_APPS`), SuperSpeed USB (`GCC_USB30_MASTER`), Bus Wrappers (`GCC_QUPV3_WRAP_0_M/S_AHB`), Camera (`GCC_CAMSS_TOP_AHB`), Display (`GCC_DISP_AHB`), GPU (`GCC_GPU_CFG_AHB`), Crypto Core (`GCC_CRYPTO_CLK`), and CPU Dynamic PLL (`APCS_CPU_PLL_CLK`).
* **`socprobe rosc` / `ring` / `cpr`**:
  * Silicon Ring Oscillators (ROSC) & Silicon Aging / Transistor Degradation Monitors.
  * Core Power Reduction (CPR) Adaptive Voltage Scaling (AVS) controller (`0x090D8000` / `0x01668000`).
  * On-die ring oscillator banks: Inverter delay chains (High/Std/Low-VT thresholds), NAND2/NOR2 logic delay chains for silicon speed binning, Pass-gate delay lines (contact and routing resistance), and interconnect capacitive delay lines.
  * Hardware control registers: `CPR_CONFIG` (open/closed loop mode), `CPR_STEP_QUOT_MIN/MAX`, `CPR_RESULT_0` (measured error delta & PMIC step recommendation), and `CPR_ROSC_MASK`.
  * TSENS thermal-dependent ring oscillators calibrated against TCXO crystal.
* **`socprobe crypto` / `ce`**:
  * Qualcomm Crypto Core (CE v5) Hardware Accelerator (`0x00700000`), BAM Dedicated Crypto DMA (`0x00704000`), Hardware Key Manager (`0x00730000`), and UFS Inline Crypto Engine (`0x01D88000`).
  * Hardware cryptographic primitives: AES-128/192/256 (ECB, CBC, CTR, XTS, CCM, GCM), SHA-1, SHA-256, SHA-384, SHA-512, HMAC-SHA256, and 3DES.
  * Silicon registers: `CRYPTO_CONFIG`, `CRYPTO_ENGINES_AVAIL`, `CRYPTO_STATUS`, `CRYPTO_AUTH_SEG_CFG`, `CRYPTO_ENCR_SEG_CFG`, `CRYPTO_ENCR_KEY0..7` (TrustZone secured), `CRYPTO_AUTH_IV0..3`, and `ICE_REGS_CONTROL`.
* **`socprobe ai` / `npu` / `htp`**:
  * Hexagon Tensor Processor (HTP) & HMX Matrix Engines (`0x08380000`) within Hexagon cDSP compute subsystem (`0x08300000`).
  * Hardware compute engines: INT8, INT16, FP16, and BFLOAT16 GEMM Matrix dot-product; 1024-bit HVX SIMD vector registers (`V0`-`V31`, 128 parallel 8-bit MACs/cycle); on-die hardware ReLU, LeakyReLU, Sigmoid, and GELU activation interpolation.
  * Registers: `HTP_CORE_CFG` (clock gate, precision mode), `HTP_STATUS`, `HTP_DMA_SRC/DST_PTR` (64-bit tensor DMA addresses), `HTP_TENSOR_DIM_M_N_K` (GEMM dimensions), `HTP_ACCUM_CTRL`, and `HVX_VECTOR_CFG`.
  * Adreno GPU machine learning FP16 dot-product accelerators (`dot2acc` / `dot4acc`).
* **`socprobe pmu` / `perf`**:
  * Pure inline assembly audit of ARMv8 architectural Performance Monitor Unit (PMU) registers with `sigsetjmp` / `SIGILL` trap recovery:
    * `PMCR_EL0`: Performance Monitors Control Register (hardware counter count, cycle prescaler, enable).
    * `PMCCNTR_EL0`: 64-bit Hardware Cycle Counter (live hardware execution cycles).
    * `PMUSERENR_EL0`: Userland Access Control Register (detects whether kernel allows EL0 unprivileged cycle/event reads).
    * `PMCNTENSET_EL0`: Counter Enable Set Register (Cycle counter & Event counters 0-30).
    * `PMCCFILTR_EL0`: Cycle Counter Filter (EL0/EL1/EL2/EL3 execution filters).
  * Architectural event catalog: `L1I_CACHE_REFILL` (0x0001), `L1D_CACHE_REFILL` (0x0003), `L1D_CACHE` (0x0004), `INST_RETIRED` (0x0008), `BR_MIS_PRED` (0x0010), `CPU_CYCLES` (0x0011), `L2D_CACHE` (0x0016), `L2D_CACHE_REFILL` (0x0017), `MEM_ACCESS` (0x0023).
* **`socprobe ardp`**:
  * Hexagon Audio Routing DSP (ARDP) & Low-Power Audio Subsystem (LPASS `0x062D0000`).
  * Digital bus controllers: MIPI Soundwire v1.1 master (`0x06280000`) for digital microphones and smart amplifiers; SLIMbus serial interconnect (`0x062DC000`).
  * Audio Front-End (AFE) PCM routing crossbar, acoustic echo cancellation (AEC), noise suppression, and multi-channel circular DMA rings.
* **`socprobe smi`**:
  * System Management Interface & Shared Memory Interconnect.
  * Inter-Processor Communication (IPC): APCS IPC hardware doorbells (`0x090B5000`) triggering interrupts to aDSP, cDSP, mDSP, and RPM.
  * Shared Memory Point-to-Point (SMP2P `0x0163C000`) 32-bit cross-core lockless status signaling.
  * Physical Shared Memory (SMEM) 2 MB reserved DRAM carveout (`0x86000000` - `0x861FFFFF`).
* **`socprobe psci` / `tz`**:
  * ARM SMCCC (Secure Monitor Call Calling Convention) register protocol (`X0-X7` input, `X0-X3` return).
  * 14 standard PSCI function IDs: `PSCI_VERSION` (0x84000000), `CPU_SUSPEND` (0x84000001 / 0xC4000001), `CPU_OFF` (0x84000002), `CPU_ON` (0x84000003 / 0xC4000003), `AFFINITY_INFO` (0x84000004 / 0xC4000004), `SYSTEM_OFF` (0x84000008), `SYSTEM_RESET` (0x84000009), `SYSTEM_RESET2` (0x84000012 / 0xC4000012), and `MEM_PROTECT` (0x84000013).
  * Qualcomm QSEE/SCM SIP IDs: `TZ_SCM_CMD_SIP` (0x02000101), `TZ_QFPROM_READ_FUSE` (0x02000200), `TZ_QFPROM_WRITE_FUSE` (0x02000300), `TZ_PIL_PAS_AUTH_RESET` (0x02000400), `TZ_MEM_PROTECT_XPU` (0x02000800), and `TZ_SMMU_SECURE_CFG` (0x02000900).
* **`socprobe isp` / `camera`**:
  * Qualcomm Spectra Dual IFE, CSID/CSIPHY 4-lane MIPI receivers, ICP, BPS, and IPE processing pipeline.
  * In-memory Hardware Lookup Tables (LUTs):
    1. **3D-LUT Color Transform**: 17x17x17 tetrahedral mesh (4,913 RGB calibration nodes) for DCI-P3, sRGB, Rec.2020 HDR color space mapping.
    2. **Gamma Correction LUT**: 512 entries per color channel (R, G, B) x 14-bit depth for perceptual non-linear luminance mapping.
    3. **Lens Shading Correction (LSC)**: 17x13 spatial mesh compensating for optical vignetting and chromatic falloff.
    4. **Color Correction Matrix (CCM)**: 3x3 floating-point sensor cross-talk and white balance matrix.
    5. **Bad Pixel Correction (BPC) & Demosaic**: Raw Bayer pixel defect detection and interpolation registers.
* **`socprobe dsp`**:
  * Qualcomm Hexagon QDSP6 v66/v68 processors:
    * **aDSP (Audio DSP)**: Base `0x062D0000`, LPASS (Low-Power Audio Subsystem) for hardware MP3/AAC/FLAC decoding, voice processing, and Soundwire.
    * **cDSP (Compute / AI DSP)**: Base `0x08300000`, Hexagon QDSP6 v68 featuring **HVX** (1024-bit SIMD vector extensions) and **HMX** (INT8/FP16 Tensor NPU matrix accelerator) for on-device AI, NNAPI, and computer vision.
    * **mDSP (Modem Subsystem)**: Base `0x04080000`, 4G/5G Baseband Processor authenticated via TrustZone PIL PAS (SMC `0x02000400`).
  * **IPA (IP Accelerator) Network Offload Engine**:
    * Physical MMIO window `0x01E40000 - 0x01EBFFFF` (768 KB).
    * Hardware IPv4/IPv6 packet routing, NAT translation, header insertion/removal, and hardware firewall rules.
    * GSI (Generic Software Interface) DMA ring buffers for zero-copy CPU-to-modem packet handoff.
* **`socprobe adc` / `a2d`**:
  * Qualcomm PMIC VADC / ADC5 15-bit / 16-bit Sigma-Delta Analog-to-Digital Converter (SPMI 0x3100 / 0x3C00).
  * Analog input multiplexer channels: VBAT (1/3 prescaler), VPH_PWR (1/3 prescaler), VDD_MSM (1/1 prescaler), USB_IN (1/16 prescaler), DIE_TEMP (on-die junction), and XO/PMIC/PA/SYS thermistors.
  * Conversion and timing registers: `ADC_DIG_PARAM` (decimation ratio), `ADC_FAST_AVG` (sample averaging), `ADC_CH_SEL_CTL`, `ADC_EN_CTL`, `ADC_CONV_REQ`, and 16-bit result registers (`ADC_DATA_LOW` / `ADC_DATA_HIGH`).
* **`socprobe noc` / `traffic`**:
  * System Interconnect Fabrics: System NoC (SNOC), Config NoC (CNOC), Multimedia NoC (MMNOC), and BIMC LPDDR4x memory controller arbiter.
  * Traffic Quality of Service (QoS): Port priority levels (0 - 15), dynamic urgency forwarding for real-time display, and token-bucket bandwidth limiters.
  * Hardware Bandwidth Monitors (BWMON): Real-time Adreno GPU and CPU memory bus monitors with hardware sampling windows and throttling interrupts.
* **`socprobe disasm <HEX...>`**:
  * Pure C zero-dependency AArch64 machine-code instruction disassembler.
  * Decodes raw 32-bit machine instructions into assembly mnemonics: MRS/MSR (system registers including PMU counters), ADRP/ADR (PC-relative), LDR/STR (32/64-bit load/store), ADD/SUB, B/BL/BLR/RET, and SMC/HVC calls with automatic ARM SMCCC / PSCI / TrustZone function annotations.

```bash
# Display silicon hardware telemetry overview with zero filesystem dependencies
busybox socprobe status

# Audit CPU architectural registers via inline assembly
busybox socprobe cpu

# Measure real-time core clock frequency via assembly timing loop
busybox socprobe pll

# View GCC/RPM clock tree, RCGR dividers & CBCR branch registers
busybox socprobe clock

# View SPMI PMIC voltage regulator specifications and registers
busybox socprobe pmic

# Inspect PMIC voltage step equations and power models
busybox socprobe volt

# View in-memory physical MMIO hardware memory map (56+ blocks)
busybox socprobe mmio

# Filter MMIO hardware blocks by name or subsystem
busybox socprobe mmio crypto

# Inspect ARM SMCCC PSCI and TrustZone SMC call registers and SIP IDs
busybox socprobe psci

# View Spectra ISP pipeline, CSID/CSIPHY, and 3D/Gamma/LSC hardware LUTs
busybox socprobe isp

# Probe Hexagon DSPs (aDSP, cDSP HVX/HMX AI NPU) and IPA network offloader
busybox socprobe dsp

# Inspect Audio Routing DSP (ARDP), Soundwire & SLIMbus registers
busybox socprobe ardp

# Inspect PMIC VADC / ADC5 analog-to-digital conversion channels and registers
busybox socprobe adc

# View System NoC interconnects, QoS arbiters, and BWMON bandwidth monitors
busybox socprobe noc

# Inspect System Management Interface (SMI) & shared memory mailboxes
busybox socprobe smi

# Probe Silicon Ring Oscillators (ROSC), Aging & CPR/TSENS sensors
busybox socprobe rosc

# Inspect Qualcomm Crypto Engine (CE v5), HWKM & Inline Crypto Engine (ICE)
busybox socprobe crypto

# View Hexagon Tensor Processor (HTP / HMX) & AI accelerators
busybox socprobe ai

# Audit ARMv8 PMU hardware performance counter registers via inline assembly
busybox socprobe pmu

# Disassemble raw AArch64 machine instructions (with automatic SMC & PMU annotations)
busybox socprobe disasm d5380000 d4000003 90000800 91000021 b9400000 d65f03c0
```

---

### 9. Build Targets

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
