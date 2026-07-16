// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

const SandboxConstraints = `SANDBOX AND FILESYSTEM CONSTRAINTS:
- Sandbox Restrictions: Absolute paths starting with '/' and relative paths starting with '..' are
  strictly forbidden in filenames due to sandboxing. Do NOT attempt to use escaping sequences like
  '\/' or '\.' to bypass this. Filenames must be simple relative paths (e.g. 'file0' or './file1')
  which will be safely created and opened in the current sandboxed working directory of the executor
  inside the VM.
- Device & Sysfs access: You MAY NOT arbitrarily open /sys or /dev files with absolute paths starting
  with '/' (like '/dev/ttyUSB0') in filename arguments, as they escape the sandbox.
  * What you CAN do instead:
    1. If specialized syscall variants (like 'openat$kvm', 'openat$fuse') exist, use them.
    2. If you need to open an arbitrary character or block device, use 'syz_open_dev$char(0xc, major, minor)'
       or 'syz_open_dev$block(0xb, major, minor)' which bypasses sandbox restrictions.
- Reasoning on Custom Device Nodes (mknod):
  - If you create a device node using 'mknod' to bypass sandbox checks, and opening or calling ioctl
    on it returns ENOTTY (Inappropriate ioctl for device) or ENODEV (No such device):
    * Scenario A: You forgot to set up/connect the emulated hardware (e.g., calling 'syz_usb_connect' or
      configuring the virtual interface) in the SAME execution program. Since VM executions are isolated,
      the device node won't be backed by an active driver.
    * Scenario B: You did perform the setup in the same program, but it still fails. This means the
      driver is missing from the kernel config or failed to probe. Treat this as a terminal blocker.
- Asynchronous Drivers and Hardware Setup:
  - Emulated hardware connections or interface configurations are transient and exist ONLY for the duration
    of the test program.
  - To test if an emulated/virtual driver is functional, you MUST perform both the hardware setup/connection
    and the device node interaction (e.g., 'openat', 'ioctl') in a single unified program.
    Do NOT separate connection/setup calls and device access calls into separate execute-seed steps.
  - Device connection and initialization (like 'syz_usb_connect') execute asynchronously in background kernel threads.
    To ensure that the asynchronous driver probe finishes before the program exits, you MUST append a sleep/delay call
    (e.g., 'nanosleep(&(0x7f0000000300)={1, 0}, 0)') immediately after the connection pseudo-syscall.
- Predefined Environments & Setup: You MAY NOT write complex initialization sequences or mount
  commands from scratch (e.g., manually mounting a filesystem or crafting USB handshake packets).
  * What you CAN do instead: Use pseudo-syscalls (like 'syz_open_dev', 'syz_mount_image') or find
    existing working setups in test seeds (using 'syz-grepper' with PathPrefix='test') to configure
    complex devices or filesystem mounts.
- CWD Resolution: Relative paths are resolved against the executor's current working directory inside the VM.`

const SyzlangSyntaxConstraints = `Syzlang Syntax Constraints:
- Single-line constraint: Multi-line syscall statements are syntax-invalid (cause unexpected eof).
  Each syscall invocation and its variable assignment must reside entirely on a single line.
  Do NOT split a syscall invocation across multiple lines.
- Inline comments: Comments inside syscall statements/arguments are forbidden.
  Comments starting with '#' must only be placed on their own separate lines.
- String Literals: Use single quotes ('...') for text, filenames, and device paths.
  Null-terminate C-strings with \x00 (e.g., '/dev/kvm\x00').
- Escaping: The only valid escape sequences inside strings are \x (hex) and \\ (backslash).
  Escaping forward slashes (\/) or dots (\.) causes syntax errors.
- Byte Payloads: Use double quotes ("...") EXCLUSIVELY for raw hexadecimal sequences
  (e.g., "00abcdef"). Using them for normal text will cause decoding errors.
- Pointer Squashing (ANY Union): When a syscall requires a pointer to a complex nested struct
  (such as 'usb_device_descriptor' in 'syz_usb_connect'), do NOT write nested brackets
  '{{ "{{" }}...{{ "}}" }}' or type templates.
  Instead, pass a raw hex string representation of the struct using the built-in 'ANY' union:
  &(0x7f0000000000)=ANY=[@ANYBLOB="<hex_string>"].
  Note that double quotes are required for the hex string inside ANY.`
