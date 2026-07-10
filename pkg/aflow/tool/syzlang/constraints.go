// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

const SandboxConstraints = `SANDBOX AND FILESYSTEM CONSTRAINTS:
- Sandbox Restrictions: Absolute paths starting with '/' and relative paths starting with '..' are
  strictly forbidden in filenames due to sandboxing. Do NOT attempt to use escaping sequences like
  '\/' or '\.' to bypass this. Filenames must be simple relative paths (e.g. 'file0' or './file1')
  which will be safely created and opened in the current sandboxed working directory of the executor
  inside the VM.
- Device & Sysfs access: You MAY NOT arbitrarily open /sys or /dev files unless they are already
  configured and present in the VM environment.
  * What you CAN do instead: If you need to open a specific device, procfs, or sysfs file, look for
    predefined specialized syscall variants (like 'openat$kvm', 'openat$fuse', or 'openat$6lowpan_enable')
    where the path is defined as a static constant string, as these are permitted. You can find these
    variants by searching with 'syz-grepper'.
- Predefined Environments & Setup: You MAY NOT write complex initialization sequences or mount
  commands from scratch (e.g., manually mounting a filesystem or crafting USB handshake packets).
  * What you CAN do instead: Use pseudo-syscalls (like 'syz_open_dev', 'syz_mount_image') or find
    existing working setups in test seeds (using 'syz-grepper' with PathPrefix='test') to configure
    complex devices or filesystem mounts.
- CWD Resolution: Relative paths are resolved against the executor's current working directory inside the VM.`

const SyzlangSyntaxConstraints = "- Single-line constraint: Multi-line syscall statements are " +
	"syntax-invalid (cause unexpected eof). " +
	"Each syscall invocation and its variable assignment must reside entirely on a single line. " +
	"Do NOT split a syscall invocation across multiple lines.\n" +
	"- Inline comments: Comments inside syscall statements/arguments are forbidden. " +
	"Comments starting with '#' must only be placed on their own separate lines.\n" +
	"- String Literals: Use single quotes ('...') for text, filenames, and device paths. " +
	"Null-terminate C-strings with \\x00 (e.g., '/dev/kvm\\x00').\n" +
	"- Escaping: The only valid escape sequences inside strings are \\x (hex) and \\\\ (backslash). " +
	"Escaping forward slashes (\\/) or dots (\\.) causes syntax errors.\n" +
	"- Byte Payloads: Use double quotes (\"...\") EXCLUSIVELY for raw hexadecimal sequences " +
	"(e.g., \"00abcdef\"). Using them for normal text will cause decoding errors."
