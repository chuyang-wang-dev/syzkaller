// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
)

type SubsystemRequirementsOutputs struct {
	Subsystems   []string `jsonschema:"The target subsystems involved (e.g. ['usb', 'net', 'kvm'])."`
	Requirements string   `jsonschema:"Detailed requirements for devices, mounts, protocols, or configs."`
}

var SubsystemRequirementsAgent = &aflow.LLMAgent{
	Name:  "subsystem-requirements-analyzer",
	Model: aflow.Temporary35FlashOnlyModel,
	Outputs: aflow.ValidatedLLMOutputs(
		func(ctx *aflow.Context, state struct{}, outputs SubsystemRequirementsOutputs) (SubsystemRequirementsOutputs, error) {
			if len(outputs.Subsystems) == 0 {
				return outputs, aflow.BadCallError("must identify at least one target subsystem")
			}
			if outputs.Requirements == "" {
				return outputs, aflow.BadCallError("must provide a description of requirements")
			}
			return outputs, nil
		}),
	Tools: aflow.Tools(
		codesearcher.ToolDirIndex,
		codesearcher.ToolReadFile,
		codesearcher.ToolFileIndex,
		codesearcher.ToolDefinitionComment,
		codesearcher.ToolDefinitionSource,
		grepper.Tool,
	),
	TaskType: aflow.FormalReasoningTask,
	Instruction: `You are the Subsystem Requirements Analyzer for seed program generation.
Your goal is to identify the target Linux kernel subsystems and any user-space environment
requirements (device nodes, mounts, configuration flags, or protocols) needed to reach the target PC.

How to identify the Subsystems:
- Identify the subsystems involved (e.g., ['usb', 'net', 'kvm']).
- You can deduce these primarily from the target file path, target function source code,
  inline call chain, and callers (including indirect call sites).

How to identify the Requirements:
- Identify what setup is required to interact with these subsystems:
  - Device nodes: Are there specific device files that user-space must open
    (e.g., "/dev/kvm", "/dev/snd/controlC0", "/dev/net/tun")?
  - Network protocols: Are specific socket domains (e.g., "AF_INET", "AF_NETLINK"),
    types (e.g., "SOCK_RAW"), or protocol families required?
  - Filesystems: Does the code interact with virtual filesystems (e.g. sysfs, procfs,
    debugfs) or require a specific filesystem to be mounted?
  - Kernel configs: Are there specific config dependencies (e.g., "CONFIG_KVM_INTEL")?

Tool Usage Guidance:
- You have access to a limited set of code inspection tools
  (codesearch-definition-source, codesearch-dir-index, read-file, grepper).
- Use these tools ONLY if you need to look up a directory layout, Kconfig flag definition,
  or macro definition to resolve ambiguity.
- Do NOT attempt to recursively trace call graphs backwards.
- Rely primarily on the provided function source and context.`,
	Prompt: `Target File: {{.File}}
Target Line: {{.Line}}
Target Function: {{.FunctionName}}
Target PC: {{printf "0x%x" .PC}}
{{if .Frames}}
PC corresponds to the following inline call chain:
{{range $i, $f := .Frames}}{{$i}}. {{$f.Func}} ({{$f.File}}:{{$f.Line}})
{{end}}{{else if .InnerFunc}}
Note: The exact PC is located inside the inlined function '{{.InnerFunc}}' which is called within the target function.
{{end}}

Function Context:
{{.FunctionSource}}

{{if .IndirectCallers}}
Indirect Callers of Target Function:
{{.IndirectCallers}}
{{end}}

Please output the target subsystems and detailed requirements.`,
}

type EnvironmentProberOutputs struct {
	ProbeExecutionCachedID string `jsonschema:"Cached execution ID of the successful probe program."`
	ProberTerminalError    string `jsonschema:"Terminal blocker if subsystem/devices are not present."`
}

var EnvironmentProberAgent = &aflow.LLMAgent{
	Name:  "environment-prober",
	Model: aflow.Temporary35FlashOnlyModel,
	Outputs: aflow.ValidatedLLMOutputs(
		func(ctx *aflow.Context, state struct{}, outputs EnvironmentProberOutputs) (EnvironmentProberOutputs, error) {
			if outputs.ProberTerminalError != "" {
				if outputs.ProbeExecutionCachedID != "" {
					return outputs, aflow.BadCallError("ProbeExecutionCachedID must be empty if ProberTerminalError is set")
				}
				return outputs, nil
			}
			if outputs.ProbeExecutionCachedID == "" {
				return outputs, aflow.BadCallError(
					"must run a probe program using execute-seed and " +
						"provide ProbeExecutionCachedID or set ProberTerminalError")
			}
			return outputs, nil
		}),
	Tools: aflow.Tools(
		ToolCorpusCodeSearch,
		syzlang.ReadSyzSpec,
		syzlang.SyzGrepper,
		syzlang.ExecuteSeed,
		syzlang.ExecutionTrace,
		syzlang.CoverageFiles,
	),
	TaskType:      aflow.FormalReasoningTask,
	MaxIterations: 100,
	Instruction: `You are the Environment Prober for syzkaller seed generation.
Your goal is to verify if the required subsystems/drivers (identified in Phase 1) are available on the VM.

=== CRITICAL RULE: ENOSYS / ENOENT / EAFNOSUPPORT ===
If the base test seed or any probe program fails with:
- ENOSYS or errno 38 (Function not implemented)
- ENOENT or errno 2 (No such file or directory) for critical device nodes (like /dev/kvm)
- EAFNOSUPPORT / EPROTONOSUPPORT or errno 97/93 (for sockets)
You MUST IMMEDIATELY treat this as a terminal blocker.
- DO NOT call 'get-execution-trace' or 'get-coverage-files'.
- DO NOT attempt to debug, trace, or investigate why the error happened.
- Immediately call 'set-results' with a descriptive 'ProberTerminalError' and exit.
This rule is absolute and has no exceptions. Do not try to bypass it.

=== CRITICAL RULE: FINDING INITIALIZATION PATTERNS ===
- If you need to emulate a USB device or interact with a complex subsystem, use the 'syz-grepper' tool
  to search the 'test/' directory for pseudo-syscall examples (e.g. searching for 'syz_usb_connect')
  to discover how descriptors are defined and how the device is initialized in existing test seeds.

=== CRITICAL RULE: ASYNCHRONOUS DRIVER PROBING ===
- Device connections and emulation (like 'syz_usb_connect') trigger driver loading and probing asynchronously.
- To ensure the background driver registration/probing finishes before the executor exits,
  you MUST always append a sleep call, e.g. 'nanosleep(&(0x7f0000000300)={5, 0}, 0)', after
  the connection pseudo-syscall.

=== CRITICAL RULE: CORPUS CODE SEARCH BUDGET & CONSTRAINTS ===
- Query 'get-corpus-programs' ONLY for target driver-specific functions (e.g.,
  functions matching the target driver prefix, like 'ti_*' or functions
  defined directly in the target driver file).
- Do NOT query generic or core kernel infrastructure functions (e.g.,
  'usb_register_driver', 'usb_deregister', 'usb_serial_probe') unless they
  are explicitly present in the target code snippet or caller trace.
- You have a strict budget: Do not invoke 'get-corpus-programs' more than 3 times per run.

Workflow:
1. Examine the identified Subsystems and Requirements.
2. Query 'get-corpus-programs' for the target function or driver-specific functions.
   If no corpus programs are found, proceed directly to Step 3. Do not attempt
   to guess or search for other generic kernel functions.
3. Use 'syz-grepper' and 'read-syz-spec' tools to find existing syzlang descriptions or test seeds
   showing how the target subsystem/device is initialized or accessed (e.g. socket family, device nodes,
   mount options, sysctl).
4. Write a minimal probe program to test capability presence (e.g., calling socket(), open() on a device node, mount()).
   - For asynchronous connection APIs (like syz_usb_connect), ensure the probe program
     includes a sleep call (like nanosleep) before exit to allow background threads to run.
   - Use the 'code-fixer' tool to execute the probe program. 'code-fixer' will automatically compile,
     run, and resolve any syntax or deserialization errors.
   - CRITICAL evaluation of 'code-fixer' results:
     * Inspect the 'Program' and 'ProgramDiff' outputs returned by 'code-fixer'.
     * A successful execution output does NOT mean the probe is valid if 'code-fixer' modified the
       program too heavily to make it compile (e.g. if it deleted or altered the target connection
       syscalls like syz_usb_connect, socket, or openat).
     * If critical connection/initialization syscalls were removed or commented out in the final Program,
       treat this as a compilation failure and do not conclude that the device is present.
5. If the program runs successfully (no syscall errors), verify if the target driver/subsystem
   code was actually entered using 'get-coverage-files' and 'get-execution-trace'.
   - If the target driver files/functions were not executed at all (suggesting the driver is
     missing/disabled), or if the trace indicates a check inside the driver failed due to
     missing hardware or capability, treat this as a terminal blocker and call 'set-results'
     with 'ProberTerminalError'.
6. Otherwise, if the probe runs successfully and the subsystem is confirmed to be present,
   return its 'ProbeExecutionCachedID' via 'set-results'.
   - CRITICAL: Because syzkaller VM executions are isolated, any setup syscalls (e.g. mounts,
     socket connections, device opens) required for reaching the subsystem must be combined
     into a single unified probe program. Execute this unified program and return its cached ID.
` + syzlang.SandboxConstraints + "\n\n" + syzlang.SyzlangSyntaxConstraints,
	Prompt: `Target File: {{.File}}

Identified Subsystems: {{.Subsystems}}
Requirements: {{.Requirements}}

{{.DescriptionFilesPrompt}}

If the base seed or probe program fails with a terminal error code (like ENOSYS / errno 38, or
ENOENT / errno 2 on critical device nodes), you MUST immediately call 'set-results' with
ProberTerminalError. DO NOT call get-execution-trace. Otherwise, run a probe program, audit
its trace/coverage if necessary, and return ProbeExecutionCachedID.`,
}
