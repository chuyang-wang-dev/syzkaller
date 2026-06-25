// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package seedgen implements the AI-guided seed generation workflow.
package seedgen

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/google/syzkaller/docs"
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
	"github.com/google/syzkaller/sys/targets"
)

type SeedGenInputs struct {
	RawPC        string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
	Image        string
	Type         string
	VM           json.RawMessage
	Syzkaller    string
	TargetOS     string
	TargetArch   string
}

func init() {
	aflow.Register[SeedGenInputs, ai.SeedGenOutputs](
		ai.WorkflowSeedGen,
		"generate a syzlang program to reach a specific code position",
		&aflow.Flow{
			Consts: map[string]any{
				"DescriptionFilesPrompt":       syzlang.DescriptionFilesPrompt(targets.Linux),
				"DocProgramSyntax":             docs.ProgramSyntax,
				"DocSyscallDescriptionsSyntax": docs.SyscallDescriptionsSyntax,
			},
			Root: aflow.Pipeline(
				ActionParsePC,
				kernel.Checkout,
				kernel.Build,
				crash.ActionConfigureRunner,
				kernel.SymbolizePC,
				codesearcher.PrepareIndex,
				codesearcher.ActionExtractFunction,
				codesearcher.ActionExtractIndirectCallers,
				&aflow.LLMAgent{
					Name:  "seed-generator",
					Model: aflow.GoodBalancedModel,
					Outputs: aflow.LLMOutputs[struct {
						BaseTestSeed     string `jsonschema:"Optional test seed file to use as base." json:",omitempty"`
						CandidateSeedSyz string `jsonschema:"Valid syz program. Appended to BaseTestSeed." json:",omitempty"`
						GeneratorGiveUp  bool   `jsonschema:"Set true if target is unreachable from userspace or you give up."`
						GeneratorReason  string `jsonschema:"If GeneratorGiveUp is true, provide your reasoning here."`
					}](),
					Tools: aflow.Tools(
						codesearcher.Tools,
						grepper.Tool,
						// gitlog.Tools,
						syzlang.ReadDescription,
						syzlang.ExecuteSeed,
						syzlang.VerifyPCReached,
						syzlang.FileCoverage,
						// syzlang.CoverageFiles,
						syzlang.ExecutionSummarizer,
						syzlang.DisassembleContext,
					),
					TaskType:    aflow.FormalReasoningTask,
					Instruction: seedGenInstruction,
					Prompt:      seedGenPrompt,
				},
				crash.VerifyPCReached,
				ActionFormatOutput,
			),
		},
	)
}

type FormatOutputArgs struct {
	BaseTestSeed     string
	CandidateSeedSyz string
	GeneratorGiveUp  bool
	GeneratorReason  string
	PCReached        bool
}

var ActionFormatOutput = aflow.NewFuncAction("format-output",
	func(ctx *aflow.Context, args FormatOutputArgs) (ai.SeedGenOutputs, error) {
		seedSyz := args.CandidateSeedSyz
		if args.BaseTestSeed != "" {
			data, err := syzlang.GetTestSeed(args.BaseTestSeed)
			if err != nil {
				return ai.SeedGenOutputs{}, aflow.BadCallError("failed to read BaseTestSeed: %v", err)
			}
			seedSyz = string(data) + "\n" + seedSyz
		}
		return ai.SeedGenOutputs{
			SeedSyz: seedSyz,
			Success: args.PCReached,
			GiveUp:  args.GeneratorGiveUp,
			Reason:  args.GeneratorReason,
		}, nil
	})

type ParsePCArgs struct {
	RawPC string
}

type ParsePCResult struct {
	PC uint64
}

var ActionParsePC = aflow.NewFuncAction("parse-pc", parsePCAction)

func parsePCAction(ctx *aflow.Context, args ParsePCArgs) (ParsePCResult, error) {
	raw := strings.TrimSpace(args.RawPC)
	if strings.HasPrefix(raw, "0x") {
		pc, err := strconv.ParseUint(raw[2:], 16, 64)
		return ParsePCResult{PC: pc}, err
	}

	pc, err := strconv.ParseUint(raw, 0, 64)
	if err == nil {
		return ParsePCResult{PC: pc}, nil
	}

	pc, err = strconv.ParseUint(raw, 16, 64)
	return ParsePCResult{PC: pc}, err
}

const seedGenInstruction = `
You are an expert in the Linux kernel fuzzing. Your primary goal is to write a syzkaller program (seed)
to reach a specific PC execution point in the kernel.

You are initially provided with:
- Target file and line number and the target PC address.
- The target function name.
- The C source code of the outermost function containing the target PC.

CRITICAL NOTE ON PC AND SYMBOLIZATION:
Our ultimate goal is to reach the specific physical PC given. The target file and line number are
provided by a symbolizer, which are NOT always accurate due to compiler optimizations or inlining.
You MUST NOT blindly trust the symbolized file and line. If you are unsure where the PC truly points,
you MUST use the 'disassemble-context' tool to view the exact assembly and compiler instrumentations
(e.g., KCOV, ASAN) at that specific PC. Do NOT guess the assembly logic.

Note: The provided Function Context is extracted using the function's symbol name
and represents the outermost non-inlined function to give you broader context. If the target PC actually resides in
an intermediate inlined function, its inline call chain will be provided.
You MUST use the 'codesearch-definition-source' tool to fetch the source code of any intermediate functions
within the call chain to fully understand the execution path, as only the outermost function's source code
is provided in the context.

Your task is to analyze the function context and generate a valid syzkaller program that will execute that code path
to reach the target.
You can use tools to search for other definitions, read files, or run the program to check coverage.

Document about syzkaller program syntax:
===
{{.DocProgramSyntax}}
===

Document about syzlang system call descriptions syntax:
===
CRITICAL NOTE ON OUTPUT FORMAT:
You are provided below with the 'syzlang system call descriptions syntax'. You must use
this documentation strictly as a reference to help you read and understand the available
syscall description files (via the 'read-description' tool). **However, your final
output MUST be a syzkaller program (a seed) conforming to the 'syzkaller program syntax'
document provided above, NOT a syzlang description.**

{{.DocSyscallDescriptionsSyntax}}
===

Here are some examples of valid syzkaller programs:
===
Example 1 (Simple file operations):
r0 = openat(0xffffffffffffff9c, &(0x7f00000000c0)='./file0\x00', 0x0, 0x0)
read(r0, &(0x7f0000000100)=""/100, 100)
close(r0)

Example 2 (Pointers and structs):
r0 = syz_open_dev$evdev(&(0x7f0000000000)='/dev/input/event#\x00', 0x0, 0x1)
ioctl$EVIOCSABS(r0, 0x401c45c0, &(0x7f0000000040)={0x0, 0x0, 0x1, 0x2, 0x3, 0x4})
===

Instruction:
1. Generate one or more syzkaller programs (seeds) that you think reach the target line.
To save time, you are STRONGLY ENCOURAGED to generate MULTIPLE alternative seeds (e.g., testing different flag
combinations, setups, or system calls) to test different hypotheses simultaneously.
If you generate a call that is likely to block, you MUST also generate a corresponding call in the same program
that unblocks it. The executor has a hard limit of 64 system calls per program.
2. Use the 'execute-seed' tool to execute your program(s) in a VM.
If you generated multiple candidate seeds, call 'execute-seed' for EACH of them simultaneously in the same response.
3. CRITICAL: EVERY time you successfully execute a seed using 'execute-seed', you MUST immediately call
the 'check-pc-coverage' tool with the ExecutionCachedID and the target PC to deterministically
check if your exact target PC was reached.
- If you executed multiple seeds in parallel, call 'check-pc-coverage' for all of their ExecutionCachedIDs
in parallel in your next response.
- If 'check-pc-coverage' returns true for any seed, you have succeeded. Call 'set-results' with that successful
seed and finish.
- If 'check-pc-coverage' returns false, the PC was not reached. You should then call the 'execution-summarizer'
tool with the ExecutionCachedID to get a broader summary of the execution path.
You MUST NEVER call 'set-results' with a candidate seed unless you have just successfully verified the seed
using 'execute-seed' and 'check-pc-coverage'.
4. If the target was not reached, you are responsible for root-cause analysis. Use tools like
'codesearch-definition-source', 'grepper', and 'disassemble-context' to examine the kernel source code.
When performing root-cause analysis or discovering execution paths (Steps 4, 5, 6), you MUST formulate multiple theories
and proactively issue MULTIPLE tool calls simultaneously (e.g., calling 'codesearch-find-references' for several
functions at once, or combining 'grepper' with 'get-file-coverage' in the same turn) to gather all necessary context
in a single round-trip.
5. You SHOULD use 'codesearch-find-references', 'codesearch-indirect-targets', and
'codesearch-indirect-callers' to discover execution paths (call chains) leading
to ANY function of interest (the target function, its callers, or related setup functions).
This helps you quickly understand which syscalls or entry points can trigger the code.
For direct function calls, use 'codesearch-find-references' to find callers.
For indirect function calls (e.g., function pointers in structs like '.encrypt = my_func'),
use 'codesearch-indirect-callers' to find all locations where the function pointer is invoked,
or 'codesearch-indirect-targets' to find implementations of an interface method.
6. You can use tools like 'grepper', 'codesearch-dir-index', 'read-file', 'codesearch-definition-source',
'codesearch-find-references', and 'disassemble-context' to lookup Linux source code and explore directories.
Use 'disassemble-context' specifically when you need to see the exact assembly and compiler instrumentations
(e.g., KCOV, ASAN) at a specific crash or coverage PC, or to verify the exact logic of the target PC
if symbolization is inaccurate.
File paths are relative to the kernel source tree (e.g., 'net/ipv4/tcp.c'). Note that 'grepper'
can ONLY grep Linux source and NOT the syzlang descriptions.
7. You can see a list of 'Available Syscall Description Files' at the bottom of the
prompt. If you need to read their contents, use the 'read-description' tool. Do NOT
use 'grepper' or other code search tools to read syzlang description files.
If you need to use complex pseudo-syscalls with highly structured binary data 
(such as compressed filesystem images like syz_mount_image):
- Use 'read-description' to grep the 'test/' directory for examples. The output
  will be prefixed with the filename (e.g., 'test/syz_mount_image_btrfs_0:6: ...').
- The payload itself will be truncated (e.g. '... <truncated>'). DO NOT try to
  copy the truncated string!
- Instead, extract the filename and pass it to the 'BaseTestSeed' argument in
  'execute-seed' (and in your final output). Provide only the additional
  syscalls you want to append in the 'ReproSyz' / 'CandidateSeedSyz' fields.
8. Decide: If the target line is unreachable from userspace, or if you want to give up for other reasons, 
set GeneratorGiveUp to true and provide a GeneratorReason
by reasoning why the wanted code position is unreachable, for instace, because we don't have proper
syzlang description to reach the code position yet, or the code position is in a function that is not
called from userspace (for instance, it is only called upon kernel initialization, or it's called from 
another function, which you can verify using 'codesearch-find-references', and you can try to reach 
that calling function). If you strongly believe the line is executed but the coverage tool does not reflect it
(e.g., due to compiler optimizations or debug info issues), you MUST set GeneratorGiveUp to true and explain
this discrepancy in GeneratorReason.
CRITICAL: If you have made multiple attempts (e.g. > 3) and are making no progress, or if you realize
a missing syzlang description prevents you from constructing the required arguments, you MUST give up
instead of infinitely trying and reasoning.
9. Otherwise, repeat by going to step 1.
10. Output the final syzkaller program in the 'CandidateSeedSyz' field. If you gave up, also set
'GeneratorGiveUp' to true and provide a 'GeneratorReason' in the 'GeneratorReason' field.
` + common.InstructionDontMakeAssumptionsAboutSourceCode

const seedGenPrompt = `
Target File: {{.File}}
Target Line: {{.Line}}
Target Function: {{.FunctionName}}
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
{{.DescriptionFilesPrompt}}

Please generate one or more candidate syzkaller programs (seeds) following the syzkaller program
syntax defined above, to reach the PC address {{printf "0x%x" .PC}}.
Test your hypotheses in parallel. If you give up, provide the reason why it is not possible.
`
