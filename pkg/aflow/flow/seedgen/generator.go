// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
)

type GeneratorOutputs struct {
	ExecutionCachedID string `jsonschema:"Cached ID of your final attempt. MUST be provided unless giving up."`
	GeneratorGiveUp   bool   `jsonschema:"Set true if target is unreachable."`
	GeneratorReason   string `jsonschema:"Reason for giving up."`
}

var GeneratorAgent = &aflow.LLMAgent{
	Name:  "seed-generator",
	Model: aflow.Temporary35FlashOnlyModel,
	Outputs: aflow.ValidatedLLMOutputs(
		func(ctx *aflow.Context, state struct{}, outputs GeneratorOutputs) (GeneratorOutputs, error) {
			if !outputs.GeneratorGiveUp {
				if outputs.ExecutionCachedID == "" {
					return outputs, aflow.BadCallError("must provide ExecutionCachedID if not giving up")
				}
				_, _, err := crash.LoadSeedProgramDetails(ctx, outputs.ExecutionCachedID)
				if err != nil {
					return outputs, aflow.BadCallError("invalid ExecutionCachedID %q: %v", outputs.ExecutionCachedID, err)
				}
			}
			return outputs, nil
		}),
	Tools: aflow.Tools(
		syzlang.CodeFixer,
		syzlang.ReadSyzSpec,
		syzlang.SyzGrepper,
	),
	TaskType:      aflow.FormalReasoningTask,
	MaxIterations: 300,
	Instruction: `You are the Generator translating a strategy into a syzlang program.
Your goal is to reach a specific target PC using the provided RefinedStrategy.

Your job:
1. Read the RefinedStrategy, SuggestedSyz, and BaseTestSeed from the prompt.
2. Translate the strategy into a valid syzlang program.
   - Use 'syz-grepper' and 'read-syz-spec' to find syscall definitions and test seeds.
   - You can use the SuggestedSyz as a starting point.
3. Call 'code-fixer' to debug and execute the program.
   - If you have a BaseTestSeed, pass it to code-fixer.
   - Define acceptable call errors if the target PC is in an error path.
4. If code-fixer returns a valid ExecutionCachedID:
   - Output it as ExecutionCachedID.
5. If code-fixer fails or you cannot translate the strategy:
   - You can try to adjust the syzlang translation and retry code-fixer.
   - If you cannot make it work, give up by setting GeneratorGiveUp = true and provide a reason.

CRITICAL SYZLANG CONSTRAINTS:
- Program Structure: Syzlang programs must contain ONLY system call invocations and variable assignments.
  Assume all types, structs, and resources are already defined.
  Never define custom types, structs, or resources inline.
` + syzlang.SyzlangSyntaxConstraints + `
` + syzlang.SandboxConstraints,
	Prompt: `Target File: {{.File}}
Target Line: {{.Line}}
Target Function: {{.FunctionName}}
Target PC: {{printf "0x%x" .PC}}

Refined Strategy:
{{.RefinedStrategy}}

Base Test Seed:
{{.BaseTestSeed}}

Suggested Syz:
{{.SuggestedSyz}}

{{if .ProberError}}WARNING: The Environment Prober execution failed/timed out
without verifying dependencies (error: {{.ProberError}}).
This means we do not have verification that the target hardware emulation,
driver, or virtual node is functional in the VM. Keep this environment constraint in mind.
- You may need to adapt the strategy to account for driver probing delays,
  check connection syscalls (like syz_usb_connect) carefully,
  or handle setup errors (like EBUSY, ENODEV, or ENOENT).
- If you conclude that the target is unreachable because of this prober verification failure,
  you must give up cleanly (e.g. by setting GeneratorGiveUp = true
  and explaining the reason in GeneratorReason).{{end}}

{{.DescriptionFilesPrompt}}

Generate and test the syzlang program using 'code-fixer'.`,
}
