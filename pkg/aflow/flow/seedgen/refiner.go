// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
)

type StrategyRefinerOutputs struct {
	RefinedStrategy string `jsonschema:"The refined strategy to reach the target PC."`
	BaseTestSeed    string `jsonschema:"Optional base test seed to use (e.g. test/usb.txt)."`
	SuggestedSyz    string `jsonschema:"Syzlang program skeleton or suggestion based on the strategy."`
}

var StrategyRefinerAgent = &aflow.LLMAgent{
	Name:  "seed-strategy-refiner",
	Model: aflow.Temporary35FlashOnlyModel,
	Outputs: aflow.ValidatedLLMOutputs(
		func(ctx *aflow.Context, state struct{}, outputs StrategyRefinerOutputs) (StrategyRefinerOutputs, error) {
			if outputs.RefinedStrategy == "" {
				return outputs, aflow.BadCallError("must provide RefinedStrategy")
			}
			return outputs, nil
		}),
	Tools: aflow.Tools(
		&SeedgenAnalyzer,
		codesearcher.Tools,
		grepper.Tool,
	),
	TaskType: aflow.FormalReasoningTask,
	Instruction: `You are the Strategy Refiner for syzkaller seed generation.
Your job is to analyze the research journal (which contains the history of attempts, failures, and previous strategies)
and refine the strategy to reach the target PC.

You have access to codesearch and analyzer tools to help you verify assumptions or research the subsystem further:
- Use 'seedgen-analyzer' to ask logical questions about the subsystem design or API usage patterns.
- Use codesearch tools (like 'grep-search' or 'view-file') to inspect kernel files, checks, and structure definitions.

Analyze the history of all attempts in the journal:
- Compare successive attempts in the history: what program changes led to deeper
  coverage, and what changes caused new failures/regressions?
- Look at the sequence of previous attempts: trace how our progress has
  evolved—are we overall getting closer to executing the target PC compared to earlier iterations?
- If we got stuck (e.g. compiler error, VM crash, wrong path), how can we avoid
  it based on what failed in past iterations?
- Do we need a different base test seed?

Output the RefinedStrategy, an optional BaseTestSeed, and a SuggestedSyz program
(or skeleton) that the Generator should try.
` + common.InstructionDontMakeAssumptionsAboutSourceCode,
	Prompt: `Target File: {{.File}}
Target Line: {{.Line}}
Target Function: {{.FunctionName}}
Target PC: {{printf "0x%x" .PC}}

Research Journal:
{{.ResearchJournalText}}

{{if .ProberError}}WARNING: The Environment Prober execution failed/timed out
without verifying dependencies (error: {{.ProberError}}).
This means we do not have verification that the target hardware emulation,
driver, or virtual node is functional in the VM. Keep this environment constraint in mind.
- You may need to adapt the strategy to account for driver probing delays,
  check connection syscalls (like syz_usb_connect) carefully,
  or handle setup errors (like EBUSY, ENODEV, or ENOENT).
- If you conclude that the target is unreachable because of this prober verification failure,
  you must explicitly state this in your RefinedStrategy so that the Generator agent knows to give up.{{end}}

Refine the strategy and provide the next step.`,
}
