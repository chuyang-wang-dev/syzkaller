// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
)

type SummarizerArgs struct {
	ExecutionCachedID string `jsonschema:"The cached ID of the execution."`
	SyzProgram        string `jsonschema:"The full generated syzkaller program."`
	TargetPC          string `jsonschema:"The exact target PC address."`
	TargetFile        string `jsonschema:"The exact file path containing the Target PC."`
	Question          string `jsonschema:"What you want the subagent to analyze."`
}

var ExecutionSummarizer = &aflow.LLMTool[SummarizerArgs]{
	Name:     "execution-summarizer",
	Model:    aflow.GoodBalancedModel,
	TaskType: aflow.FormalReasoningTask,
	Description: "Summarizes the execution of a syzkaller program, identifying the deepest point of execution. " +
		"You MUST pass the ExecutionCachedID, the syzlang program source code, " +
		"and your target constraints (including TargetFile and TargetPC) in your query.",
	Instruction: summarizerInstruction,
	Tools: aflow.Tools(
		CoverageFiles, FileCoverage, ExecutionTrace,
	),
	PromptBuilder: func(ctx *aflow.Context, args SummarizerArgs) (string, error) {
		stateMap := ctx.StateMap()
		b, _ := json.Marshal(stateMap)
		var state reproduceState
		json.Unmarshal(b, &state)

		coverage, err := crash.LoadCoverage(ctx, args.ExecutionCachedID)
		if err != nil {
			return "", err
		}

		var traceBuilder strings.Builder
		traceBuilder.WriteString("Execution Trace (All Syscalls):\n")
		for i := range coverage {
			tr := processSyscallTrace(i, coverage[i], ExecutionTraceArgs{IncludeNoise: false})
			traceBuilder.WriteString(fmt.Sprintf("Syscall %d:\n", tr.CallIndex))
			for _, frame := range tr.Trace {
				traceBuilder.WriteString(fmt.Sprintf("  %s\n", frame))
			}
			traceBuilder.WriteString("\n")
		}

		covStr := "No target file provided."
		if args.TargetFile != "" {
			covRes, err := getFileCoverage(ctx, state, FileCoverageArgs{
				ExecutionCachedID: args.ExecutionCachedID,
				Filename:          args.TargetFile,
			})
			if err == nil {
				covStr = strings.Join(covRes.Snippets, "\n")
			} else {
				covStr = fmt.Sprintf("Failed to get coverage for %s: %v", args.TargetFile, err)
			}
		}

		return fmt.Sprintf(`Target Execution Details:
- ExecutionCachedID: %s
- Target PC: %s

Syzlang Program:
%s

%s
Coverage for Target File (%s):
%s

Question from Parent Agent:
%s`, args.ExecutionCachedID, args.TargetPC, args.SyzProgram,
			traceBuilder.String(), args.TargetFile, covStr, args.Question), nil
	},
}

const summarizerInstruction = `
You are an expert in analyzing kernel executions. Your task is to compress and summarize the execution of a syzkaller
program, identifying the deepest point of execution before divergence.
You must base all your claims on the provided execution trace and coverage information.
If you don't have enough information, you MUST state that instead of guessing.

The main agent has provided you with:
1. The ExecutionCachedID.
2. The full syzkaller program that was executed.
3. The target constraint (e.g., target file, and PC address).
4. The formatted execution traces for all syscalls.
5. The source code coverage snippets for the target file.

Instructions:
1. Review the initial Execution Trace and File Coverage provided by the main agent. The initial
   trace might be truncated if it is too long.
2. If the trace is truncated, use the 'get-execution-trace' tool with the 'Offset' and 'Limit'
   arguments to paginate through the omitted middle sections of the trace.
3. Use the 'get-coverage-files' tool to explore other files hit during execution. After you see the list
   of covered files, if there are multiple interesting files, you MUST use the 'get-file-coverage' tool
   simultaneously for ALL of those files in the same response. Do not fetch coverage one by one.
4. Find the deepest point or the exact divergence point in the trace.
5. Provide a concise, highly relevant summary back to the main agent. Include:
   - A brief summary of the trace leading up to the divergence.

CRITICAL: Do NOT attempt to reason about *why* the execution diverged (e.g., failed checks, missing flags).
Your job is strictly to summarize *what* happened and report the deepest execution point.
The parent agent will handle the root-cause analysis.
`
