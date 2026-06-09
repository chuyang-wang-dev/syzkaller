// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
)

type SummarizerInputs struct {
	LastFailedExecutionCachedID string
	File                        string
	PC                          uint64
}

type SummarizerOutputs struct {
	LastFailureSummary string `jsonschema:"Comprehensive summary of the execution analysis."`
}

var ActionPrepareSummarizer = aflow.NewFuncAction("prepare-summarizer", prepareSummarizer)

type prepareSummarizerArgs struct {
	LastFailedExecutionCachedID string
}

type prepareSummarizerResults struct {
	ExecutionSummaryContext string
}

func prepareSummarizer(ctx *aflow.Context, args prepareSummarizerArgs) (prepareSummarizerResults, error) {
	return prepareSummarizerResults{}, nil
}

var SummarizerAgent = &aflow.LLMAgent{
	Name:     "execution-summarizer",
	Model:    aflow.TemporaryFlashOnlyModel,
	TaskType: aflow.FormalReasoningTask,
	Outputs: aflow.ValidatedLLMOutputs(
		func(ctx *aflow.Context, state struct{}, outputs SummarizerOutputs) (SummarizerOutputs, error) {
			return outputs, nil
		}),
	Instruction: summarizerInstruction,
	Tools: aflow.Tools(
		CoverageFiles, FileCoverage, ExecutionTrace, DisassembleContext, codesearcher.Tools,
	),
	Prompt: `{{.ExecutionSummaryContext}}`,
}

const summarizerInstruction = `
You are an expert in analyzing kernel executions. Your task is to comprehensively analyze the execution of a syzkaller
program, identifying the deepest point of execution before divergence and explaining why it diverged.
You must base all your claims on the provided execution trace and coverage information.
If you don't have enough information, you MUST state that instead of guessing.

The main agent has provided you with:
1. The target constraint (e.g., target file, and PC address).
2. The full syzkaller program that was executed.
3. The formatted execution traces for all syscalls.
4. The source code coverage snippets for the target file.

Instructions:
1. Use the 'get-executed-program' tool to load the syzlang program that was executed.
2. Use the 'get-execution-trace' tool with 'SyscallIndex' set to the 0-based index of the call statement
   in the program (e.g. 0 for 1st call, -1 for background coverage).
3. Use the 'get-coverage-files' tool to explore other files hit during execution. After you see the list
   of covered files, if there are multiple interesting files, you MUST use the 'get-file-coverage' tool
   simultaneously for ALL of those files in the same response. Do not fetch coverage one by one.
4. Find the deepest point or the exact divergence point in the trace.
5. Provide a highly detailed and comprehensive summary back to the main agent.

CRITICAL: You MUST reason about *why* the execution diverged and provide a high-level, semantic 
summary of the failure (e.g., 'syscall X returned EINVAL because flag Y was missing'). You MUST 
include ALL possible information relevant to the divergence, such as variable values, error codes, 
and control flow conditions, so the manager can fully understand the failure context and adjust 
its strategy. Do not focus excessively on low-level syntax.
`
