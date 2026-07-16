// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/symbolizer"
)

type ExecutionSummarizerArgs struct {
	ExecutionCachedID string `jsonschema:"Optional cached execution ID (defaults to last failed)."`
	Question          string `jsonschema:"The question to answer about this execution."`
}

type ExecutionSummarizerResult struct {
	DivergenceSyscallIndex   int    `jsonschema:"Syscall index of divergence, or -1."`
	DivergenceFile           string `jsonschema:"Divergence file path (relative to kernel src) or empty."`
	DivergenceLine           int    `jsonschema:"Divergence line number or 0."`
	DivergenceReason         string `jsonschema:"Reason why execution diverged."`
	KernelConstraintViolated string `jsonschema:"Kernel code constraint that failed (e.g. if (size > 10))."`
	SuggestedFix             string `jsonschema:"Actionable suggestion on how to modify the syzlang program."`
	TerminalError            string `jsonschema:"Terminal environmental blocker if unrecoverable, empty otherwise."`
}

type executionSummarizerState struct {
	File                        string
	PC                          uint64
	LastFailedExecutionCachedID string
}

var ExecutionSummarizer = &aflow.StructuredLLMTool[
	executionSummarizerState, ExecutionSummarizerArgs, ExecutionSummarizerResult,
]{
	Name:        "execution-summarizer",
	Model:       aflow.Temporary35FlashOnlyModel,
	TaskType:    aflow.FormalReasoningTask,
	Description: "Analyzes the execution of a syzkaller program to explain why it behaved the way it did.",
	Instruction: summarizerInstruction,
	Tools: aflow.Tools(
		CoverageFiles, FileCoverage, ExecutionTrace, DisassembleContext,
		codesearcher.Tools, GetExecutedProgram, VerifyPCReached,
	),
	Prompt: `Analyze the execution of program ` +
		`{{if .ExecutionCachedID}}{{.ExecutionCachedID}}{{else}}{{.LastFailedExecutionCachedID}}{{end}} ` +
		`to answer the question:
{{if .Question}}{{.Question}}{{else}}Why did this program fail to reach the target PC?{{end}}

Target file: {{.File}}
Target PC: {{printf "0x%x" .PC}}`,
	ValidatedOutputs: func(
		ctx *aflow.Context, state executionSummarizerState,
		args ExecutionSummarizerArgs, results ExecutionSummarizerResult,
	) (ExecutionSummarizerResult, error) {
		cachedID := args.ExecutionCachedID
		if cachedID == "" {
			cachedID = state.LastFailedExecutionCachedID
		}
		if cachedID == "" {
			return results, aflow.BadCallError("no execution ID found to validate coverage")
		}
		reached, err := crash.CheckPCInCoverage(ctx, cachedID, state.PC)
		if err != nil {
			return results, fmt.Errorf("failed to check PC in coverage: %w", err)
		}
		if reached {
			return results, aflow.BadCallError("target PC 0x%x was reached; nothing to summarize", state.PC)
		}
		if results.TerminalError != "" {
			if results.DivergenceReason != "" || results.SuggestedFix != "" {
				return results, aflow.BadCallError("TerminalError is set; DivergenceReason and SuggestedFix must be empty")
			}
		} else {
			if results.DivergenceReason == "" || results.SuggestedFix == "" {
				return results, aflow.BadCallError(
					"PC was not reached; DivergenceReason and SuggestedFix " +
						"must not be empty unless TerminalError is set")
			}
		}

		if results.DivergenceFile != "" {
			coverage, err := crash.LoadCoverage(ctx, cachedID)
			if err != nil {
				return results, fmt.Errorf("failed to load coverage for validation: %w", err)
			}
			foundFile, foundLine := checkCoverageLocation(
				coverage, results.DivergenceFile, results.DivergenceLine)
			if !foundFile {
				return results, aflow.BadCallError(
					"DivergenceFile %q was not executed in the coverage trace",
					results.DivergenceFile)
			}
			if results.DivergenceLine > 0 && !foundLine {
				return results, aflow.BadCallError(
					"DivergenceLine %d in %q was not executed in coverage (no close lines found)",
					results.DivergenceLine, results.DivergenceFile)
			}
		}

		return results, nil
	},
}

const summarizerInstruction = `
You are an expert in analyzing kernel executions. Your task is to comprehensively analyze the execution of a syzkaller
program, identifying the deepest point of execution before divergence and explaining why it diverged.
You must base all your claims on the execution trace, program details, and coverage information.
If you don't have enough information, you MUST state that instead of guessing.

The main agent has provided you with:
1. The target constraint (e.g., target file, and PC address).
2. The ExecutionCachedID of the execution to analyze.

Instructions:
1. Use the 'get-executed-program' tool to load the syzlang program that was executed.
2. Use the 'get-execution-trace' tool to fetch the execution trace.
3. Use the 'check-pc-coverage' tool to evaluate if the target PC was reached. This is your primary capability probe.
4. Use the 'get-coverage-files' tool to explore other files hit during execution. After you see the list
   of covered files, if there are multiple interesting files, you MUST use the 'get-file-coverage' tool
   simultaneously for ALL of those files in the same response. Do not fetch coverage one by one.
5. Find the deepest point or the exact divergence point in the trace.
6. Provide a highly detailed and comprehensive summary back to the main agent.

You MUST call the 'set-results' tool with the following structured outputs:
- DivergenceSyscallIndex: 0-based index of the syscall in the syzlang program
  where execution diverged, or -1 if the target PC was reached or not found.
- DivergenceFile: File path (relative to kernel src tree root, e.g. "fs/read_write.c")
  where execution diverged, or empty if the target PC was reached.
- DivergenceLine: Line number in the DivergenceFile where the execution diverged,
  or 0 if the target PC was reached, or if the exact line is unknown or mapped to line 0 in inline frames.
- DivergenceReason: Reason why execution diverged. Must be non-empty if the
  target PC was not reached, unless TerminalError is set.
- KernelConstraintViolated: Kernel code constraint that failed (e.g. if (size > 10)).
- SuggestedFix: Actionable suggestion on how to modify the syzlang program.
  Must be non-empty if the target PC was not reached, unless TerminalError is set.
- TerminalError: Terminal environmental blocker (e.g. missing KVM node) if
  unrecoverable, empty otherwise. If this is set, DivergenceReason and
  SuggestedFix must be empty.

CRITICAL: You MUST reason about *why* the execution diverged and provide a high-level, semantic 
summary of the failure (e.g., 'syscall X returned EINVAL because flag Y was missing'). You MUST 
include ALL possible information relevant to the divergence, such as variable values, error codes, 
and control flow conditions, so the manager can fully understand the failure context and adjust 
its strategy. Do not focus excessively on low-level syntax.
`

// checkCoverageLocation scans the execution coverage trace to verify if the
// given file and line number were executed. It returns foundFile=true if the
// file was executed, and foundLine=true if the line (or a line within +/- 5
// lines of it to account for symbolization shift) was executed.
func checkCoverageLocation(coverage [][]symbolizer.Frame, file string, line int) (foundFile, foundLine bool) {
	for _, callcov := range coverage {
		for _, frame := range callcov {
			if frame.File == file {
				foundFile = true
				if line > 0 {
					diff := frame.Line - line
					if diff < 0 {
						diff = -diff
					}
					if diff <= 5 {
						foundLine = true
					}
				}
			}
		}
	}
	return foundFile, foundLine
}

var ExecutionSummarizerAgent = &aflow.LLMAgent{
	Name:        "execution-summarizer-agent",
	Model:       aflow.Temporary35FlashOnlyModel,
	TaskType:    aflow.FormalReasoningTask,
	Outputs:     aflow.LLMOutputs[ExecutionSummarizerResult](),
	Instruction: ExecutionSummarizer.Instruction,
	Tools:       ExecutionSummarizer.Tools,
	Prompt: `Please analyze the execution of program {{.LastFailedExecutionCachedID}}
to answer the question: Why did this program fail to reach the target PC?
Target file: {{.File}}
Target PC: {{printf "0x%x" .PC}}`,
}
