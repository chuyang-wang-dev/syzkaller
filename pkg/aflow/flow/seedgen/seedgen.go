// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package seedgen implements the AI-guided seed generation workflow.
package seedgen

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/syzkaller/docs"
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
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
				"DocPseudoSyscalls":            docs.PseudoSyscalls,
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
				&aflow.DoWhile{
					While:         "ContinueLoop",
					MaxIterations: 250,
					Do: aflow.Pipeline(
						ManagerAgent,
						ActionCheckGiveUp,
						&aflow.If{
							Condition: "RunCoder",
							Do: aflow.Pipeline(
								CoderAgent,
								ActionVerifyPCReached,
								&aflow.If{
									Condition: "RunSummarizer",
									Do: aflow.Pipeline(
										ActionPrepareSummarizer,
										SummarizerAgent,
										ActionAppendSummary,
									),
								},
							),
						},
						ActionUpdateLoopState,
					),
				},
				ActionFormatOutput,
			),
		},
	)
}

type FormatOutputArgs struct {
	BaseTestSeed      string
	ExecutionCachedID string
	GeneratorGiveUp   bool
	GeneratorReason   string
	PCReached         bool
}

var ActionFormatOutput = aflow.NewFuncAction("format-output",
	func(ctx *aflow.Context, args FormatOutputArgs) (ai.SeedGenOutputs, error) {
		seedSyz := ""
		if args.ExecutionCachedID != "" {
			var err error
			seedSyz, err = crash.LoadProgram(ctx, args.ExecutionCachedID)
			if err != nil {
				return ai.SeedGenOutputs{}, aflow.BadCallError("failed to read program from cache: %v", err)
			}
		}
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

type UpdateLoopStateArgs struct {
	GeneratorGiveUp bool
	PCReached       bool
}

type UpdateLoopStateResult struct {
	ContinueLoop string
}

type CheckGiveUpArgs struct {
	GeneratorGiveUp bool
}

type CheckGiveUpResult struct {
	RunCoder bool
}

var ActionCheckGiveUp = aflow.NewFuncAction("check-give-up",
	func(ctx *aflow.Context, args CheckGiveUpArgs) (CheckGiveUpResult, error) {
		return CheckGiveUpResult{RunCoder: !args.GeneratorGiveUp}, nil
	})

var ActionUpdateLoopState = aflow.NewFuncAction("update-loop-state",
	func(ctx *aflow.Context, args UpdateLoopStateArgs) (UpdateLoopStateResult, error) {
		if args.GeneratorGiveUp || args.PCReached {
			return UpdateLoopStateResult{ContinueLoop: ""}, nil
		}
		return UpdateLoopStateResult{ContinueLoop: "yes"}, nil
	})

type VerifyPCReachedArgs struct {
	ExecutionCachedID string
	PC                uint64
	GeneratorGiveUp   bool
}

type VerifyPCReachedResult struct {
	PCReached     bool
	RunSummarizer bool
}

var ActionVerifyPCReached = aflow.NewFuncAction("seedgen-verify-pc-reached",
	func(ctx *aflow.Context, args VerifyPCReachedArgs) (VerifyPCReachedResult, error) {
		if args.GeneratorGiveUp || args.ExecutionCachedID == "" {
			return VerifyPCReachedResult{PCReached: false, RunSummarizer: false}, nil
		}
		reached, err := crash.CheckPCInCoverage(ctx, args.ExecutionCachedID, args.PC)
		if err != nil {
			return VerifyPCReachedResult{PCReached: false, RunSummarizer: false}, err
		}
		return VerifyPCReachedResult{PCReached: reached, RunSummarizer: !reached}, nil
	})

type PrepareSummarizerArgs struct {
	ExecutionCachedID string
	PC                uint64
	File              string
}

type PrepareSummarizerResult struct {
	ExecutionSummarizerPrompt string
}

var ActionPrepareSummarizer = aflow.NewFuncAction("prepare-summarizer",
	func(ctx *aflow.Context, args PrepareSummarizerArgs) (PrepareSummarizerResult, error) {
		candidateSeedSyz, err := crash.LoadProgram(ctx, args.ExecutionCachedID)
		if err != nil {
			return PrepareSummarizerResult{}, err
		}
		toolArgs := syzlang.SummarizerArgs{
			ExecutionCachedID: args.ExecutionCachedID,
			SyzProgram:        candidateSeedSyz,
			TargetPC:          fmt.Sprintf("0x%x", args.PC),
			TargetFile:        args.File,
			Question:          "Analyze why this execution failed to reach the target PC.",
		}
		prompt, err := syzlang.ExecutionSummarizer.PromptBuilder(ctx, toolArgs)
		if err != nil {
			return PrepareSummarizerResult{}, err
		}
		return PrepareSummarizerResult{ExecutionSummarizerPrompt: prompt}, nil
	})

var SummarizerAgent = &aflow.LLMAgent{
	Name:        syzlang.ExecutionSummarizer.Name,
	Model:       syzlang.ExecutionSummarizer.Model,
	TaskType:    syzlang.ExecutionSummarizer.TaskType,
	Instruction: syzlang.ExecutionSummarizer.Instruction,
	Tools:       syzlang.ExecutionSummarizer.Tools,
	Prompt:      "{{.ExecutionSummarizerPrompt}}",
	Outputs: aflow.LLMOutputs[struct {
		Summary string `jsonschema:"The summary of the execution divergence."`
	}](),
}

type AppendSummaryArgs struct {
	Summary               string
	FailedStrategySummary string
}

type AppendSummaryResult struct {
	FailedStrategySummary string
}

var ActionAppendSummary = aflow.NewFuncAction("append-summary",
	func(ctx *aflow.Context, args AppendSummaryArgs) (AppendSummaryResult, error) {
		newSummary := args.FailedStrategySummary
		if newSummary != "" {
			newSummary += "\n\n"
		}
		newSummary += args.Summary
		return AppendSummaryResult{FailedStrategySummary: newSummary}, nil
	})
