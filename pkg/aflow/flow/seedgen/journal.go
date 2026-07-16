// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
)

type ResourceDef struct {
	Name        string `json:"name"`         // e.g. "fd_usb"
	ProducerSyz string `json:"producer_syz"` // e.g. "syz_usb_connect(...)"
}

type ExecutionRecord struct {
	Iteration              int    `json:"iteration"`
	ExecutionID            string `json:"execution_id,omitempty"`
	DivergenceSyscallIndex int    `json:"divergence_syscall_index"`
	DivergenceFile         string `json:"divergence_file"`
	DivergenceLine         int    `json:"divergence_line"`
	DivergenceReason       string `json:"divergence_reason"`
	KernelCheckFailed      string `json:"kernel_check_failed"`
	SuggestedFix           string `json:"suggested_fix"`
}

type ResearchJournal struct {
	TargetPC            string            `json:"target_pc"`
	Subsystem           string            `json:"subsystem"`
	CurrentStrategy     string            `json:"current_strategy"`
	SyscallSpecs        map[string]string `json:"syscall_specs"`        // Syscall name -> AST description.
	DiscoveredResources []ResourceDef     `json:"discovered_resources"` // Discovered producers.
	History             []ExecutionRecord `json:"history"`              // Log of past attempts.
}

func (rj *ResearchJournal) MergeFeedback(fb *syzlang.ExecutionSummarizerResult) {
	if fb == nil {
		return
	}
	rj.History = append(rj.History, ExecutionRecord{
		Iteration:         len(rj.History) + 1,
		DivergenceReason:  fb.DivergenceReason,
		KernelCheckFailed: fb.KernelConstraintViolated,
		SuggestedFix:      fb.SuggestedFix,
	})
}

type InitializeJournalArgs struct {
	PC                     uint64
	ProbeExecutionCachedID string `json:",omitempty"`
	Subsystems             []string
}

type InitializeJournalResult struct {
	InitialJournal *ResearchJournal
}

var ActionInitializeJournal = aflow.NewFuncAction("initialize-journal",
	func(ctx *aflow.Context, args InitializeJournalArgs) (InitializeJournalResult, error) {
		rj := ResearchJournal{
			TargetPC:        fmt.Sprintf("0x%x", args.PC),
			Subsystem:       strings.Join(args.Subsystems, ", "),
			CurrentStrategy: "",
			History: []ExecutionRecord{
				{
					Iteration:   0,
					ExecutionID: args.ProbeExecutionCachedID,
				},
			},
		}
		return InitializeJournalResult{
			InitialJournal: &rj,
		}, nil
	})

type formattedExecutionRecord struct {
	Iteration              int    `json:"iteration"`
	BaseTestSeed           string `json:"base_test_seed,omitempty"`
	SyzProgram             string `json:"syz_program,omitempty"`
	DivergenceSyscallIndex int    `json:"divergence_syscall_index"`
	DivergenceFile         string `json:"divergence_file,omitempty"`
	DivergenceLine         int    `json:"divergence_line,omitempty"`
	DivergenceReason       string `json:"divergence_reason,omitempty"`
	KernelCheckFailed      string `json:"kernel_check_failed,omitempty"`
	SuggestedFix           string `json:"suggested_fix,omitempty"`
}

type formattedResearchJournal struct {
	TargetPC            string                     `json:"target_pc"`
	Subsystem           string                     `json:"subsystem"`
	CurrentStrategy     string                     `json:"current_strategy"`
	SyscallSpecs        map[string]string          `json:"syscall_specs"`        // Syscall name -> AST description.
	DiscoveredResources []ResourceDef              `json:"discovered_resources"` // Discovered producers.
	History             []formattedExecutionRecord `json:"history"`              // Log of past attempts.
}

func formatJournal(ctx *aflow.Context, rj ResearchJournal) (string, error) {
	formattedHistory := make([]formattedExecutionRecord, len(rj.History))
	for i, rec := range rj.History {
		var baseSeed, syzProg string
		if rec.ExecutionID != "" {
			var err error
			baseSeed, syzProg, err = crash.LoadSeedProgramDetails(ctx, rec.ExecutionID)
			if err != nil {
				return "", fmt.Errorf("failed to load program details for execution %s: %w", rec.ExecutionID, err)
			}
		}
		formattedHistory[i] = formattedExecutionRecord{
			Iteration:              rec.Iteration,
			BaseTestSeed:           baseSeed,
			SyzProgram:             syzProg,
			DivergenceSyscallIndex: rec.DivergenceSyscallIndex,
			DivergenceFile:         rec.DivergenceFile,
			DivergenceLine:         rec.DivergenceLine,
			DivergenceReason:       rec.DivergenceReason,
			KernelCheckFailed:      rec.KernelCheckFailed,
			SuggestedFix:           rec.SuggestedFix,
		}
	}

	formatted := formattedResearchJournal{
		TargetPC:            rj.TargetPC,
		Subsystem:           rj.Subsystem,
		CurrentStrategy:     rj.CurrentStrategy,
		SyscallSpecs:        rj.SyscallSpecs,
		DiscoveredResources: rj.DiscoveredResources,
		History:             formattedHistory,
	}

	b, err := json.MarshalIndent(formatted, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
