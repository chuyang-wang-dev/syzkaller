// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"fmt"
	"maps"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
)

type MergeJournalArgs struct {
	InitialJournal                    *ResearchJournal `json:",omitempty"`
	ResearchJournal                   *ResearchJournal `json:",omitempty"`
	syzlang.ExecutionSummarizerResult                  // Embedded to parse flat fields from state.
	LastFailedExecutionCachedID       string
	GeneratorGiveUp                   bool
	GeneratorReason                   string
	GeneratorError                    string
}

type MergeJournalResult struct {
	ResearchJournal     *ResearchJournal
	ResearchJournalText string
}

// ActionMergeJournal merges feedback into the journal.
var ActionMergeJournal = aflow.NewFuncAction("merge-journal", mergeJournalAction)

func mergeJournalAction(ctx *aflow.Context, args MergeJournalArgs) (MergeJournalResult, error) {
	var journal *ResearchJournal
	if args.ResearchJournal != nil {
		journal = args.ResearchJournal
	} else {
		if args.InitialJournal == nil {
			return MergeJournalResult{}, fmt.Errorf("both ResearchJournal and InitialJournal are nil")
		}
		journal = cloneJournal(args.InitialJournal)
	}

	if args.LastFailedExecutionCachedID != "" || args.GeneratorError != "" || args.GeneratorGiveUp {
		reason := args.DivergenceReason
		if args.GeneratorError != "" {
			reason = fmt.Sprintf("Generator Error: %s", args.GeneratorError)
		} else if args.GeneratorGiveUp {
			reason = fmt.Sprintf("Generator Gave Up: %s", args.GeneratorReason)
		}

		journal.History = append(journal.History, ExecutionRecord{
			Iteration:              len(journal.History) + 1,
			ExecutionID:            args.LastFailedExecutionCachedID,
			DivergenceSyscallIndex: args.DivergenceSyscallIndex,
			DivergenceFile:         args.DivergenceFile,
			DivergenceLine:         args.DivergenceLine,
			DivergenceReason:       reason,
			KernelCheckFailed:      args.KernelConstraintViolated,
			SuggestedFix:           args.SuggestedFix,
		})
	}

	txt, err := formatJournal(ctx, *journal)
	if err != nil {
		return MergeJournalResult{}, err
	}

	return MergeJournalResult{
		ResearchJournal:     journal,
		ResearchJournalText: txt,
	}, nil
}

func cloneJournal(src *ResearchJournal) *ResearchJournal {
	if src == nil {
		return nil
	}
	dst := &ResearchJournal{
		TargetPC:        src.TargetPC,
		Subsystem:       src.Subsystem,
		CurrentStrategy: src.CurrentStrategy,
		SyscallSpecs:    make(map[string]string),
	}
	maps.Copy(dst.SyscallSpecs, src.SyscallSpecs)
	dst.DiscoveredResources = append([]ResourceDef(nil), src.DiscoveredResources...)
	dst.History = append([]ExecutionRecord(nil), src.History...)
	return dst
}

type CheckProberTerminalErrorArgs struct {
	ProberTerminalError string `json:",omitempty"`
}

// ActionCheckProberTerminalError aborts the workflow if the dependency prober encountered a terminal error.
var ActionCheckProberTerminalError = aflow.NewFuncAction("check-prober-terminal-error",
	func(ctx *aflow.Context, args CheckProberTerminalErrorArgs) (struct{}, error) {
		if args.ProberTerminalError != "" {
			return struct{}{}, aflow.FlowError(fmt.Errorf("subsystem dependency error: %s", args.ProberTerminalError))
		}
		return struct{}{}, nil
	})

// ActionClearIterationState clears stale iteration variables from state before a new run.
var ActionClearIterationState = aflow.NewFuncAction("clear-iteration-state",
	func(ctx *aflow.Context, args struct{}) (struct{}, error) {
		ctx.StateMap()["DivergenceSyscallIndex"] = -1
		ctx.StateMap()["DivergenceReason"] = ""
		ctx.StateMap()["KernelConstraintViolated"] = ""
		ctx.StateMap()["SuggestedFix"] = ""
		ctx.StateMap()["TerminalError"] = ""
		ctx.StateMap()["GeneratorError"] = ""
		ctx.StateMap()["GeneratorGiveUp"] = false
		ctx.StateMap()["GeneratorReason"] = ""
		ctx.StateMap()["ExecutionCachedID"] = ""
		return struct{}{}, nil
	})
