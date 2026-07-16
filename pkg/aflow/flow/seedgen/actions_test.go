// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
	"github.com/stretchr/testify/require"
)

type mockCachedExecution struct {
	BaseTestSeed string
	GeneratedSyz string
}

func TestMergeJournalAction(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	// Seed the cache with a mock probe execution.
	mockProbe := mockCachedExecution{
		BaseTestSeed: "",
		GeneratedSyz: "syz_init()",
	}
	_, probeCachedID, err := aflow.CacheObject(
		ctx, "seed-exec", "probe-execution-desc",
		func() (mockCachedExecution, error) {
			return mockProbe, nil
		})
	require.NoError(t, err)

	// Seed the cache with a mock execution details.
	mockExec := mockCachedExecution{
		BaseTestSeed: "test/usb.txt",
		GeneratedSyz: "syz_usb_connect()",
	}
	_, cachedID, err := aflow.CacheObject(
		ctx, "seed-exec", "test-execution-desc",
		func() (mockCachedExecution, error) {
			return mockExec, nil
		})
	require.NoError(t, err)

	// Initialize the journal.
	journal := ResearchJournal{
		TargetPC:        "0xffffffff81000000",
		CurrentStrategy: "Initial strategy",
		History: []ExecutionRecord{
			{
				Iteration:   0,
				ExecutionID: probeCachedID,
			},
		},
	}

	// Prepare arguments.
	feedback := syzlang.ExecutionSummarizerResult{
		DivergenceSyscallIndex:   1,
		DivergenceFile:           "fs/read_write.c",
		DivergenceLine:           42,
		DivergenceReason:         "syscall returned EINVAL",
		KernelConstraintViolated: "if (arg == 0)",
		SuggestedFix:             "change arg to 1",
	}

	args := MergeJournalArgs{
		ResearchJournal:             &journal,
		ExecutionSummarizerResult:   feedback,
		LastFailedExecutionCachedID: cachedID,
	}

	// Run the action function.
	res, err := mergeJournalAction(ctx, args)
	require.NoError(t, err)

	updatedJournal := res.ResearchJournal
	require.NotNil(t, updatedJournal)
	require.Equal(t, journal.TargetPC, updatedJournal.TargetPC)
	require.Equal(t, journal.CurrentStrategy, updatedJournal.CurrentStrategy)
	require.Len(t, updatedJournal.History, 2)

	// Verify the new history entry.
	newEntry := updatedJournal.History[1]
	require.Equal(t, 2, newEntry.Iteration)
	require.Equal(t, cachedID, newEntry.ExecutionID)
	require.Equal(t, 1, newEntry.DivergenceSyscallIndex)
	require.Equal(t, "fs/read_write.c", newEntry.DivergenceFile)
	require.Equal(t, 42, newEntry.DivergenceLine)
	require.Equal(t, "syscall returned EINVAL", newEntry.DivergenceReason)
	require.Equal(t, "if (arg == 0)", newEntry.KernelCheckFailed)
	require.Equal(t, "change arg to 1", newEntry.SuggestedFix)

	// Verify ResearchJournalText.
	require.NotEmpty(t, res.ResearchJournalText)
	require.Contains(t, res.ResearchJournalText, "syz_usb_connect()")
	require.Contains(t, res.ResearchJournalText, "test/usb.txt")
}

func TestMergeJournalAction_GeneratorError(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	journal := ResearchJournal{
		TargetPC: "0xffffffff81000000",
		History:  []ExecutionRecord{},
	}

	args := MergeJournalArgs{
		ResearchJournal: &journal,
		GeneratorError:  "compiler failed",
	}

	res, err := mergeJournalAction(ctx, args)
	require.NoError(t, err)

	updatedJournal := res.ResearchJournal
	require.NotNil(t, updatedJournal)
	require.Len(t, updatedJournal.History, 1)
	require.Equal(t, "Generator Error: compiler failed", updatedJournal.History[0].DivergenceReason)
	require.Empty(t, updatedJournal.History[0].ExecutionID)
}
