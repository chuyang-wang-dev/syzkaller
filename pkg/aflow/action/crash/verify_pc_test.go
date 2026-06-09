// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/require"
)

func TestVerifyPCReached_CachedHit(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	// Create dummy image file.
	imagePath := filepath.Join(t.TempDir(), "dummy_image")
	err := os.WriteFile(imagePath, []byte("dummy-image"), 0644)
	require.NoError(t, err)

	candidateSyz := "openat(0x0, 0x0, 0x0, 0x0)"

	args := VerifyPCReachedArgs{
		PC:               0x123456,
		CandidateSeedSyz: candidateSyz,
		Image:            imagePath,
		Type:             "qemu",
		VM:               json.RawMessage(`{"qemu_args": "dummy"}`),
		KernelCommit:     "commit1",
		KernelConfig:     "config1",
	}

	// Build exact desc that ExecuteSeedFunc uses.
	cfg := mgrconfig.DefaultValues()
	cfg.RawTarget = "linux/amd64"
	opts := csource.DefaultOpts(cfg)
	opts.Threaded = true
	opts.RepeatTimes = 1
	reproOpts := string(opts.Serialize())

	// Normalize candidateSyz exactly like ExecuteSeedFunc does.
	pt, _ := prog.GetTarget("linux", "amd64")
	p, _ := pt.Deserialize([]byte(candidateSyz), prog.Strict)
	candidateSyzNorm := string(p.Serialize())

	desc := "seed-exec: kernel commit " + args.KernelCommit +
		", kernel config hash " + hash.String(args.KernelConfig) +
		", image hash " + hash.String([]byte("dummy-image")) +
		", vm " + args.Type +
		", vm config hash " + hash.String(args.VM) +
		", syz repro hash " + hash.String([]byte(candidateSyzNorm)) +
		", opts hash " + hash.String([]byte(reproOpts))

	// Pre-populate the cache with a cachedExecution object that has coverage for our PC.
	mockedCoverage := [][]symbolizer.Frame{
		{
			{PC: 0x123456, Func: "dummy_func", File: "dummy.c", Line: 10},
		},
	}
	_, _, err = aflow.CacheObject(ctx, "seed-exec", desc, func() (cachedExecution, error) {
		return cachedExecution{
			Coverage: mockedCoverage,
		}, nil
	})
	require.NoError(t, err)

	// Now run the function. It should hit the cache and find the PC reached.
	res, err := VerifyPCReachedFunc(ctx, args)
	require.NoError(t, err)
	require.True(t, res.PCReached)

	// Test with a PC that is not in the mocked coverage.
	args.PC = 0x999999
	res, err = VerifyPCReachedFunc(ctx, args)
	require.NoError(t, err)
	require.False(t, res.PCReached)
}
