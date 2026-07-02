// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type ExecuteSeedArgs struct {
	TargetConfig
	SeedSyz string
}

// ExecuteSeedFunc boots the kernel and runs a single test program to collect coverage.
// It differs from ReproduceFuncWithCoverage in that it forces threaded mode and
// returns coverage data even if the execution fails with an error (e.g., timeout).
func ExecuteSeedFunc(ctx *aflow.Context, args ExecuteSeedArgs, baseTestSeed, generatedSyz string) (string, error) {
	imageData, err := os.ReadFile(args.Image)
	if err != nil {
		return "", err
	}

	if args.TargetArch == "" {
		args.TargetArch = targets.AMD64
	}

	target, err := prog.GetTarget(targets.Linux, args.TargetArch)
	if err != nil {
		return "", err
	}

	// We perform normalization so that the cache key is calculated correctly.
	p, err := target.Deserialize([]byte(args.SeedSyz), prog.Strict)
	if err != nil {
		return "", err
	}
	args.SeedSyz = string(p.Serialize())

	desc := fmt.Sprintf("seed-exec: kernel commit %v, kernel config hash %v, image hash %v,"+
		" vm %v, vm config hash %v, syz repro hash %v",
		args.KernelCommit, hash.String(args.KernelConfig), hash.String(imageData),
		args.Type, hash.String(args.VM), hash.String(args.SeedSyz))

	cached, cachedID, err := aflow.CacheObject(ctx, "seed-exec", desc, func() (cachedExecution, error) {
		var res cachedExecution
		res.BaseTestSeed = baseTestSeed
		res.GeneratedSyz = generatedSyz
		workdir, err := ctx.TempDir()
		if err != nil {
			return res, err
		}

		cfg, err := buildConfig(args.TargetConfig, workdir)
		if err != nil {
			return res, err
		}
		cfg.Timeouts.NoOutputRunningTime = 2 * time.Minute

		rm, err := ctx.GetRunnerManager(cfg)
		if err != nil {
			return res, fmt.Errorf("failed to get runner manager: %w", err)
		}

		runRes, err := rm.Submit(ctx.Context, p)
		if err != nil {
			return res, aflow.FlowError(fmt.Errorf("RunnerManager Submit failed: %w", err))
		}

		log.Logf(1, "VM Console Output:\n%s", runRes.Output)

		crashes := rm.RecentCrashes()
		if len(crashes) > 0 {
			res.BugTitle = crashes[0].Title
			res.Report = fmt.Sprintf("The kernel crashed after one of the previous executions:\n%s", string(crashes[0].Report))
		}

		if runRes.Status == queue.ExecFailure && runRes.Err != nil {
			res.Error = runRes.Err.Error()
		}

		if runRes.Info != nil {
			for _, call := range runRes.Info.Calls {
				res.CallErrors = append(res.CallErrors, call.Error)
			}
			var err error
			res.Coverage, err = extractCoverage(runRes.Info, cfg)
			if err != nil {
				return res, err
			}
		}

		return res, nil
	})

	if err != nil {
		return "", err
	}

	if cached.Error != "" {
		return "", errors.New(cached.Error)
	}

	return cachedID, nil
}

func extractCoverage(info *flatrpc.ProgInfo, cfg *mgrconfig.Config) ([][]symbolizer.Frame, error) {
	var cov [][]uint64
	for _, call := range info.Calls {
		cov = append(cov, call.Cover)
	}
	if info.Extra != nil && len(info.Extra.Cover) > 0 {
		cov = append(cov, info.Extra.Cover)
	} else {
		cov = append(cov, nil)
	}
	if len(cov) > 0 {
		args := TargetConfig{
			TargetArch: cfg.TargetArch,
			Type:       cfg.Type,
			KernelObj:  cfg.KernelObj,
			KernelSrc:  cfg.KernelSrc,
		}
		symbolized, err := symbolize(args, cov)
		if err != nil {
			return nil, fmt.Errorf("failed to symbolize coverage: %w", err)
		}
		return symbolized, nil
	}
	return nil, nil
}

// CombineSyzPrograms concatenates a base test seed (read from disk) and a generated syz program.
// It returns the combined program, the number of lines in the base seed, and any error encountered.
func CombineSyzPrograms(baseTestSeed, generatedSyz string) (string, int, error) {
	if baseTestSeed == "" {
		return generatedSyz, 0, nil
	}
	data, err := sys.Files.ReadFile(path.Join("linux", baseTestSeed))
	if err != nil {
		return "", 0, fmt.Errorf("failed to read BaseTestSeed: %w", err)
	}
	baseLines := len(strings.Split(string(data), "\n"))
	return string(data) + "\n" + generatedSyz, baseLines, nil
}

// BaseSeedCallCount parses the base test seed and returns the number of calls it contains.
func BaseSeedCallCount(baseTestSeed, targetArch string) (int, error) {
	if baseTestSeed == "" {
		return 0, nil
	}
	data, err := sys.Files.ReadFile(path.Join("linux", baseTestSeed))
	if err != nil {
		return 0, fmt.Errorf("failed to read BaseTestSeed: %w", err)
	}
	pt, err := prog.GetTarget(targets.Linux, targetArch)
	if err != nil {
		return 0, err
	}
	p, err := pt.Deserialize(data, prog.NonStrict)
	if err != nil {
		return 0, err
	}
	return len(p.Calls), nil
}
