// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// ExecuteSeedFunc boots the kernel and runs a single test program to collect coverage.
// It differs from ReproduceFuncWithCoverage in that it forces threaded mode and
// returns coverage data even if the execution fails with an error (e.g., timeout).
func ExecuteSeedFunc(ctx *aflow.Context, args ReproduceArgs) (string, error) {
	imageData, err := os.ReadFile(args.Image)
	if err != nil {
		return "", err
	}

	if args.TargetArch == "" {
		args.TargetArch = targets.AMD64
	}

	// We force threaded mode to allow blocking calls to not hang the whole execution.
	// If ReproOpts is empty, we generate default opts and set Threaded = true.
	// If it's not empty, we assume the caller (or LLM) knows what it's doing,
	// or we could try to parse and modify it. For simplicity, we just force it if empty.
	var execOpts flatrpc.ExecOpts
	if args.ReproOpts == "" {
		cfg := mgrconfig.DefaultValues()
		cfg.RawTarget = targets.Linux + "/" + args.TargetArch
		opts := csource.DefaultOpts(cfg)
		opts.Threaded = true
		opts.RepeatTimes = 1
		args.ReproOpts = string(opts.Serialize())
		execOpts.ExecFlags |= flatrpc.ExecFlagThreaded
	} else {
		opts, err := csource.DeserializeOptions([]byte(args.ReproOpts))
		if err == nil {
			opts.RepeatTimes = 1
			args.ReproOpts = string(opts.Serialize())
			if opts.Threaded {
				execOpts.ExecFlags |= flatrpc.ExecFlagThreaded
			}
		}
	}

	execOpts.ExecFlags |= flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal

	target, err := prog.GetTarget(targets.Linux, args.TargetArch)
	if err != nil {
		return "", err
	}

	// We perform normalization so that the cache key is calculated correctly.
	p, err := target.Deserialize([]byte(args.ReproSyz), prog.Strict)
	if err != nil {
		return "", err
	}
	args.ReproSyz = string(p.Serialize())

	desc := fmt.Sprintf("seed-exec: kernel commit %v, kernel config hash %v, image hash %v,"+
		" vm %v, vm config hash %v, syz repro hash %v, opts hash %v",
		args.KernelCommit, hash.String(args.KernelConfig), hash.String(imageData),
		args.Type, hash.String(args.VM), hash.String(args.ReproSyz), hash.String(args.ReproOpts))

	cached, cachedID, err := aflow.CacheObject(ctx, "seed-exec", desc, func() (cachedExecution, error) {
		var res cachedExecution
		workdir, err := ctx.TempDir()
		if err != nil {
			return res, err
		}

		cfg, err := buildConfig(args, workdir)
		if err != nil {
			return res, err
		}
		cfg.Timeouts.NoOutputRunningTime = 2 * time.Minute

		rm, err := ctx.GetRunnerManager(cfg)
		if err != nil {
			return res, fmt.Errorf("failed to get runner manager: %w", err)
		}

		runRes, crashRep, err := rm.Submit(ctx.Context, p, execOpts)
		if err != nil {
			return res, aflow.FlowError(fmt.Errorf("RunnerManager Submit failed: %w", err))
		}

		log.Logf(0, "VM Console Output:\n%s", runRes.Output)
		if crashRep != nil {
			res.BugTitle = crashRep.Title
			res.Report = string(crashRep.Report)
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
		args := ReproduceArgs{
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
