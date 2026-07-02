// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"

	"github.com/google/syzkaller/pkg/aflow"
)

var VerifyPCReached = aflow.NewFuncAction("verify-pc-reached", VerifyPCReachedFunc)

type VerifyPCReachedArgs struct {
	PC               uint64
	BaseTestSeed     string
	CandidateSeedSyz string
	TargetOS         string
	TargetArch       string
	Syzkaller        string
	Image            string
	Type             string
	VM               json.RawMessage
	KernelSrc        string
	KernelObj        string
	KernelCommit     string
	KernelConfig     string
}

type VerifyPCReachedResult struct {
	PCReached bool
}

func VerifyPCReachedFunc(ctx *aflow.Context, args VerifyPCReachedArgs) (VerifyPCReachedResult, error) {
	fullSyz, _, err := CombineSyzPrograms(args.BaseTestSeed, args.CandidateSeedSyz)
	if err != nil {
		return VerifyPCReachedResult{PCReached: false}, aflow.BadCallError("%v", err)
	}

	if fullSyz == "" {
		return VerifyPCReachedResult{PCReached: false}, nil
	}

	executeArgs := ExecuteSeedArgs{
		TargetConfig: TargetConfig{
			TargetArch:   args.TargetArch,
			Syzkaller:    args.Syzkaller,
			Image:        args.Image,
			Type:         args.Type,
			VM:           args.VM,
			KernelSrc:    args.KernelSrc,
			KernelObj:    args.KernelObj,
			KernelCommit: args.KernelCommit,
			KernelConfig: args.KernelConfig,
		},
		SeedSyz: fullSyz,
	}

	cachedID, err := ExecuteSeedFunc(ctx, executeArgs, args.BaseTestSeed, args.CandidateSeedSyz)
	if err != nil {
		// If the seed is malformed or execution fails, it means the PC was not reached.
		return VerifyPCReachedResult{PCReached: false}, nil
	}

	reached, err := CheckPCInCoverage(ctx, cachedID, args.PC)
	return VerifyPCReachedResult{PCReached: reached}, err
}

func CheckPCInCoverage(ctx *aflow.Context, executionCachedID string, targetPC uint64) (bool, error) {
	coverage, err := LoadCoverage(ctx, executionCachedID)
	if err != nil {
		return false, err
	}

	// TODO: For the future, we should reject non-KCOV call PC lines. KCOV typically
	// only records the PC at the start of a basic block, so exact PC matching here
	// will fail if the provided PC is in the middle of a basic block.
	for _, callcov := range coverage {
		for _, frame := range callcov {
			if frame.PC == targetPC {
				return true, nil
			}
		}
	}

	return false, nil
}
