// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"syscall"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

var ExecuteSeed = aflow.NewFuncTool("execute-seed", executeSeed, `
Tool executes the given syz program in a VM to collect coverage.
It allows calls to block without hanging the execution by running in threaded mode.
It returns an ExecutionCachedID even if the execution times out or doesn't crash.
`)

type ExecuteSeedArgs struct {
	BaseTestSeed string `jsonschema:"Optional path to a test seed file." json:",omitempty"`
	ReproSyz     string `jsonschema:"Syz program to execute. Appended to BaseTestSeed if provided." json:",omitempty"`
}

type CallError struct {
	Index    int    `jsonschema:"0-based index of the failed syscall."`
	CallName string `jsonschema:"Name of the syscall that failed."`
	Errno    int32  `jsonschema:"The raw error code (errno) returned."`
	Error    string `jsonschema:"String representation of the error."`
}

type ExecuteSeedResult struct {
	ExecutionCachedID string      `jsonschema:"Cached ID. Pass to coverage tools to explore executed code."`
	CallErrors        []CallError `jsonschema:"List of calls that failed. Empty if all succeeded."`
}

func executeSeed(ctx *aflow.Context, state reproduceState, args ExecuteSeedArgs) (ExecuteSeedResult, error) {
	fullSyz := args.ReproSyz
	if args.BaseTestSeed != "" {
		data, err := GetTestSeed(args.BaseTestSeed)
		if err != nil {
			return ExecuteSeedResult{}, aflow.BadCallError("failed to read BaseTestSeed: %v", err)
		}
		fullSyz = string(data) + "\n" + args.ReproSyz
	}

	if fullSyz == "" {
		return ExecuteSeedResult{}, aflow.BadCallError("syz program cannot be empty")
	}

	pt, err := prog.GetTarget(targets.Linux, state.TargetArch)
	if err != nil {
		return ExecuteSeedResult{}, err
	}
	p, err := pt.Deserialize([]byte(fullSyz), prog.Strict)
	if err != nil {
		return ExecuteSeedResult{}, aflow.BadCallError("%v", err)
	}
	if len(p.Calls) > 64 {
		return ExecuteSeedResult{}, aflow.BadCallError("program has %d calls, exceeding the limit of 64", len(p.Calls))
	}

	if state.Image == "" || state.VM == nil {
		// VM configuration is missing, we can only verify the program compiles.
		return ExecuteSeedResult{}, nil
	}

	reproArgs := crash.ReproduceArgs{
		TargetArch:   state.TargetArch,
		Syzkaller:    state.Syzkaller,
		Image:        state.Image,
		Type:         state.Type,
		VM:           state.VM,
		ReproSyz:     fullSyz,
		KernelSrc:    state.KernelSrc,
		KernelObj:    state.KernelObj,
		KernelCommit: state.KernelCommit,
		KernelConfig: state.KernelConfig,
	}

	executionCachedID, err := crash.ExecuteSeedFunc(ctx, reproArgs)
	if err != nil {
		return ExecuteSeedResult{}, err
	}

	callErrors, err := crash.LoadCallErrors(ctx, executionCachedID)
	if err != nil {
		return ExecuteSeedResult{}, err
	}

	var structuredErrors []CallError
	for i, errCode := range callErrors {
		if errCode != 0 {
			callName := "unknown"
			if i < len(p.Calls) {
				callName = p.Calls[i].Meta.Name
			}
			structuredErrors = append(structuredErrors, CallError{
				Index:    i,
				CallName: callName,
				Errno:    errCode,
				Error:    syscall.Errno(errCode).Error(),
			})
		}
	}

	return ExecuteSeedResult{
		ExecutionCachedID: executionCachedID,
		CallErrors:        structuredErrors,
	}, nil
}
