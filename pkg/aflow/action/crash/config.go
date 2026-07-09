// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/sys/targets"
)

type TargetConfig struct {
	AgentName    string
	TargetArch   string
	Syzkaller    string
	Image        string
	Type         string
	VM           json.RawMessage
	KernelSrc    string
	KernelObj    string
	KernelCommit string
	KernelConfig string
	StraceBin    string
	NeedStrace   bool
	Procs        int
	Snapshot     bool
	Sandbox      string
}

func BuildConfig(args TargetConfig, workdir string) (*mgrconfig.Config, error) {
	var vmConfig map[string]any
	if err := json.Unmarshal(args.VM, &vmConfig); err != nil {
		return nil, fmt.Errorf("failed to parse VM config: %w", err)
	}

	targetArch := args.TargetArch
	image := args.Image

	switch args.Type {
	case "qemu":
		vmConfig["kernel"] = filepath.Join(args.KernelObj, filepath.FromSlash(build.LinuxKernelImage(targetArch)))
	case "gce":
		params := build.Params{
			TargetOS:     targets.Linux,
			TargetArch:   targetArch,
			UserspaceDir: image,
			OutputDir:    workdir,
		}
		kernelPath := filepath.Join(args.KernelObj, filepath.FromSlash(build.LinuxKernelImage(targetArch)))
		if err := build.EmbedLinuxKernel(params, kernelPath); err != nil {
			return nil, fmt.Errorf("failed to embed kernel into image: %w", err)
		}
		image = filepath.Join(workdir, "image")
	}

	vmCfg, err := json.Marshal(vmConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VM config: %w", err)
	}

	cfg := mgrconfig.DefaultValues()
	cfg.Name = args.AgentName
	cfg.RawTarget = targets.Linux + "/" + targetArch
	cfg.Workdir = workdir
	cfg.Syzkaller = args.Syzkaller
	cfg.KernelObj = args.KernelObj
	cfg.KernelSrc = args.KernelSrc
	cfg.Image = image
	cfg.Type = args.Type
	cfg.VM = vmCfg
	if args.Procs > 0 {
		cfg.Procs = args.Procs
	} else {
		cfg.Procs = 1
	}
	if args.Snapshot && args.Type != "qemu" {
		return nil, fmt.Errorf("snapshot mode is only supported with qemu VM type")
	}
	cfg.Snapshot = args.Snapshot
	if args.Sandbox != "" {
		cfg.Sandbox = args.Sandbox
	}
	cfg.Experimental.DescriptionsMode = mgrconfig.AnyDescriptionsMode
	if args.NeedStrace && args.StraceBin != "" {
		cfg.StraceBin = args.StraceBin
		cfg.StraceBinOnTarget = false
	}

	if err := mgrconfig.SetTargets(cfg); err != nil {
		return nil, err
	}
	if err := mgrconfig.Complete(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
