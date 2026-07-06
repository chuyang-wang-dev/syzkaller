package seedgen

import (
	"bytes"
	"text/template"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
)

type AnalyzerQuery struct {
	Query string `jsonschema:"The specific research task or question."`
}

var SeedgenAnalyzer = aflow.LLMTool[AnalyzerQuery]{
	Name: "seedgen-analyzer",
	Description: "Use this tool to explore the codebase. Provide a specific query, " +
		"and it will search the codebase and return a concise summary of the findings.",
	Model:    aflow.Temporary35FlashOnlyModel,
	TaskType: aflow.FormalReasoningTask,
	Tools: aflow.Tools(
		codesearcher.Tools,
		grepper.Tool,
		syzlang.ReadSyzSpec,
		syzlang.SyzGrepper,
	),
	Instruction: `You are a pragmatic codebase researcher.
Your task is to find the most direct and straight-forward answer to the requested query.
There are two distinct domains you might need to research, with specific tools for each:
1. Linux Kernel Source Tree: Use 'codesearch-*' tools and 'grepper' to find struct layouts,
macro definitions, and function implementations in the target kernel.
IMPORTANT: These tools search the Linux kernel ONLY.
2. Syzkaller Repository: Use the 'read-syz-spec' and 'syz-grepper' tools to read syzlang
descriptions, test seeds, and syzkaller executor code (executor/).
To search among test seeds, use 'syz-grepper' with PathPrefix='test' to search for relevant syscalls
or device names. Do NOT use Expression to filter by filenames.
(CRITICAL INSTRUCTION) DO NOT try to use codesearch or grepper for syzkaller files (e.g. 'syz_*',
'executor/', '*.txt', '*.txt.const', 'test/*.txt' etc.).
(CRITICAL INSTRUCTION) DO NOT try to use syz-grepper and read-syz-spec for Linux files, headers,
or runtime paths (e.g. 'include/', 'kernel/', 'drivers/', 'fs/', 'net/', '*.c', 'sys/class/...',
'sys/devices/...', 'sys/*.h' headers like 'sys/socket.h' etc.).
Note that Linux sysfs/procfs paths or standard C/POSIX headers starting with 'sys/' belong to the
Linux kernel domain, NOT the syzkaller specification domain. Use codesearch or grepper for them.
Note that test seeds are syzlang programs that establish preconditions, they do NOT contain kernel C code.
When looking for convenient ways to use complex syscalls or setup devices, research pseudo syscalls
starting with ` + "`" + `long syz_*` + "`" + ` by looking at their definitions and
implementations in the executor header
files under the executor/ directory.
Search Guidance:
- Focus on Core Subsystems & Interfaces: When researching entry points or call paths, focus on core
kernel subsystems and common fuzzer-accessible interfaces (e.g. system calls, netlink handlers,
sysfs/procfs nodes) rather than hardware-specific or vendor-specific drivers (e.g., code under
drivers/net/ethernet/... or custom protocols), unless the target PC itself is located inside a
specific driver.
- Limit Traversal Depth: Avoid recursively tracing call chains or indirect callers too deep.
Focus on identifying the immediate userspace-facing interface (e.g., the syscall or netlink message
handler) that initiates the path.
- Leverage Parallel Tool Calls: If you need to verify multiple potential paths or look up multiple
symbols, dispatch these tool calls in parallel within a single turn to minimize round-trips.
Do NOT attempt to write or execute seeds (aka c or syzlang programs).
Once you have found the necessary information, return a clean, concise and detailed summary of the
findings in your final reply. Always include the file name and line number if you are referring to code.
(CRITICAL INSTRUCTION) Focus on the most actionable information (e.g., specific syscalls, sysfs files,
or netlink commands) and do not list excessive or irrelevant caller paths.` +
		common.InstructionDontMakeAssumptionsAboutSourceCode,
	PromptBuilder: func(ctx *aflow.Context, args AnalyzerQuery) (string, error) {
		tmpl, err := template.New("").Parse(`Query: {{.Query}}`)
		if err != nil {
			return "", err
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, args); err != nil {
			return "", err
		}
		return buf.String(), nil
	},
}
