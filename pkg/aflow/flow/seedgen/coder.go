package seedgen

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
)

var CoderAgent = &aflow.LLMAgent{
	Name:     "seed-coder",
	Model:    aflow.Temporary35FlashOnlyModel,
	TaskType: aflow.FormalReasoningTask,
	Outputs: aflow.LLMOutputs[struct {
		BaseTestSeed      string `jsonschema:"Optional base seed file." json:",omitempty"`
		ExecutionCachedID string `jsonschema:"The cached execution ID." json:",omitempty"`
	}](),
	Tools: aflow.Tools(
		syzlang.ExecuteSeed,
		syzlang.ReadSyzSpec,
		syzlang.DisassembleContext,
	),
	Instruction: "You are an expert syzkaller seed generator.\n" +
		"Based on the provided Preconditions and previous Failed Strategies, write a valid syzkaller program " +
		"(seed) to reach the target.\n" +
		"You MUST:\n" +
		"1. Generate one or more alternative seeds.\n" +
		"2. Execute them using 'execute-seed' until you get one successful execution " +
		"(i.e. no call errors or compiler errors).\n" +
		"3. Call 'set-results' with BaseTestSeed (if any) and ExecutionCachedID.\n" +
		"Do NOT attempt to verify PC coverage or diagnose divergence. That will be handled by the pipeline.\n\n" +
		"===\n{{.DocProgramSyntax}}\n===\n\n" +
		"Document about syzlang system call descriptions syntax:\n" +
		"===\n{{.DocSyscallDescriptionsSyntax}}\n===\n\n" +
		"Document about pseudo-syscalls:\n" +
		"===\n{{.DocPseudoSyscalls}}\n===\n",
	Prompt: `Preconditions:
{{.TargetPreconditions}}

Failed Strategies:
{{.FailedStrategySummary}}`,
}
