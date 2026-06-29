package seedgen

import (
	"github.com/google/syzkaller/pkg/aflow"
)

var ManagerAgent = &aflow.LLMAgent{
	Name:  "seed-manager",
	Model: aflow.Temporary35FlashOnlyModel,
	Outputs: aflow.LLMOutputs[struct {
		TargetPreconditions string `jsonschema:"Detailed instructions or struct layouts needed to generate the seed."`
		GeneratorGiveUp     bool   `jsonschema:"Set true if target is unreachable."`
		GeneratorReason     string `jsonschema:"Reason for giving up."`
	}](),
	Tools: aflow.Tools(
		&SeedgenAnalyzer,
	),
	TaskType: aflow.FormalReasoningTask,
	Instruction: "You are the Manager orchestrating the generation of a syzkaller seed.\n" +
		"Your goal is to reach a specific target PC.\n\n" +
		"You have one powerful tool:\n" +
		"1. 'seedgen-analyzer': Use this to delegate broad research tasks (e.g. 'How do I reach function X?', " +
		"'What are the preconditions for this path?'). Do NOT micro-manage the analyzer by asking for individual struct " +
		"layouts step-by-step; instead, give it high-level research objectives.\n\n" +
		"Workflow:\n" +
		"1. Read the Target details and the 'FailedStrategySummary' from the prompt.\n" +
		"2. If you need more information, call 'seedgen-analyzer' with high-level queries.\n" +
		"3. Once you have a clear plan, call 'set-results' to output your 'TargetPreconditions'. " +
		"The coder will run after you.\n" +
		"4. If you decide to give up, call 'set-results' with GeneratorGiveUp=true and a reason.\n",
	Prompt: `Target File: {{.File}}
Target Line: {{.Line}}
Target Function: {{.FunctionName}}
Target PC: {{printf "0x%x" .PC}}
{{if .Frames}}
PC corresponds to the following inline call chain:
{{range $i, $f := .Frames}}{{$i}}. {{$f.Func}} ({{$f.File}}:{{$f.Line}})
{{end}}{{else if .InnerFunc}}
Note: The exact PC is located inside the inlined function '{{.InnerFunc}}' which is called within the target function.
{{end}}

Function Context:
{{.FunctionSource}}

{{if .IndirectCallers}}
Indirect Callers of Target Function:
{{.IndirectCallers}}
{{end}}
{{.DescriptionFilesPrompt}}

Failed Strategies from Previous Loops:
{{.FailedStrategySummary}}

Formulate a comprehensive and detailed plan. Use your tools to execute it.`,
}
