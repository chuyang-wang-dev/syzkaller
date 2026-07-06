// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"errors"
	"fmt"
	"maps"
	"reflect"

	"github.com/google/syzkaller/pkg/aflow/backend"
)

// LLMTool acts like a tool for the parent LLM, but is itself implemented as an LLM agent.
// It can have own tools, different from the parent LLM agent.
// It can do complex multi-step research, and provide a concise answer to the parent LLM
// without polluting its context window.
type LLMTool[State, Args any] struct {
	// Most fields match that of LLMAgent.
	Name     string
	Model    backend.ModelCategory
	TaskType TaskType
	// Description of the tool exposed to the parent LLM.
	Description string
	Instruction string
	Tools       []Tool

	// Prompt template for the subagent, formatted using both State and Args.
	Prompt string

	// Optional evaluator/judge agent that is invoked after each iteration to inspect history.
	Judge *LLMJudge

	agent *LLMAgent
}

type DefaultLLMArgs struct {
	Question string `jsonschema:"Question you have."`
}

type llmToolResults struct {
	Answer string `jsonschema:"Answer to your question."`
}

func (t *LLMTool[State, Args]) declaration() *backend.FunctionDeclaration {
	return &backend.FunctionDeclaration{
		Name:                 t.Name,
		Description:          t.Description,
		ParametersJSONSchema: mustSchemaFor[Args](),
		ResponseJSONSchema:   mustSchemaFor[llmToolResults](),
	}
}

func (t *LLMTool[State, Args]) execute(ctx *Context, args map[string]any) (map[string]any, error) {
	s, err := convertFromMap[State](ctx.state, false, true)
	if err != nil {
		return nil, err
	}
	a, err := convertFromMap[Args](args, false, true)
	if err != nil {
		return nil, err
	}

	combined := make(map[string]any)
	maps.Copy(combined, convertToMap(s))
	maps.Copy(combined, convertToMap(a))
	for _, tool := range t.Tools {
		name := tool.declaration().Name
		combined[toolTemplateName(name)] = name
	}

	prompt := formatTemplate(t.Prompt, combined)

	ctx.state[llmToolPrompt] = prompt
	defer delete(ctx.state, llmToolPrompt)
	if err := t.agent.execute(ctx); err != nil {
		return nil, err
	}
	reply, ok := ctx.state[llmToolReply]
	if !ok {
		return nil, errors.New("state does not contain LLMTool reply")
	}
	delete(ctx.state, llmToolReply)
	return map[string]any{"Answer": reply}, nil
}

const (
	llmToolPrompt = "AFLOW_LLMTOOL_PROMPT"
	llmToolReply  = "AFLOW_LLMTOOL_REPLY"
)

func (t *LLMTool[State, Args]) verify(ctx *verifyContext) {
	ctx.requireNotEmpty(t.Name, "Name", t.Name)
	ctx.requireNotEmpty(t.Name, "Description", t.Description)
	requireSchema[Args](ctx, t.Name, "Args")
	requireInputs[State](ctx, t.Name)

	vars := make(map[string]reflect.Type)
	maps.Insert(vars, foreachFieldOf[State]())
	maps.Insert(vars, foreachFieldOf[Args]())
	for _, tool := range t.Tools {
		vars[toolTemplateName(tool.declaration().Name)] = reflect.TypeFor[string]()
	}
	if _, err := verifyTemplate(t.Prompt, vars); err != nil {
		ctx.errorf(t.Name, "invalid prompt template: %v", err)
	}

	t.agent = &LLMAgent{
		Name:        t.Name,
		Model:       t.Model,
		Reply:       llmToolReply,
		TaskType:    t.TaskType,
		Instruction: t.Instruction,
		Prompt:      fmt.Sprintf("{{.%v}}", llmToolPrompt),
		Tools:       t.Tools,
		Judge:       t.Judge,
	}
	t.agent.verify(ctx)
}
