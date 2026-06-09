// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codesearch

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/clangtool/tooltest"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/tools/clang/codesearch"
)

func TestClangTool(t *testing.T) {
	tooltest.TestClangTool[Database](t, clangtoolimpl.Tool)
}

func TestCommands(t *testing.T) {
	index := NewTestIndex(t, "testdata")
	files, err := filepath.Glob(filepath.Join(osutil.Abs("testdata"), "query*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("found no qeury files")
	}
	covered := make(map[string]bool)
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			testCommand(t, index, covered, file)
		})
	}
	for _, cmd := range Commands {
		if !covered[cmd.Name] {
			t.Errorf("command %v is not covered, add at least one test", cmd.Name)
		}
	}
}

func testCommand(t *testing.T, index *Index, covered map[string]bool, file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	query, _, _ := bytes.Cut(data, []byte{'\n'})
	qStr := string(query)
	var fields []string
	var current strings.Builder
	inQuotes := false
	for _, ch := range qStr {
		if ch == '"' {
			inQuotes = !inQuotes
		} else if ch == ' ' && !inQuotes {
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
		} else {
			current.WriteRune(ch)
		}
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	if len(fields) == 0 {
		t.Fatal("no command found")
	}
	cmd := fields[0]
	args := fields[1:]
	result, err := index.Command(cmd, args)
	if err != nil {
		// This is supposed to test aflow.BadCallError messages.
		result = err.Error() + "\n"
	}
	got := append([]byte(qStr+"\n\n"), result...)
	tooltest.CompareGoldenData(t, file, got)
	covered[cmd] = true
}
