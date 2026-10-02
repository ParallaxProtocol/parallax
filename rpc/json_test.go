// Copyright 2025-2026 The Parallax Protocol Authors
// This file is part of the parallax library.
//
// The parallax library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The parallax library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the parallax library. If not, see <http://www.gnu.org/licenses/>.

package rpc

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestParsePositionalArguments(t *testing.T) {
	var (
		tInt = reflect.TypeOf(0)
		tStr = reflect.TypeOf("")
		tPtr = reflect.TypeOf((*int)(nil))
		tBNH = reflect.TypeOf(BlockNumberOrHash{})
	)
	tests := []struct {
		name  string
		input string
		types []reflect.Type
		want  []any
		err   string
	}{
		{"no params", ``, []reflect.Type{tPtr}, []any{(*int)(nil)}, ""},
		{"null params", `null`, []reflect.Type{tPtr}, []any{(*int)(nil)}, ""},
		{"values", `[1, "x"]`, []reflect.Type{tInt, tStr}, []any{1, "x"}, ""},
		{"null into a pointer", `[null]`, []reflect.Type{tPtr}, []any{(*int)(nil)}, ""},
		{"missing optional argument", `[1]`, []reflect.Type{tInt, tPtr}, []any{1, (*int)(nil)}, ""},

		{"too many arguments", `[1,2,3]`, []reflect.Type{tInt}, nil, "too many arguments"},
		{"missing required argument", `[1]`, []reflect.Type{tInt, tInt}, nil, "missing value for required argument 1"},
		{"null into a value", `[null]`, []reflect.Type{tInt}, nil, "missing value for required argument 0"},
		{"null into a self decoding value", `[ null ]`, []reflect.Type{tBNH}, nil, "missing value for required argument 0"},
		{"wrong type", `["not an int"]`, []reflect.Type{tInt}, nil, "invalid argument 0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args, err := parsePositionalArguments(json.RawMessage(tc.input), tc.types)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("expected error containing %q, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(args) != len(tc.want) {
				t.Fatalf("wrong number of args: have %d, want %d", len(args), len(tc.want))
			}
			for i, arg := range args {
				if !reflect.DeepEqual(arg.Interface(), tc.want[i]) {
					t.Errorf("arg %d: have %v, want %v", i, arg.Interface(), tc.want[i])
				}
			}
		})
	}
}
