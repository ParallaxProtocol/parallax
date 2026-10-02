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

// Package tracers is a manager for transaction tracing engines.
package tracers

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ParallaxProtocol/parallax/v2/script"
	"github.com/ParallaxProtocol/parallax/v2/util"
)

// Context contains some contextual infos for a transaction execution that is not
// available from within the PVM object.
type Context struct {
	BlockHash util.Hash // Hash of the block the tx is contained within (zero if dangling tx or call)
	TxIndex   int       // Index of the transaction within a block (zero if dangling tx or call)
	TxHash    util.Hash // Hash of the transaction being traced (zero if dangling call)
}

// Tracer interface extends vm.PVMLogger and additionally
// allows collecting the tracing result.
type Tracer interface {
	script.PVMLogger
	GetResult() (json.RawMessage, error)
	// Stop terminates execution of the tracer at the first opportune moment.
	Stop(err error)
}

type lookupFunc func(string, *Context) (Tracer, error)

var (
	lookups []lookupFunc
)

// RegisterLookup registers a method as a lookup for tracers, meaning that
// users can invoke a named tracer through that lookup. If 'wildcard' is true,
// then the lookup will be placed last. This is typically meant for interpreted
// engines (js) which can evaluate dynamic user-supplied code.
func RegisterLookup(wildcard bool, lookup lookupFunc) {
	if wildcard {
		lookups = append(lookups, lookup)
	} else {
		lookups = append([]lookupFunc{lookup}, lookups...)
	}
}

// New returns a new instance of a tracer, by iterating through the
// registered lookups.
func New(code string, ctx *Context) (Tracer, error) {
	for _, lookup := range lookups {
		if tracer, err := lookup(code, ctx); err == nil {
			return tracer, nil
		}
	}
	return nil, errors.New("tracer not found")
}

const (
	memoryPadLimit = 1024 * 1024
)

// GetMemoryCopyPadded returns offset + size as a new slice.
// It zero-pads the slice if it extends beyond memory bounds.
func GetMemoryCopyPadded(m *script.Memory, offset, size int64) ([]byte, error) {
	if offset < 0 || size < 0 {
		return nil, fmt.Errorf("offset or size must not be negative")
	}
	if int(offset+size) < m.Len() { // slice fully inside memory
		return m.GetCopy(offset, size), nil
	}
	paddingNeeded := int(offset+size) - m.Len()
	if paddingNeeded > memoryPadLimit {
		return nil, fmt.Errorf("reached limit for padding memory slice: %d", paddingNeeded)
	}
	cpy := make([]byte, size)
	if overlap := int64(m.Len()) - offset; overlap > 0 {
		copy(cpy, m.GetPtr(offset, overlap))
	}
	return cpy, nil
}
