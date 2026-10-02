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

package graphql

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/internal/api"
	"github.com/ParallaxProtocol/parallax/v2/node"
	"github.com/graph-gophers/graphql-go"
)

// maxQueryDepth limits the maximum field nesting depth allowed in GraphQL queries.
const maxQueryDepth = 20

// maxRequestBodySize limits the size of incoming GraphQL request bodies.
const maxRequestBodySize = 5 * 1024 * 1024

type handler struct {
	Schema *graphql.Schema
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var params struct {
		Query         string         `json:"query"`
		OperationName string         `json:"operationName"`
		Variables     map[string]any `json:"variables"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&params); err != nil {
		writeRequestError(w, err)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			err = errors.New("unexpected content after JSON value")
		}
		writeRequestError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	response := h.Schema.Exec(ctx, params.Query, params.OperationName, params.Variables)
	responseJSON, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if len(response.Errors) > 0 {
		w.WriteHeader(http.StatusBadRequest)
	}
	w.Write(responseJSON)
}

func writeRequestError(w http.ResponseWriter, err error) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

// New constructs a new GraphQL service instance.
func New(stack *node.Node, backend api.Backend, cors, vhosts []string) error {
	if backend == nil {
		panic("missing backend")
	}
	// check if http server with given endpoint exists and enable graphQL on it
	_, err := newHandler(stack, backend, cors, vhosts)
	return err
}

// newHandler returns a new `http.Handler` that will answer GraphQL queries.
// It additionally exports an interactive query browser on the / endpoint.
func newHandler(stack *node.Node, backend api.Backend, cors, vhosts []string) (*handler, error) {
	q := Resolver{backend}

	s, err := graphql.ParseSchema(schema, &q, graphql.MaxDepth(maxQueryDepth))
	if err != nil {
		return nil, err
	}
	h := handler{Schema: s}
	handler := node.NewHTTPHandlerStack(h, cors, vhosts, nil)

	stack.RegisterHandler("GraphQL UI", "/graphql/ui", GraphiQL{})
	stack.RegisterHandler("GraphQL", "/graphql", handler)
	stack.RegisterHandler("GraphQL", "/graphql/", handler)

	return &h, nil
}
