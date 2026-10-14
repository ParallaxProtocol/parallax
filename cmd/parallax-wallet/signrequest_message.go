// Copyright 2025-2026 The Parallax Protocol Authors
// This file is part of parallax.
//
// parallax is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// parallax is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with parallax. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ParallaxProtocol/parallax/v2/cmd/utils"
	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"gopkg.in/urfave/cli.v1"
)

// Offline message signing, version 1 of the same exchange format.
const (
	signMessageRequestType = "parallax-sign-message-request"
	signedMessageType      = "parallax-signed-message"
	signMessageMaxBytes    = 1024
)

// signMessageRequest is the wire form of a message signing request. The
// message is kept raw so its JSON string can be checked for invalid UTF-8
// and lone surrogate escapes, which encoding/json would silently replace
// with U+FFFD.
type signMessageRequest struct {
	Type    *string         `json:"type"`
	Version *int            `json:"version"`
	ID      *string         `json:"id"`
	From    *string         `json:"from"`
	Message json.RawMessage `json:"message"`
}

// signedMessageDocument is the wire form of the signed message handed
// back to the online machine.
type signedMessageDocument struct {
	Type      string `json:"type"`
	Version   int    `json:"version"`
	ID        string `json:"id"`
	Address   string `json:"address"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

// validatedMessageRequest holds a message request after every check that
// can be done without the key has passed.
type validatedMessageRequest struct {
	id      util.Hash
	from    util.Address
	message string
}

func runSignMessageRequest(ctx *cli.Context, keyfile string, doc []byte, confirmed bool) {
	req, err := validateSignMessageRequest(doc)
	if err != nil {
		utils.Fatalf("Invalid signing request: %v", err)
	}

	key := decryptRequestKey(ctx, keyfile, req.from)
	defer zeroPrivateKey(key.PrivateKey)

	printSignMessageSummary(os.Stderr, req)
	if !confirmed {
		confirmSigning("Sign this message? [y/N] ")
	}

	sig, err := crypto.Sign(req.id[:], key.PrivateKey)
	zeroPrivateKey(key.PrivateKey)
	if err != nil {
		utils.Fatalf("Failed to sign message: %v", err)
	}
	// Self-check before anything leaves the offline machine.
	pub, err := crypto.SigToPub(signHash([]byte(req.message)), sig)
	if err != nil {
		utils.Fatalf("Signed message failed its self-check: %v", err)
	}
	if signer := crypto.PubkeyToAddress(*pub); signer != req.from {
		utils.Fatalf("Signed message failed its self-check: signer recovers to %s, want %s", signer.Hex(), req.from.Hex())
	}
	sig[crypto.RecoveryIDOffset] += 27 // the common wallet form

	writeSignedDocument(ctx, signedMessageDocument{
		Type:      signedMessageType,
		Version:   signRequestVersion,
		ID:        req.id.Hex(),
		Address:   req.from.Hex(),
		Message:   req.message,
		Signature: "0x" + hex.EncodeToString(sig),
	}, "Signed message")
}

// validateSignMessageRequest parses a message request document and runs
// every check of the exchange format that doesn't need the private key.
// The check that "from" is the key's address is left to the caller.
func validateSignMessageRequest(data []byte) (*validatedMessageRequest, error) {
	var doc signMessageRequest
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("malformed JSON: %v", err)
	}
	for _, f := range []struct {
		name    string
		missing bool
	}{
		{"type", doc.Type == nil}, {"version", doc.Version == nil},
		{"id", doc.ID == nil}, {"from", doc.From == nil},
		{"message", doc.Message == nil || string(doc.Message) == "null"},
	} {
		if f.missing {
			return nil, fmt.Errorf("missing required field %q", f.name)
		}
	}
	req := new(validatedMessageRequest)

	// 1. Document type and version.
	if *doc.Type != signMessageRequestType {
		return nil, fmt.Errorf("type is %q, want %q", *doc.Type, signMessageRequestType)
	}
	if *doc.Version != signRequestVersion {
		return nil, fmt.Errorf("unsupported version %d (this signer understands version %d)", *doc.Version, signRequestVersion)
	}

	// 2. The signing address.
	var err error
	if req.from, err = parseRequestAddress(*doc.From); err != nil {
		return nil, fmt.Errorf("from: %v", err)
	}
	if req.from == (util.Address{}) {
		return nil, errors.New("from is the zero address")
	}

	// 3. The message rules.
	if req.message, err = decodeRequestMessage(doc.Message); err != nil {
		return nil, fmt.Errorf("message: %v", err)
	}
	if err := checkRequestMessage(req.message); err != nil {
		return nil, fmt.Errorf("message: %v", err)
	}

	// 4. The id must be the message's EIP-191 hash.
	if !isHex32(*doc.ID) {
		return nil, fmt.Errorf("id %q is not a 0x-prefixed 32-byte hex string", *doc.ID)
	}
	req.id = util.BytesToHash(signHash([]byte(req.message)))
	if !strings.EqualFold(*doc.ID, req.id.Hex()) {
		return nil, fmt.Errorf("id %s does not match the message's hash %s; the request was altered", *doc.ID, req.id.Hex())
	}
	return req, nil
}

// decodeRequestMessage decodes the message's JSON string, refusing what
// encoding/json would otherwise turn into U+FFFD: raw bytes that aren't
// UTF-8 and \u escapes of unpaired surrogates.
func decodeRequestMessage(raw json.RawMessage) (string, error) {
	if !utf8.Valid(raw) {
		return "", errors.New("not valid UTF-8")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++ // the escaped character
		if i >= len(raw) || raw[i] != 'u' {
			continue
		}
		r, ok := jsonEscapeRune(raw, i-1)
		if !ok {
			continue // malformed escapes are left to the decoder
		}
		i += 4
		switch {
		case r >= 0xD800 && r <= 0xDBFF:
			lo, ok := jsonEscapeRune(raw, i+1)
			if !ok || lo < 0xDC00 || lo > 0xDFFF {
				return "", errors.New("not valid UTF-8 (unpaired surrogate)")
			}
			i += 6
		case r >= 0xDC00 && r <= 0xDFFF:
			return "", errors.New("not valid UTF-8 (unpaired surrogate)")
		}
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", errors.New("not a string")
	}
	return s, nil
}

// jsonEscapeRune decodes the \uXXXX escape starting at raw[at].
func jsonEscapeRune(raw []byte, at int) (rune, bool) {
	if at+6 > len(raw) || raw[at] != '\\' || raw[at+1] != 'u' {
		return 0, false
	}
	v, err := strconv.ParseUint(string(raw[at+2:at+6]), 16, 16)
	if err != nil {
		return 0, false
	}
	return rune(v), true
}

// checkRequestMessage applies the message rules: valid UTF-8, 1 to 1024
// bytes, and no control characters other than line feed and tab, so what
// is shown is everything that is signed.
func checkRequestMessage(msg string) error {
	if !utf8.ValidString(msg) {
		return errors.New("not valid UTF-8")
	}
	if len(msg) == 0 {
		return errors.New("empty")
	}
	if len(msg) > signMessageMaxBytes {
		return fmt.Errorf("%d bytes is longer than %d", len(msg), signMessageMaxBytes)
	}
	for i, r := range msg {
		if r != '\n' && r != '\t' && unicode.Is(unicode.Cc, r) {
			return fmt.Errorf("control character U+%04X at byte %d", r, i)
		}
	}
	return nil
}

// printSignMessageSummary writes what is about to be signed: the whole
// message, one line per message line, with anything that isn't plainly
// printable escaped.
func printSignMessageSummary(w io.Writer, req *validatedMessageRequest) {
	lines := strings.Split(req.message, "\n")
	fmt.Fprintln(w, "Message signing request")
	fmt.Fprintln(w, "  From:       ", req.from.Hex())
	fmt.Fprintf(w, "  Message:     %d bytes, %d line(s), each shown after \"| \"\n", len(req.message), len(lines))
	escaped := false
	for _, line := range lines {
		shown, esc := escapeMessageLine(line)
		escaped = escaped || esc
		fmt.Fprintln(w, "    |", shown)
	}
	if escaped {
		fmt.Fprintln(w, `  Escapes:     \t is a tab, \\ a backslash, \u{…} an invisible or unusual character`)
	}
	fmt.Fprintln(w, "  Fingerprint:", signRequestFingerprint(req.id))
}

// escapeMessageLine makes a message line safe and unambiguous on a
// terminal: tabs, backslashes and every rune that isn't a printable
// character or an ASCII space are escaped.
func escapeMessageLine(line string) (string, bool) {
	var b strings.Builder
	escaped := false
	for _, r := range line {
		switch {
		case r == '\t':
			b.WriteString(`\t`)
			escaped = true
		case r == '\\':
			b.WriteString(`\\`)
			escaped = true
		case unicode.IsPrint(r):
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, `\u{%X}`, r)
			escaped = true
		}
	}
	return b.String(), escaped
}
