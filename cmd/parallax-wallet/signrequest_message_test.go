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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet"
	"github.com/ParallaxProtocol/parallax/v2/wallet/keystore"
)

// messageRequestFields builds a valid message request as a map so tests
// can tamper with individual fields afterwards.
func messageRequestFields(from util.Address, message string) map[string]any {
	return map[string]any{
		"type":      "parallax-sign-message-request",
		"version":   1,
		"id":        "0x" + hex.EncodeToString(wallet.TextHash([]byte(message))),
		"from":      from.Hex(),
		"message":   message,
		"createdAt": 1791965000,
	}
}

var signedMessageSigRE = regexp.MustCompile(`^0x[0-9a-f]{130}$`)

// decodeSignedMessage checks a signed-message document against the
// request it came from and returns its signature.
func decodeSignedMessage(t *testing.T, data []byte, message string, from util.Address) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, data)
	}
	if doc["type"] != "parallax-signed-message" || doc["version"] != float64(1) {
		t.Fatalf("wrong type/version: %v %v", doc["type"], doc["version"])
	}
	if len(doc) != 6 {
		t.Errorf("document has %d fields, want 6: %v", len(doc), doc)
	}
	hash := wallet.TextHash([]byte(message))
	if doc["id"] != "0x"+hex.EncodeToString(hash) {
		t.Errorf("id = %v, want the message hash", doc["id"])
	}
	if doc["address"] != from.Hex() {
		t.Errorf("address = %v, want %s", doc["address"], from.Hex())
	}
	if doc["message"] != message {
		t.Errorf("message = %q, want %q", doc["message"], message)
	}
	sigHex, _ := doc["signature"].(string)
	if !signedMessageSigRE.MatchString(sigHex) {
		t.Fatalf("signature %q is not 0x-prefixed lowercase 65-byte hex", sigHex)
	}
	sig, _ := hex.DecodeString(sigHex[2:])
	if v := sig[64]; v != 27 && v != 28 {
		t.Fatalf("signature v = %d, want 27 or 28", v)
	}
	sig[64] -= 27
	pub, err := crypto.SigToPub(hash, sig)
	if err != nil {
		t.Fatalf("signature does not recover: %v", err)
	}
	if signer := crypto.PubkeyToAddress(*pub); signer != from {
		t.Fatalf("signature recovers to %s, want %s", signer.Hex(), from.Hex())
	}
	return sigHex
}

// expectVerifies runs verifymessage and requires success.
func expectVerifies(t *testing.T, addr util.Address, sig, message string) {
	t.Helper()
	cmd := runParallaxWallet(t, "verifymessage", addr.Hex(), sig, message)
	out := string(cmd.Output())
	cmd.WaitExit()
	if cmd.ExitStatus() != 0 || !strings.Contains(out, "Signature verification successful!") || !strings.Contains(out, "Recovered address: "+addr.Hex()) {
		t.Fatalf("verifymessage %s failed:\n%s", sig, out)
	}
}

func TestSignMessageRequestValid(t *testing.T) {
	env := newSignRequestEnv(t)
	message := "I control this address. 2026-10-14"
	reqPath := env.writeRequest(t, messageRequestFields(env.addr, message))

	cmd := runParallaxWallet(t, env.signArgs(reqPath)...)
	out := cmd.Output()
	cmd.WaitExit()
	if cmd.ExitStatus() != 0 {
		t.Fatalf("signrequest failed:\n%s", out)
	}
	sig := decodeSignedMessage(t, out, message, env.addr)
	expectVerifies(t, env.addr, sig, message)
}

func TestSignMessageRequestMultiline(t *testing.T) {
	env := newSignRequestEnv(t)
	message := "Line one\n\tindented\n\nlast line"
	reqPath := env.writeRequest(t, messageRequestFields(env.addr, message))

	cmd := runParallaxWallet(t, env.signArgs(reqPath)...)
	out := cmd.Output()
	cmd.WaitExit()
	if cmd.ExitStatus() != 0 {
		t.Fatalf("signrequest failed:\n%s", out)
	}
	decodeSignedMessage(t, out, message, env.addr)

	stderr := cmd.StderrText()
	for _, want := range []string{
		"    | Line one\n", "    | \\tindented\n", "    | \n", "    | last line\n",
		fmt.Sprintf("%d bytes, 4 line(s)", len(message)),
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("summary is missing %q:\n%s", want, stderr)
		}
	}
}

func TestSignMessageRequestOutFile(t *testing.T) {
	env := newSignRequestEnv(t)
	// 1024 bytes exactly, with a backslash and a right-to-left override
	// that the summary must escape.
	message := `C:\keys ` + "\u202e" + strings.Repeat("é", 506) + "!"
	if len(message) != 1024 {
		t.Fatalf("test message is %d bytes", len(message))
	}
	req := messageRequestFields(env.addr, message)
	reqPath := env.writeRequest(t, req)
	outPath := filepath.Join(env.dir, "signed.json")
	if err := os.WriteFile(outPath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	// --chainid and --feecap don't apply to messages, even when invalid.
	cmd := runParallaxWallet(t, env.signArgs(reqPath, "--out", outPath, "--chainid", "1", "--feecap", "1e18")...)
	cmd.ExpectExit()
	if cmd.ExitStatus() != 0 {
		t.Fatalf("signrequest failed:\n%s", cmd.StderrText())
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("output mode %v, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	decodeSignedMessage(t, data, message, env.addr)

	id := req["id"].(string)
	fingerprint := strings.ToUpper(id[2:6]) + "-" + strings.ToUpper(id[6:10])
	stderr := cmd.StderrText()
	for _, want := range []string{"Fingerprint: " + fingerprint, "1024 bytes", `| C:\\keys \u{202E}éé`, "Escapes:", "Signed message written to"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("summary is missing %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "\u202e") {
		t.Errorf("summary prints the raw override character")
	}
}

func TestSignMessageRequestConfirmPrompt(t *testing.T) {
	env := newSignRequestEnv(t)
	message := "hello"
	reqPath := env.writeRequest(t, messageRequestFields(env.addr, message))
	outPath := filepath.Join(env.dir, "signed.json")
	args := []string{"signrequest", "--passwordfile", env.passfile, "--out", outPath, env.keyfile, reqPath}

	decline := runParallaxWallet(t, args...)
	decline.Expect(`
Sign this message? [y/N] {{.InputLine "n"}}
`)
	out := string(decline.Output())
	decline.WaitExit()
	if decline.ExitStatus() == 0 || !strings.Contains(out, "Not confirmed") {
		t.Fatalf("declining should refuse to sign, got:\n%s", out)
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Fatalf("output file exists after declining: %v", err)
	}

	accept := runParallaxWallet(t, args...)
	accept.Expect(`
Sign this message? [y/N] {{.InputLine "y"}}
`)
	accept.ExpectExit()
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	decodeSignedMessage(t, data, message, env.addr)
}

func TestSignMessageRequestStdin(t *testing.T) {
	env := newSignRequestEnv(t)
	message := "from stdin"
	data, _ := json.Marshal(messageRequestFields(env.addr, message))

	cmd := runParallaxWallet(t, env.signArgs("-")...)
	cmd.InputLine(string(data))
	cmd.CloseStdin()
	out := cmd.Output()
	cmd.WaitExit()
	if cmd.ExitStatus() != 0 {
		t.Fatalf("signrequest failed:\n%s", out)
	}
	decodeSignedMessage(t, out, message, env.addr)

	expectSignRequestFailure(t, "pass --yes",
		"signrequest", "--passwordfile", env.passfile, env.keyfile, "-")
}

// TestVerifyMessageSignatureForms checks that verifymessage takes the old
// signmessage form (no prefix, v 0/1) and the wallet form (0x, v 27/28).
func TestVerifyMessageSignatureForms(t *testing.T) {
	env := newSignRequestEnv(t)
	message := "test message"

	sign := runParallaxWallet(t, "signmessage", "--passwordfile", env.passfile, env.keyfile, message)
	_, matches := sign.ExpectRegexp(`Signature: ([0-9a-f]{130})\n`)
	sign.ExpectExit()
	old := matches[1]
	if v := old[128:]; v != "00" && v != "01" {
		t.Fatalf("signmessage v = %s, want 00 or 01", v)
	}
	expectVerifies(t, env.addr, old, message)

	sig, _ := hex.DecodeString(old)
	sig[64] += 27
	walletForm := hex.EncodeToString(sig)
	expectVerifies(t, env.addr, "0x"+walletForm, message)
	expectVerifies(t, env.addr, walletForm, message)
	expectVerifies(t, env.addr, "0x"+old, message)

	cmd := runParallaxWallet(t, "verifymessage", env.addr.Hex(), "0x"+walletForm, "another message")
	out := string(cmd.Output())
	cmd.WaitExit()
	if strings.Contains(out, "successful") {
		t.Fatalf("a signature over a different message verified:\n%s", out)
	}

	// The signed-message document's signature verifies as well.
	reqPath := env.writeRequest(t, messageRequestFields(env.addr, message))
	signReq := runParallaxWallet(t, env.signArgs(reqPath)...)
	data := signReq.Output()
	signReq.WaitExit()
	expectVerifies(t, env.addr, decodeSignedMessage(t, data, message, env.addr), message)
}

func TestSignMessageRequestRejects(t *testing.T) {
	env := newSignRequestEnv(t)
	other := keystore.NewKeyForDirectICAP(rand.Reader).Address

	tests := []struct {
		name   string
		mutate func(req map[string]any) map[string]any
		want   string
	}{
		{"wrong version", func(r map[string]any) map[string]any { r["version"] = 2; return r }, "unsupported version 2"},
		{"missing message", func(r map[string]any) map[string]any { delete(r, "message"); return r }, `missing required field "message"`},
		{"null message", func(r map[string]any) map[string]any { r["message"] = nil; return r }, `missing required field "message"`},
		{"missing id", func(r map[string]any) map[string]any { delete(r, "id"); return r }, `missing required field "id"`},
		{"tampered message", func(r map[string]any) map[string]any { r["message"] = "hello!"; return r }, "does not match the message's hash"},
		{"bad id", func(r map[string]any) map[string]any { r["id"] = "0x1234"; return r }, "not a 0x-prefixed 32-byte hex string"},
		{"carriage return", func(r map[string]any) map[string]any { return messageRequestFields(env.addr, "a\r\nb") }, "control character U+000D"},
		{"NUL", func(r map[string]any) map[string]any { return messageRequestFields(env.addr, "a\x00b") }, "control character U+0000"},
		{"escape", func(r map[string]any) map[string]any { return messageRequestFields(env.addr, "\x1b[2J") }, "control character U+001B"},
		{"C1 control", func(r map[string]any) map[string]any { return messageRequestFields(env.addr, "a\u0085b") }, "control character U+0085"},
		{"empty", func(r map[string]any) map[string]any { return messageRequestFields(env.addr, "") }, "message: empty"},
		{"too long", func(r map[string]any) map[string]any {
			return messageRequestFields(env.addr, strings.Repeat("x", 1025))
		}, "1025 bytes is longer than 1024"},
		{"bad checksum", func(r map[string]any) map[string]any { r["from"] = flipCase(r["from"].(string)); return r }, "invalid checksum"},
		{"zero from", func(r map[string]any) map[string]any { return messageRequestFields(util.Address{}, "hello") }, "from is the zero address"},
		{"from not the key", func(r map[string]any) map[string]any { return messageRequestFields(other, "hello") }, "but the request is from " + other.Hex()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqPath := env.writeRequest(t, tt.mutate(messageRequestFields(env.addr, "hello")))
			expectSignRequestFailure(t, tt.want, env.signArgs(reqPath)...)
		})
	}

	// encoding/json would quietly turn these into U+FFFD; they are written
	// out literally so the bytes reach the signer as they are.
	raw := func(message, id string) string {
		return fmt.Sprintf(`{"type":"parallax-sign-message-request","version":1,"id":"%s","from":"%s","message":"%s"}`,
			id, env.addr.Hex(), message)
	}
	fffdID := "0x" + hex.EncodeToString(wallet.TextHash([]byte("a\ufffdb")))
	for name, doc := range map[string]string{
		"invalid UTF-8 byte":      raw("a\xffb", fffdID),
		"lone high surrogate":     raw(`a\ud800b`, fffdID),
		"lone low surrogate":      raw(`a\udc00b`, fffdID),
		"reversed surrogate pair": raw(`\udc00\ud800`, fffdID),
	} {
		t.Run(name, func(t *testing.T) {
			reqPath := env.writeRequest(t, doc)
			expectSignRequestFailure(t, "message: not valid UTF-8", env.signArgs(reqPath)...)
		})
	}

	// An escaped surrogate pair and an escaped backslash before "u" are fine.
	t.Run("escaped pair", func(t *testing.T) {
		message := "\U0001F600 \\ud800"
		id := "0x" + hex.EncodeToString(wallet.TextHash([]byte(message)))
		reqPath := env.writeRequest(t, raw(`\ud83d\ude00 \\ud800`, id))
		cmd := runParallaxWallet(t, env.signArgs(reqPath)...)
		out := cmd.Output()
		cmd.WaitExit()
		if cmd.ExitStatus() != 0 {
			t.Fatalf("signrequest failed:\n%s", out)
		}
		decodeSignedMessage(t, out, message, env.addr)
	})

	t.Run("oversized", func(t *testing.T) {
		req := messageRequestFields(env.addr, "hello")
		req["padding"] = strings.Repeat("x", 9000)
		reqPath := env.writeRequest(t, req)
		expectSignRequestFailure(t, "larger than 8192 bytes", env.signArgs(reqPath)...)
	})
}

func TestEscapeMessageLine(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":   "plain text",
		"tab\there":    `tab\there`,
		`back\slash`:   `back\\slash`,
		"zw\u200bsp":   `zw\u{200B}sp`,
		"nb\u00a0sp":   `nb\u{A0}sp`,
		"émoji \u2764": "émoji \u2764",
	} {
		if got, _ := escapeMessageLine(in); got != want {
			t.Errorf("escapeMessageLine(%q) = %q, want %q", in, got, want)
		}
	}
}
