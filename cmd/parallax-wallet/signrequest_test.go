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
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/util/hexutil"
	"github.com/ParallaxProtocol/parallax/v2/wallet/keystore"
)

const signRequestTestPassword = "foobar"

// signRequestEnv is a temp dir holding a light-scrypt keyfile and its
// password file.
type signRequestEnv struct {
	dir      string
	keyfile  string
	passfile string
	addr     util.Address
}

func newSignRequestEnv(t *testing.T) *signRequestEnv {
	t.Helper()
	env := &signRequestEnv{dir: t.TempDir()}
	key := keystore.NewKeyForDirectICAP(rand.Reader)
	keyjson, err := keystore.EncryptKey(key, signRequestTestPassword, keystore.LightScryptN, keystore.LightScryptP)
	if err != nil {
		t.Fatal(err)
	}
	env.addr = key.Address
	env.keyfile = filepath.Join(env.dir, "keyfile.json")
	env.passfile = filepath.Join(env.dir, "password.txt")
	if err := os.WriteFile(env.keyfile, keyjson, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.passfile, []byte(signRequestTestPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return env
}

// testRecipient is a fixed, checksummed recipient address.
var testRecipient = util.HexToAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")

// signRequestFields builds a valid request as a map so tests can tamper
// with individual fields afterwards.
func signRequestFields(from, to util.Address, chainID int64, nonce, gas uint64, value, gasPrice *big.Int) map[string]any {
	tx := types.NewTransaction(nonce, to, value, gas, gasPrice, nil)
	id := types.LatestSignerForChainID(big.NewInt(chainID)).Hash(tx)
	return map[string]any{
		"type":        "parallax-sign-request",
		"version":     1,
		"id":          id.Hex(),
		"chainId":     fmt.Sprint(chainID),
		"from":        from.Hex(),
		"to":          to.Hex(),
		"nonce":       fmt.Sprint(nonce),
		"valueWei":    value.String(),
		"gasLimit":    fmt.Sprint(gas),
		"gasPriceWei": gasPrice.String(),
		"createdAt":   1791965000,
		"memo":        "rent",
	}
}

func (env *signRequestEnv) defaultRequest() map[string]any {
	return signRequestFields(env.addr, testRecipient, 2110, 7, 21000,
		new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), big.NewInt(1_000_000_000))
}

func (env *signRequestEnv) writeRequest(t *testing.T, req any) string {
	t.Helper()
	var data []byte
	switch r := req.(type) {
	case string:
		data = []byte(r)
	default:
		var err error
		if data, err = json.Marshal(r); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(env.dir, "request.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// signArgs returns the usual non-interactive invocation.
func (env *signRequestEnv) signArgs(reqPath string, extra ...string) []string {
	args := append([]string{"signrequest", "--passwordfile", env.passfile, "--yes"}, extra...)
	return append(args, env.keyfile, reqPath)
}

// expectSignRequestFailure runs the command and requires a non-zero exit
// whose fatal message contains want.
func expectSignRequestFailure(t *testing.T, want string, args ...string) {
	t.Helper()
	cmd := runParallaxWallet(t, args...)
	out := string(cmd.Output())
	cmd.WaitExit()
	if cmd.ExitStatus() == 0 {
		t.Fatalf("expected failure containing %q, command succeeded with output:\n%s", want, out)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("expected failure containing %q, got:\n%s", want, out)
	}
}

// decodeSignedDocument checks a signed-tx document against the request it
// came from.
func decodeSignedDocument(t *testing.T, data []byte, req map[string]any, from util.Address) *types.Transaction {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, data)
	}
	if doc["type"] != "parallax-signed-tx" || doc["version"] != float64(1) {
		t.Fatalf("wrong type/version: %v %v", doc["type"], doc["version"])
	}
	for _, k := range []string{"nonce", "chainId"} {
		if doc[k] != req[k] {
			t.Errorf("%s = %v, want %v", k, doc[k], req[k])
		}
	}
	if doc["from"] != from.Hex() {
		t.Errorf("from = %v, want %s", doc["from"], from.Hex())
	}
	if !strings.EqualFold(doc["id"].(string), req["id"].(string)) {
		t.Errorf("id = %v, want %v", doc["id"], req["id"])
	}
	raw, err := hexutil.Decode(doc["raw"].(string))
	if err != nil {
		t.Fatalf("raw is not hex: %v", err)
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(raw); err != nil {
		t.Fatalf("raw does not decode: %v", err)
	}
	chainID, _ := new(big.Int).SetString(req["chainId"].(string), 10)
	signer := types.LatestSignerForChainID(chainID)
	if tx.Type() != types.LegacyTxType || !tx.Protected() || tx.ChainId().Cmp(chainID) != 0 {
		t.Errorf("unexpected tx: type %d protected %v chain %v", tx.Type(), tx.Protected(), tx.ChainId())
	}
	sender, err := types.Sender(signer, tx)
	if err != nil || sender != from {
		t.Errorf("sender = %s (%v), want %s", sender.Hex(), err, from.Hex())
	}
	if tx.Hash().Hex() != doc["hash"] {
		t.Errorf("hash = %v, tx hash %s", doc["hash"], tx.Hash().Hex())
	}
	if !strings.EqualFold(signer.Hash(tx).Hex(), req["id"].(string)) {
		t.Errorf("signing hash %s != id %v", signer.Hash(tx).Hex(), req["id"])
	}
	if tx.Value().String() != req["valueWei"] || tx.To() == nil || tx.To().Hex() != req["to"] {
		t.Errorf("tx fields differ from the request: value %s to %v", tx.Value(), tx.To())
	}
	return tx
}

func TestSignRequestValid(t *testing.T) {
	env := newSignRequestEnv(t)
	req := env.defaultRequest()
	reqPath := env.writeRequest(t, req)

	cmd := runParallaxWallet(t, env.signArgs(reqPath)...)
	out := cmd.Output()
	cmd.WaitExit()
	if cmd.ExitStatus() != 0 {
		t.Fatalf("signrequest failed:\n%s", out)
	}
	decodeSignedDocument(t, out, req, env.addr)
}

func TestSignRequestOutFile(t *testing.T) {
	env := newSignRequestEnv(t)
	req := env.defaultRequest()
	reqPath := env.writeRequest(t, req)
	outPath := filepath.Join(env.dir, "signed.json")

	cmd := runParallaxWallet(t, env.signArgs(reqPath, "--out", outPath)...)
	cmd.ExpectExit()
	if cmd.ExitStatus() != 0 {
		t.Fatalf("signrequest failed")
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
	decodeSignedDocument(t, data, req, env.addr)

	id := req["id"].(string)
	fingerprint := strings.ToUpper(id[2:6]) + "-" + strings.ToUpper(id[6:10])
	stderr := cmd.StderrText()
	for _, want := range []string{"Fingerprint: " + fingerprint, "1 LAX", "0.000021 LAX", "1 gwei", `"rent"`} {
		if !strings.Contains(stderr, want) {
			t.Errorf("summary is missing %q:\n%s", want, stderr)
		}
	}
}

// TestSignRequestSpecShape feeds a request written out literally in the
// exchange format's example layout rather than via encoding/json.
func TestSignRequestSpecShape(t *testing.T) {
	env := newSignRequestEnv(t)
	value, _ := new(big.Int).SetString("1000000000000000000", 10)
	tx := types.NewTransaction(7, testRecipient, value, 21000, big.NewInt(1000000000), nil)
	id := types.LatestSignerForChainID(big.NewInt(2110)).Hash(tx).Hex()
	doc := fmt.Sprintf(`{
  "type": "parallax-sign-request",
  "version": 1,
  "id": "%s",
  "chainId": "2110",
  "from": "%s",
  "to": "%s",
  "nonce": "7",
  "valueWei": "1000000000000000000",
  "gasLimit": "21000",
  "gasPriceWei": "1000000000",
  "createdAt": 1791965000,
  "memo": "rent"
}`, id, env.addr.Hex(), testRecipient.Hex())
	reqPath := env.writeRequest(t, doc)

	cmd := runParallaxWallet(t, env.signArgs(reqPath)...)
	out := cmd.Output()
	cmd.WaitExit()
	if cmd.ExitStatus() != 0 {
		t.Fatalf("signrequest failed:\n%s", out)
	}
	var req map[string]any
	if err := json.Unmarshal([]byte(doc), &req); err != nil {
		t.Fatal(err)
	}
	decodeSignedDocument(t, out, req, env.addr)
}

func TestSignRequestConfirmPrompt(t *testing.T) {
	env := newSignRequestEnv(t)
	req := env.defaultRequest()
	reqPath := env.writeRequest(t, req)
	outPath := filepath.Join(env.dir, "signed.json")
	args := []string{"signrequest", "--passwordfile", env.passfile, "--out", outPath, env.keyfile, reqPath}

	decline := runParallaxWallet(t, args...)
	decline.Expect(`
Sign this transaction? [y/N] {{.InputLine "n"}}
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
Sign this transaction? [y/N] {{.InputLine "y"}}
`)
	accept.ExpectExit()
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	decodeSignedDocument(t, data, req, env.addr)
}

func TestSignRequestStdin(t *testing.T) {
	env := newSignRequestEnv(t)
	req := env.defaultRequest()
	data, _ := json.Marshal(req)

	cmd := runParallaxWallet(t, env.signArgs("-")...)
	cmd.InputLine(string(data))
	cmd.CloseStdin()
	out := cmd.Output()
	cmd.WaitExit()
	if cmd.ExitStatus() != 0 {
		t.Fatalf("signrequest failed:\n%s", out)
	}
	decodeSignedDocument(t, out, req, env.addr)

	expectSignRequestFailure(t, "pass --yes",
		"signrequest", "--passwordfile", env.passfile, env.keyfile, "-")
}

func TestSignRequestFeeCap(t *testing.T) {
	env := newSignRequestEnv(t)
	// 30,000,000 gas at 100 gwei is a 3 LAX maximum fee.
	req := signRequestFields(env.addr, testRecipient, 2110, 0, 30000000, big.NewInt(1), big.NewInt(100_000_000_000))
	reqPath := env.writeRequest(t, req)

	expectSignRequestFailure(t, "exceeds the cap of 1 LAX", env.signArgs(reqPath)...)
	expectSignRequestFailure(t, "exceeds the cap of 2.5 LAX", env.signArgs(reqPath, "--feecap", "2.5")...)

	cmd := runParallaxWallet(t, env.signArgs(reqPath, "--feecap", "3")...)
	out := cmd.Output()
	cmd.WaitExit()
	if cmd.ExitStatus() != 0 {
		t.Fatalf("signrequest with a raised cap failed:\n%s", out)
	}
	decodeSignedDocument(t, out, req, env.addr)

	expectSignRequestFailure(t, "Invalid --feecap", env.signArgs(reqPath, "--feecap", "1e18")...)
}

func TestSignRequestChainID(t *testing.T) {
	env := newSignRequestEnv(t)
	value := big.NewInt(1)
	gasPrice := big.NewInt(1_000_000_000)

	req := signRequestFields(env.addr, testRecipient, 1, 0, 21000, value, gasPrice)
	reqPath := env.writeRequest(t, req)
	expectSignRequestFailure(t, "is not Parallax mainnet", env.signArgs(reqPath)...)
	expectSignRequestFailure(t, "does not match --chainid 1337", env.signArgs(reqPath, "--chainid", "1337")...)

	cmd := runParallaxWallet(t, env.signArgs(reqPath, "--chainid", "1")...)
	out := cmd.Output()
	cmd.WaitExit()
	if cmd.ExitStatus() != 0 {
		t.Fatalf("signrequest with --chainid 1 failed:\n%s", out)
	}
	decodeSignedDocument(t, out, req, env.addr)

	// --chainid replaces mainnet rather than adding to it.
	req = signRequestFields(env.addr, testRecipient, 2110, 0, 21000, value, gasPrice)
	reqPath = env.writeRequest(t, req)
	expectSignRequestFailure(t, "does not match --chainid 1", env.signArgs(reqPath, "--chainid", "1")...)
}

// flipCase swaps the case of the first hex letter of a checksummed address.
func flipCase(addr string) string {
	b := []byte(addr)
	for i := 2; i < len(b); i++ {
		switch {
		case b[i] >= 'a' && b[i] <= 'f':
			b[i] -= 'a' - 'A'
			return string(b)
		case b[i] >= 'A' && b[i] <= 'F':
			b[i] += 'a' - 'A'
			return string(b)
		}
	}
	panic("address has no hex letters")
}

func TestSignRequestRejects(t *testing.T) {
	env := newSignRequestEnv(t)
	other := keystore.NewKeyForDirectICAP(rand.Reader).Address

	tests := []struct {
		name   string
		mutate func(req map[string]any) map[string]any
		want   string
	}{
		{"wrong type", func(r map[string]any) map[string]any { r["type"] = "parallax-signed-tx"; return r }, `type is "parallax-signed-tx"`},
		{"wrong version", func(r map[string]any) map[string]any { r["version"] = 2; return r }, "unsupported version 2"},
		{"missing field", func(r map[string]any) map[string]any { delete(r, "gasLimit"); return r }, `missing required field "gasLimit"`},
		{"bad checksum", func(r map[string]any) map[string]any { r["to"] = flipCase(r["to"].(string)); return r }, "invalid checksum"},
		{"short address", func(r map[string]any) map[string]any { r["to"] = "0x1234"; return r }, "not a 0x-prefixed 40 hex digit address"},
		{"zero to", func(r map[string]any) map[string]any {
			return signRequestFields(env.addr, util.Address{}, 2110, 7, 21000, big.NewInt(1), big.NewInt(1_000_000_000))
		}, "to is the zero address"},
		{"data", func(r map[string]any) map[string]any { r["data"] = "0xab"; return r }, "data must be empty"},
		{"hex nonce", func(r map[string]any) map[string]any { r["nonce"] = "0x7"; return r }, "nonce"},
		{"negative value", func(r map[string]any) map[string]any { r["valueWei"] = "-1"; return r }, "valueWei"},
		{"gas too low", func(r map[string]any) map[string]any {
			return signRequestFields(env.addr, testRecipient, 2110, 7, 20999, big.NewInt(1), big.NewInt(1_000_000_000))
		}, "gasLimit 20999 is outside"},
		{"gas too high", func(r map[string]any) map[string]any { r["gasLimit"] = "30000001"; return r }, "gasLimit 30000001 is outside"},
		{"zero gas price", func(r map[string]any) map[string]any {
			return signRequestFields(env.addr, testRecipient, 2110, 7, 21000, big.NewInt(1), big.NewInt(0))
		}, "gasPriceWei must be greater than zero"},
		{"tampered value", func(r map[string]any) map[string]any { r["valueWei"] = "2000000000000000000"; return r }, "does not match the transaction's signing hash"},
		{"bad id", func(r map[string]any) map[string]any { r["id"] = "0x1234"; return r }, "not a 0x-prefixed 32-byte hex string"},
		{"from not the key", func(r map[string]any) map[string]any {
			return signRequestFields(other, testRecipient, 2110, 7, 21000, big.NewInt(1), big.NewInt(1_000_000_000))
		}, "but the request is from " + other.Hex()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqPath := env.writeRequest(t, tt.mutate(env.defaultRequest()))
			expectSignRequestFailure(t, tt.want, env.signArgs(reqPath)...)
		})
	}

	t.Run("oversized", func(t *testing.T) {
		req := env.defaultRequest()
		req["memo"] = strings.Repeat("x", 9000)
		reqPath := env.writeRequest(t, req)
		expectSignRequestFailure(t, "larger than 8192 bytes", env.signArgs(reqPath)...)
	})
}

func TestParseLAX(t *testing.T) {
	good := map[string]string{
		"1":                    "1000000000000000000",
		"0.5":                  "500000000000000000",
		".25":                  "250000000000000000",
		"0.000000000000000001": "1",
		"21000000":             "21000000000000000000000000",
	}
	for in, want := range good {
		v, err := parseLAX(in)
		if err != nil || v.String() != want {
			t.Errorf("parseLAX(%q) = %v, %v; want %s", in, v, err, want)
		}
	}
	for _, in := range []string{"", ".", "1.", "-1", "+1", "1e18", "0.0000000000000000001", "1.2.3", " 1", "0x1"} {
		if v, err := parseLAX(in); err == nil {
			t.Errorf("parseLAX(%q) = %v, want error", in, v)
		}
	}
}

func TestFormatUnits(t *testing.T) {
	lax := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	for in, want := range map[string]string{
		"0":                    "0",
		"1":                    "0.000000000000000001",
		"1000000000000000000":  "1",
		"1500000000000000000":  "1.5",
		"21000000000000":       "0.000021",
		"12345678901234567890": "12.34567890123456789",
	} {
		v, _ := new(big.Int).SetString(in, 10)
		if got := formatUnits(v, lax); got != want {
			t.Errorf("formatUnits(%s) = %s, want %s", in, got, want)
		}
	}
}
