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
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/ParallaxProtocol/parallax/v2/cmd/utils"
	"github.com/ParallaxProtocol/parallax/v2/node/console/prompt"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/keystore"
	"gopkg.in/urfave/cli.v1"
)

// Offline signing exchange format, version 1. These documents are shared
// with Parallax Desktop's air-gapped signing flow and must stay
// byte-compatible with it.
const (
	signRequestType    = "parallax-sign-request"
	signedTxType       = "parallax-signed-tx"
	signRequestVersion = 1

	signRequestMaxSize = 8 * 1024 // readers cap the document at 8 KiB
	signRequestMaxMemo = 200      // characters
	signRequestMinGas  = 21000
	signRequestMaxGas  = 30000000
	signRequestMainnet = 2110
	signRequestFeeCap  = "1" // LAX
	signRequestMaxBits = 256 // bit length cap for integers
)

var (
	weiPerLAX  = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	weiPerGwei = big.NewInt(1_000_000_000)
)

// signRequest is the wire form of a signing request. Pointer fields let
// us tell a missing field from an empty one; unknown fields are ignored.
type signRequest struct {
	Type        *string `json:"type"`
	Version     *int    `json:"version"`
	ID          *string `json:"id"`
	ChainID     *string `json:"chainId"`
	From        *string `json:"from"`
	To          *string `json:"to"`
	Nonce       *string `json:"nonce"`
	ValueWei    *string `json:"valueWei"`
	GasLimit    *string `json:"gasLimit"`
	GasPriceWei *string `json:"gasPriceWei"`
	Data        *string `json:"data"`
	Memo        *string `json:"memo"`
}

// signedTxDocument is the wire form of the signed transaction handed back
// to the online machine.
type signedTxDocument struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
	ID      string `json:"id"`
	Hash    string `json:"hash"`
	Raw     string `json:"raw"`
	From    string `json:"from"`
	Nonce   string `json:"nonce"`
	ChainID string `json:"chainId"`
}

// validatedRequest holds a signing request after every check that can be
// done without the key has passed.
type validatedRequest struct {
	id       util.Hash
	chainID  *big.Int
	from     util.Address
	to       util.Address
	nonce    uint64
	value    *big.Int
	gas      uint64
	gasPrice *big.Int
	maxFee   *big.Int
	memo     string
	tx       *types.Transaction
	signer   types.Signer
}

var (
	signRequestChainIDFlag = cli.StringFlag{
		Name:  "chainid",
		Usage: "allow this chain ID instead of Parallax mainnet (2110); the request's chainId must equal it (transfers only)",
	}
	signRequestFeeCapFlag = cli.StringFlag{
		Name:  "feecap",
		Usage: "maximum fee (gasLimit × gasPrice) to sign, in LAX (transfers only)",
		Value: signRequestFeeCap,
	}
	signRequestYesFlag = cli.BoolFlag{
		Name:  "yes",
		Usage: "sign without asking for confirmation",
	}
	signRequestOutFlag = cli.StringFlag{
		Name:  "out",
		Usage: "write the signed document to this file (mode 0600) instead of stdout",
	}
)

var commandSignRequest = cli.Command{
	Name:      "signrequest",
	Usage:     "sign a Parallax Desktop offline signing request with a keyfile",
	ArgsUsage: "<keyfile> <request.json>",
	Flags: []cli.Flag{
		passphraseFlag,
		signRequestChainIDFlag,
		signRequestFeeCapFlag,
		signRequestYesFlag,
		signRequestOutFlag,
	},
	Description: `
Sign a "parallax-sign-request" document, as exported by Parallax
Desktop's offline signing flow, with the private key decrypted from
<keyfile>, and emit the matching "parallax-signed-tx" document for the
online machine to broadcast. This is the command-line counterpart of
Parallax Desktop's offline signer. Pass - as <request.json> to read the
request from stdin.

The request is fully validated before the key is touched: only plain
LAX transfers are accepted, the chain must be Parallax mainnet (2110)
unless --chainid names another, the maximum fee may not exceed --feecap
(1 LAX by default), and the request id must equal the transaction's
recomputed signing hash. A summary and its fingerprint are printed to
stderr; compare the fingerprint with the one shown on the online machine
before confirming.

A "parallax-sign-message-request" document is signed as an EIP-191
personal message instead, and answered with a "parallax-signed-message"
document. The message must be 1 to 1024 bytes of UTF-8 with no control
characters other than line feed and tab, and the request id must equal
the message's EIP-191 hash. The whole message is printed to stderr with
its fingerprint before confirming. --chainid and --feecap don't apply.

This command never talks to a node.`,
	Action: runSignRequest,
}

func runSignRequest(ctx *cli.Context) error {
	if ctx.NArg() != 2 {
		utils.Fatalf("Usage: parallax-wallet signrequest [flags] <keyfile> <request.json>")
	}
	keyfile, reqPath := ctx.Args().Get(0), ctx.Args().Get(1)
	fromStdin := reqPath == "-"
	confirmed := ctx.Bool(signRequestYesFlag.Name)
	if fromStdin && !confirmed {
		utils.Fatalf("Reading the request from stdin leaves no way to confirm it; pass --yes")
	}
	if fromStdin && ctx.String(passphraseFlag.Name) == "" {
		utils.Fatalf("Reading the request from stdin leaves no way to prompt for a password; pass --%s", passphraseFlag.Name)
	}

	doc, err := readSignRequest(reqPath)
	if err != nil {
		utils.Fatalf("Failed to read the signing request: %v", err)
	}
	// Message requests carry no chain or fee, so --chainid and --feecap
	// don't apply to them.
	if signRequestDocType(doc) == signMessageRequestType {
		runSignMessageRequest(ctx, keyfile, doc, confirmed)
		return nil
	}

	allowedChain := big.NewInt(signRequestMainnet)
	if s := ctx.String(signRequestChainIDFlag.Name); s != "" {
		v, err := parseDecimal(s)
		if err != nil || v.Sign() == 0 {
			utils.Fatalf("Invalid --%s value: %s", signRequestChainIDFlag.Name, s)
		}
		allowedChain = v
	}
	feeCap, err := parseLAX(ctx.String(signRequestFeeCapFlag.Name))
	if err != nil {
		utils.Fatalf("Invalid --%s value: %v", signRequestFeeCapFlag.Name, err)
	}
	req, err := validateSignRequest(doc, allowedChain, feeCap)
	if err != nil {
		utils.Fatalf("Invalid signing request: %v", err)
	}

	key := decryptRequestKey(ctx, keyfile, req.from)
	defer zeroPrivateKey(key.PrivateKey)

	printSignRequestSummary(os.Stderr, req)
	if !confirmed {
		confirmSigning("Sign this transaction? [y/N] ")
	}

	signed, err := types.SignTx(req.tx, req.signer, key.PrivateKey)
	zeroPrivateKey(key.PrivateKey)
	if err != nil {
		utils.Fatalf("Failed to sign transaction: %v", err)
	}
	if err := checkSignedTx(signed, req); err != nil {
		utils.Fatalf("Signed transaction failed its self-check: %v", err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		utils.Fatalf("Failed to encode transaction: %v", err)
	}

	writeSignedDocument(ctx, signedTxDocument{
		Type:    signedTxType,
		Version: signRequestVersion,
		ID:      req.id.Hex(),
		Hash:    signed.Hash().Hex(),
		Raw:     "0x" + hex.EncodeToString(raw),
		From:    req.from.Hex(),
		Nonce:   new(big.Int).SetUint64(req.nonce).String(),
		ChainID: req.chainID.String(),
	}, "Signed transaction")
	return nil
}

// signRequestDocType returns the document's "type", or "" if it can't be
// read; the full validators report why.
func signRequestDocType(data []byte) string {
	var doc struct {
		Type *string `json:"type"`
	}
	if json.Unmarshal(data, &doc) != nil || doc.Type == nil {
		return ""
	}
	return *doc.Type
}

// decryptRequestKey decrypts the keyfile and requires that it holds the
// request's from address. The caller zeroes the key.
func decryptRequestKey(ctx *cli.Context, keyfile string, from util.Address) *keystore.Key {
	keyjson, err := os.ReadFile(keyfile)
	if err != nil {
		utils.Fatalf("Failed to read the keyfile at '%s': %v", keyfile, err)
	}
	passphrase := getPassphrase(ctx, false)
	key, err := keystore.DecryptKey(keyjson, passphrase)
	if err != nil {
		utils.Fatalf("Error decrypting key: %v", err)
	}
	if key.Address != from {
		zeroPrivateKey(key.PrivateKey)
		utils.Fatalf("The keyfile holds %s, but the request is from %s", key.Address.Hex(), from.Hex())
	}
	return key
}

// confirmSigning asks question on the terminal and exits unless the answer
// is yes.
func confirmSigning(question string) {
	answer, err := prompt.Stdin.PromptInput(question)
	if err != nil {
		utils.Fatalf("Failed to read confirmation: %v", err)
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		utils.Fatalf("Not confirmed; nothing was signed")
	}
}

// writeSignedDocument encodes doc as indented JSON and writes it to --out
// (mode 0600) or stdout. what names the document in the confirmation.
func writeSignedDocument(ctx *cli.Context, doc any, what string) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		utils.Fatalf("Failed to marshal JSON object: %v", err)
	}
	out := buf.Bytes()

	if path := ctx.String(signRequestOutFlag.Name); path != "" {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			utils.Fatalf("Failed to create %s: %v", path, err)
		}
		if _, err := f.Write(out); err != nil {
			f.Close()
			utils.Fatalf("Failed to write %s: %v", path, err)
		}
		if err := f.Close(); err != nil {
			utils.Fatalf("Failed to write %s: %v", path, err)
		}
		// The mode above applies only to a new file: tighten one it replaced
		if err := os.Chmod(path, 0o600); err != nil {
			utils.Fatalf("Failed to restrict %s: %v", path, err)
		}
		fmt.Fprintf(os.Stderr, "%s written to %s\n", what, path)
		return
	}
	os.Stdout.Write(out)
}

// readSignRequest reads the request document from path ("-" for stdin),
// refusing anything over the 8 KiB cap.
func readSignRequest(path string) ([]byte, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, signRequestMaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > signRequestMaxSize {
		return nil, fmt.Errorf("document is larger than %d bytes", signRequestMaxSize)
	}
	return data, nil
}

// validateSignRequest parses a request document and runs every check of
// the exchange format that doesn't need the private key, in the order the
// format lists them. The check that "from" is the key's address is left
// to the caller.
func validateSignRequest(data []byte, allowedChain, feeCap *big.Int) (*validatedRequest, error) {
	var doc signRequest
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("malformed JSON: %v", err)
	}
	for _, f := range []struct {
		name    string
		missing bool
	}{
		{"type", doc.Type == nil}, {"version", doc.Version == nil},
		{"id", doc.ID == nil}, {"chainId", doc.ChainID == nil},
		{"from", doc.From == nil}, {"to", doc.To == nil},
		{"nonce", doc.Nonce == nil}, {"valueWei", doc.ValueWei == nil},
		{"gasLimit", doc.GasLimit == nil}, {"gasPriceWei", doc.GasPriceWei == nil},
	} {
		if f.missing {
			return nil, fmt.Errorf("missing required field %q", f.name)
		}
	}
	req := new(validatedRequest)

	// 1. Document type and version.
	if *doc.Type != signRequestType {
		return nil, fmt.Errorf("type is %q, want %q", *doc.Type, signRequestType)
	}
	if *doc.Version != signRequestVersion {
		return nil, fmt.Errorf("unsupported version %d (this signer understands version %d)", *doc.Version, signRequestVersion)
	}

	// 2. Chain ID must be the allowed one.
	chainID, err := parseDecimal(*doc.ChainID)
	if err != nil {
		return nil, fmt.Errorf("chainId: %v", err)
	}
	if chainID.Cmp(allowedChain) != 0 {
		if allowedChain.Cmp(big.NewInt(signRequestMainnet)) == 0 {
			return nil, fmt.Errorf("chainId %s is not Parallax mainnet (%d); pass --chainid %s to allow it", chainID, signRequestMainnet, chainID)
		}
		return nil, fmt.Errorf("chainId %s does not match --chainid %s", chainID, allowedChain)
	}
	req.chainID = chainID

	// 3. Addresses (the key match is checked once the key is decrypted).
	if req.from, err = parseRequestAddress(*doc.From); err != nil {
		return nil, fmt.Errorf("from: %v", err)
	}
	if req.to, err = parseRequestAddress(*doc.To); err != nil {
		return nil, fmt.Errorf("to: %v", err)
	}
	if req.to == (util.Address{}) {
		return nil, errors.New("to is the zero address")
	}

	// 4. Integer fields.
	nonce, err := parseDecimal(*doc.Nonce)
	if err != nil || !nonce.IsUint64() {
		return nil, fmt.Errorf("nonce %q is not a valid uint64", *doc.Nonce)
	}
	req.nonce = nonce.Uint64()
	gas, err := parseDecimal(*doc.GasLimit)
	if err != nil || !gas.IsUint64() {
		return nil, fmt.Errorf("gasLimit %q is not a valid uint64", *doc.GasLimit)
	}
	req.gas = gas.Uint64()
	if req.value, err = parseDecimal(*doc.ValueWei); err != nil {
		return nil, fmt.Errorf("valueWei: %v", err)
	}
	if req.gasPrice, err = parseDecimal(*doc.GasPriceWei); err != nil {
		return nil, fmt.Errorf("gasPriceWei: %v", err)
	}
	if req.gasPrice.Sign() == 0 {
		return nil, errors.New("gasPriceWei must be greater than zero")
	}
	if req.gas < signRequestMinGas || req.gas > signRequestMaxGas {
		return nil, fmt.Errorf("gasLimit %d is outside %d..%d", req.gas, signRequestMinGas, signRequestMaxGas)
	}

	// 5. Plain transfers only.
	if doc.Data != nil && *doc.Data != "" && *doc.Data != "0x" {
		return nil, errors.New("data must be empty (version 1 signs plain LAX transfers only)")
	}

	// 6. Fee cap.
	req.maxFee = new(big.Int).Mul(new(big.Int).SetUint64(req.gas), req.gasPrice)
	if req.maxFee.Cmp(feeCap) > 0 {
		return nil, fmt.Errorf("max fee %s LAX exceeds the cap of %s LAX (raise it with --feecap)", formatUnits(req.maxFee, weiPerLAX), formatUnits(feeCap, weiPerLAX))
	}

	// 7. The id must bind exactly these fields.
	if !isHex32(*doc.ID) {
		return nil, fmt.Errorf("id %q is not a 0x-prefixed 32-byte hex string", *doc.ID)
	}
	req.tx = types.NewTransaction(req.nonce, req.to, req.value, req.gas, req.gasPrice, nil)
	req.signer = types.LatestSignerForChainID(req.chainID)
	req.id = req.signer.Hash(req.tx)
	if !strings.EqualFold(*doc.ID, req.id.Hex()) {
		return nil, fmt.Errorf("id %s does not match the transaction's signing hash %s; the request was altered", *doc.ID, req.id.Hex())
	}

	if doc.Memo != nil {
		if utf8.RuneCountInString(*doc.Memo) > signRequestMaxMemo {
			return nil, fmt.Errorf("memo is longer than %d characters", signRequestMaxMemo)
		}
		req.memo = *doc.Memo
	}
	return req, nil
}

// checkSignedTx re-derives everything a broadcaster will check, so a bad
// signature never leaves the offline machine.
func checkSignedTx(tx *types.Transaction, req *validatedRequest) error {
	if tx.Type() != types.LegacyTxType {
		return fmt.Errorf("transaction type %d is not legacy", tx.Type())
	}
	if !tx.Protected() {
		return errors.New("signature is not EIP-155 protected")
	}
	if tx.ChainId().Cmp(req.chainID) != 0 {
		return fmt.Errorf("chain ID %s, want %s", tx.ChainId(), req.chainID)
	}
	sender, err := types.Sender(req.signer, tx)
	if err != nil {
		return err
	}
	if sender != req.from {
		return fmt.Errorf("sender recovers to %s, want %s", sender.Hex(), req.from.Hex())
	}
	if h := req.signer.Hash(tx); h != req.id {
		return fmt.Errorf("signing hash %s, want %s", h.Hex(), req.id.Hex())
	}
	return nil
}

// printSignRequestSummary writes what is about to be signed.
func printSignRequestSummary(w io.Writer, req *validatedRequest) {
	fmt.Fprintln(w, "Signing request")
	fmt.Fprintln(w, "  From:       ", req.from.Hex())
	fmt.Fprintln(w, "  To:         ", req.to.Hex())
	fmt.Fprintln(w, "  Amount:     ", formatUnits(req.value, weiPerLAX), "LAX")
	fmt.Fprintln(w, "  Max fee:    ", formatUnits(req.maxFee, weiPerLAX), "LAX")
	fmt.Fprintln(w, "  Gas price:  ", formatUnits(req.gasPrice, weiPerGwei), "gwei")
	fmt.Fprintln(w, "  Gas limit:  ", req.gas)
	fmt.Fprintln(w, "  Nonce:      ", req.nonce)
	fmt.Fprintln(w, "  Chain ID:   ", req.chainID)
	if req.memo != "" {
		fmt.Fprintf(w, "  Memo:        %q (not signed)\n", req.memo)
	}
	fmt.Fprintln(w, "  Fingerprint:", signRequestFingerprint(req.id))
}

// signRequestFingerprint is the short code both sides display: the first
// eight hex digits of the id, upper-cased, as two groups of four.
func signRequestFingerprint(id util.Hash) string {
	h := strings.ToUpper(id.Hex()[2:10])
	return h[:4] + "-" + h[4:]
}

// parseDecimal parses a non-negative decimal integer string strictly: ASCII
// digits only, no sign, no hex, at most 256 bits.
func parseDecimal(s string) (*big.Int, error) {
	if s == "" {
		return nil, errors.New("empty integer")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return nil, fmt.Errorf("%q is not a decimal integer", s)
		}
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("%q is not a decimal integer", s)
	}
	if v.BitLen() > signRequestMaxBits {
		return nil, fmt.Errorf("%q is out of range", s)
	}
	return v, nil
}

// parseRequestAddress accepts a 0x-prefixed, 40 hex digit address. A
// mixed-case address must carry a valid EIP-55 checksum.
func parseRequestAddress(s string) (util.Address, error) {
	if len(s) != 42 || !strings.HasPrefix(s, "0x") {
		return util.Address{}, fmt.Errorf("%q is not a 0x-prefixed 40 hex digit address", s)
	}
	if _, err := hex.DecodeString(s[2:]); err != nil {
		return util.Address{}, fmt.Errorf("%q is not a 0x-prefixed 40 hex digit address", s)
	}
	addr := util.HexToAddress(s)
	body := s[2:]
	if body != strings.ToLower(body) && body != strings.ToUpper(body) && s != addr.Hex() {
		return util.Address{}, fmt.Errorf("%q has an invalid checksum", s)
	}
	return addr, nil
}

// isHex32 reports whether s is 0x followed by exactly 64 hex digits.
func isHex32(s string) bool {
	if len(s) != 66 || !strings.HasPrefix(s, "0x") {
		return false
	}
	_, err := hex.DecodeString(s[2:])
	return err == nil
}

// parseLAX converts a decimal LAX amount such as "1" or "0.25" to wei
// exactly, without going through floating point.
func parseLAX(s string) (*big.Int, error) {
	whole, frac, hasDot := strings.Cut(s, ".")
	if whole == "" && frac == "" {
		return nil, fmt.Errorf("%q is not a LAX amount", s)
	}
	if hasDot && frac == "" {
		return nil, fmt.Errorf("%q is not a LAX amount", s)
	}
	if len(frac) > 18 {
		return nil, fmt.Errorf("%q has more than 18 decimal places", s)
	}
	if whole == "" {
		whole = "0"
	}
	digits := whole + frac + strings.Repeat("0", 18-len(frac))
	v, err := parseDecimal(digits)
	if err != nil {
		return nil, fmt.Errorf("%q is not a LAX amount", s)
	}
	return v, nil
}

// formatUnits renders v / unit as an exact decimal with trailing zeros
// trimmed. unit must be a power of ten.
func formatUnits(v, unit *big.Int) string {
	q, r := new(big.Int).QuoRem(v, unit, new(big.Int))
	if r.Sign() == 0 {
		return q.String()
	}
	decimals := len(unit.String()) - 1
	frac := r.String()
	frac = strings.Repeat("0", decimals-len(frac)) + frac
	return q.String() + "." + strings.TrimRight(frac, "0")
}

// zeroPrivateKey overwrites the private scalar in memory.
func zeroPrivateKey(k *ecdsa.PrivateKey) {
	if k == nil || k.D == nil {
		return
	}
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}
