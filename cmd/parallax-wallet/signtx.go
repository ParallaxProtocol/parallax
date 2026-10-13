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
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ParallaxProtocol/parallax/v2/cmd/utils"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/keystore"
	"gopkg.in/urfave/cli.v1"
)

type signTxOutput struct {
	Raw     string `json:"raw"`
	Hash    string `json:"hash"`
	From    string `json:"from"`
	To      string `json:"to,omitempty"`
	Nonce   uint64 `json:"nonce"`
	ChainID string `json:"chainid"`
}

var (
	signTxChainIDFlag = cli.StringFlag{
		Name:  "chainid",
		Usage: "chain ID for EIP-155 replay protection (integer or 0x hex)",
	}
	signTxNonceFlag = cli.StringFlag{
		Name:  "nonce",
		Usage: "transaction nonce (integer or 0x hex)",
	}
	signTxToFlag = cli.StringFlag{
		Name:  "to",
		Usage: "recipient address; omit to produce a contract-creation tx",
	}
	signTxValueFlag = cli.StringFlag{
		Name:  "value",
		Usage: "value in wei (integer or 0x hex); default 0",
	}
	signTxGasFlag = cli.StringFlag{
		Name:  "gas",
		Usage: "gas limit (integer)",
	}
	signTxGasPriceFlag = cli.StringFlag{
		Name:  "gasprice",
		Usage: "gas price in wei (integer or 0x hex)",
	}
	signTxDataFlag = cli.StringFlag{
		Name:  "data",
		Usage: "call data as hex (0x-prefixed); default empty",
	}
)

var commandSignTx = cli.Command{
	Name:      "signtx",
	Usage:     "build and sign a transaction offline with a keyfile",
	ArgsUsage: "<keyfile>",
	Flags: []cli.Flag{
		passphraseFlag,
		jsonFlag,
		signTxChainIDFlag,
		signTxNonceFlag,
		signTxToFlag,
		signTxValueFlag,
		signTxGasFlag,
		signTxGasPriceFlag,
		signTxDataFlag,
	},
	Description: `
Build a legacy transaction from the given flags, sign it with the
private key decrypted from <keyfile>, and print the raw signed payload
as 0x-prefixed hex suitable for submission via "parallax-cli sendraw".

This command never talks to a node: the caller is responsible for
providing a correct --nonce, --gas, --gasprice, and --chainid. Obtain
these from a running node (for example, parallax-cli nonce /
gasprice) and pass them in explicitly when you want to cold-sign.`,
	Action: runSignTx,
}

func runSignTx(ctx *cli.Context) error {
	keyfile := ctx.Args().First()
	if keyfile == "" {
		utils.Fatalf("keyfile must be given as argument")
	}
	chainID := mustParseBigInt(ctx, signTxChainIDFlag.Name, true)
	nonce := mustParseUint64(ctx, signTxNonceFlag.Name, true)
	gas := mustParseUint64(ctx, signTxGasFlag.Name, true)
	gasPrice := mustParseBigInt(ctx, signTxGasPriceFlag.Name, true)
	value := mustParseBigInt(ctx, signTxValueFlag.Name, false)
	if value == nil {
		value = new(big.Int)
	}
	data := mustParseHex(ctx, signTxDataFlag.Name)

	var to *util.Address
	if toStr := ctx.String(signTxToFlag.Name); toStr != "" {
		if !util.IsHexAddress(toStr) {
			utils.Fatalf("Invalid --to address: %s", toStr)
		}
		addr := util.HexToAddress(toStr)
		to = &addr
	}

	keyjson, err := os.ReadFile(keyfile)
	if err != nil {
		utils.Fatalf("Failed to read the keyfile at '%s': %v", keyfile, err)
	}
	passphrase := getPassphrase(ctx, false)
	key, err := keystore.DecryptKey(keyjson, passphrase)
	if err != nil {
		utils.Fatalf("Error decrypting key: %v", err)
	}

	var tx *types.Transaction
	if to == nil {
		tx = types.NewContractCreation(nonce, value, gas, gasPrice, data)
	} else {
		tx = types.NewTransaction(nonce, *to, value, gas, gasPrice, data)
	}

	signer := types.LatestSignerForChainID(chainID)
	signed, err := types.SignTx(tx, signer, key.PrivateKey)
	if err != nil {
		utils.Fatalf("Failed to sign transaction: %v", err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		utils.Fatalf("Failed to encode transaction: %v", err)
	}

	out := signTxOutput{
		Raw:     "0x" + hex.EncodeToString(raw),
		Hash:    signed.Hash().Hex(),
		From:    key.Address.Hex(),
		Nonce:   nonce,
		ChainID: chainID.String(),
	}
	if to != nil {
		out.To = to.Hex()
	}

	if ctx.Bool(jsonFlag.Name) {
		mustPrintJSON(out)
		return nil
	}
	fmt.Println("Raw:    ", out.Raw)
	fmt.Println("Hash:   ", out.Hash)
	fmt.Println("From:   ", out.From)
	if out.To != "" {
		fmt.Println("To:     ", out.To)
	} else {
		fmt.Println("To:      <contract creation>")
	}
	fmt.Println("Nonce:  ", out.Nonce)
	fmt.Println("ChainID:", out.ChainID)
	return nil
}

func mustParseBigInt(ctx *cli.Context, flagName string, required bool) *big.Int {
	raw := ctx.String(flagName)
	if raw == "" {
		if required {
			utils.Fatalf("--%s is required", flagName)
		}
		return nil
	}
	v := new(big.Int)
	trimmed := strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")
	base := 10
	if trimmed != raw {
		base = 16
	}
	if _, ok := v.SetString(trimmed, base); !ok {
		utils.Fatalf("Invalid --%s value: %s", flagName, raw)
	}
	return v
}

func mustParseUint64(ctx *cli.Context, flagName string, required bool) uint64 {
	v := mustParseBigInt(ctx, flagName, required)
	if v == nil {
		return 0
	}
	if !v.IsUint64() {
		utils.Fatalf("Invalid --%s value: must fit in uint64", flagName)
	}
	return v.Uint64()
}

func mustParseHex(ctx *cli.Context, flagName string) []byte {
	raw := ctx.String(flagName)
	if raw == "" {
		return nil
	}
	trimmed := strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")
	b, err := hex.DecodeString(trimmed)
	if err != nil {
		utils.Fatalf("Invalid --%s hex: %v", flagName, err)
	}
	return b
}
