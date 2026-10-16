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

package usbwallet

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/primitives/rlp"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet"
	"github.com/ParallaxProtocol/parallax/v2/wallet/usbwallet/trezor"
	"google.golang.org/protobuf/proto"
)

// testChainID is Parallax's, whose EIP-155 V (2110*2+35) doesn't fit the byte
// a Ledger replies with.
var testChainID = big.NewInt(2110)

func testTx(data []byte) *types.Transaction {
	to := util.HexToAddress("0x00000000000000000000000000000000deadbeef")
	return types.NewTransaction(7, to, big.NewInt(1e18), 21000+uint64(len(data))*16, big.NewInt(1e9), data)
}

// fakeLedger speaks the Ledger HID framing, handing each APDU it's sent to
// handle and framing the reply (data followed by the status word) back.
type fakeLedger struct {
	handle func(apdu []byte) []byte

	in   []byte
	need int
	out  bytes.Buffer
}

func (f *fakeLedger) Write(chunk []byte) (int, error) {
	payload := chunk[5:]
	if binary.BigEndian.Uint16(chunk[3:5]) == 0 {
		f.need, f.in, payload = int(binary.BigEndian.Uint16(payload[:2])), nil, payload[2:]
	}
	f.in = append(f.in, payload[:min(len(payload), f.need-len(f.in))]...)
	if len(f.in) == f.need {
		reply := binary.BigEndian.AppendUint16(nil, 0)
		reply = append(reply, f.handle(f.in)...)
		binary.BigEndian.PutUint16(reply, uint16(len(reply)-2))
		for seq := 0; seq == 0 || len(reply) > 0; seq++ {
			frame := make([]byte, 64)
			copy(frame, []byte{0x01, 0x01, 0x05})
			binary.BigEndian.PutUint16(frame[3:], uint16(seq))
			reply = reply[copy(frame[5:], reply):]
			f.out.Write(frame)
		}
	}
	return len(chunk), nil
}

func (f *fakeLedger) Read(p []byte) (int, error) { return f.out.Read(p) }

func sw(code uint16) []byte { return binary.BigEndian.AppendUint16(nil, code) }

// ledgerApp is an Ethereum app on a fake Ledger, holding one key on every path.
type ledgerApp struct {
	key    *ecdsa.PrivateKey
	closed bool   // whether the app isn't open (the dashboard answers)
	deny   bool   // whether the user turns signing down
	tx     []byte // the transaction payload received so far
	txLen  int    // the payload length the transaction under test takes
	msg    []byte // the personal message received so far
	msgLen int
}

func (a *ledgerApp) handle(t *testing.T) func([]byte) []byte {
	return func(apdu []byte) []byte {
		if a.closed {
			return sw(0x6e00)
		}
		ins, p1, data := apdu[1], apdu[2], apdu[5:]
		switch ledgerOpcode(ins) {
		case ledgerOpGetConfiguration:
			return append([]byte{0x00, 1, 12, 0}, sw(0x9000)...)

		case ledgerOpRetrieveAddress:
			pub := crypto.FromECDSAPub(&a.key.PublicKey)
			addr := []byte(hex.EncodeToString(crypto.PubkeyToAddress(a.key.PublicKey).Bytes()))
			reply := append([]byte{byte(len(pub))}, pub...)
			reply = append(append(reply, byte(len(addr))), addr...)
			return append(reply, sw(0x9000)...)

		case ledgerOpSignTransaction:
			if p1 == byte(ledgerP1InitTransactionData) {
				a.tx = nil
			}
			a.tx = append(a.tx, data...)
			if len(a.tx) < a.txLen {
				return sw(0x9000)
			}
			if a.deny {
				return sw(0x6985)
			}
			// The test's transaction carries no data, so its hash is known
			hash := types.NewEIP155Signer(testChainID).Hash(testTx(nil))
			sig, err := crypto.Sign(hash[:], a.key)
			if err != nil {
				t.Fatal(err)
			}
			// The app's V is the full EIP-155 one, cut to its low byte
			v := byte(testChainID.Uint64()*2 + 35 + uint64(sig[64]))
			return append(append([]byte{v}, sig[:64]...), sw(0x9000)...)

		case ledgerOpSignPersonalMessage:
			if p1 == byte(ledgerP1InitPersonalMessageData) {
				pathLen := 1 + 4*int(data[0])
				a.msgLen = int(binary.BigEndian.Uint32(data[pathLen:]))
				a.msg, data = nil, data[pathLen+4:]
			}
			a.msg = append(a.msg, data...)
			if len(a.msg) < a.msgLen {
				return sw(0x9000)
			}
			if a.deny {
				return sw(0x6985)
			}
			sig, err := crypto.Sign(wallet.TextHash(a.msg), a.key)
			if err != nil {
				t.Fatal(err)
			}
			return append(append([]byte{27 + sig[64]}, sig[:64]...), sw(0x9000)...)
		}
		return sw(0x6d00)
	}
}

func newLedgerTest(t *testing.T) (*ledgerApp, *ledgerDriver, util.Address) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	app := &ledgerApp{key: key}
	driver := newLedgerDriver(logging.New()).(*ledgerDriver)
	if err := driver.Open(&fakeLedger{handle: app.handle(t)}, ""); err != nil {
		t.Fatal(err)
	}
	return app, driver, crypto.PubkeyToAddress(key.PublicKey)
}

func TestLedgerSignTxChainID(t *testing.T) {
	app, driver, addr := newLedgerTest(t)

	// The payload is the path then the EIP-155 RLP, split as the driver splits it
	path := wallet.DefaultBaseDerivationPath
	tx := testTx(nil)
	app.txLen = 1 + 4*len(path) + len(mustRLP(t, tx))

	sender, signed, err := driver.SignTx(path, tx, testChainID)
	if err != nil {
		t.Fatal(err)
	}
	if sender != addr {
		t.Fatalf("sender %s, want %s", sender.Hex(), addr.Hex())
	}
	if signed.ChainId().Cmp(testChainID) != 0 {
		t.Fatalf("chain ID %v, want %v", signed.ChainId(), testChainID)
	}
	if from, err := types.Sender(types.LatestSignerForChainID(testChainID), signed); err != nil || from != addr {
		t.Fatalf("recovered %s (%v), want %s", from.Hex(), err, addr.Hex())
	}
}

func mustRLP(t *testing.T, tx *types.Transaction) []byte {
	t.Helper()
	// The unsigned EIP-155 RLP the driver sends: the transaction's fields,
	// then the chain ID and two zeros
	enc, err := rlp.EncodeToBytes([]any{tx.Nonce(), tx.GasPrice(), tx.Gas(), tx.To(), tx.Value(), tx.Data(), testChainID, big.NewInt(0), big.NewInt(0)})
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func TestLedgerSignTextAndDenial(t *testing.T) {
	app, driver, addr := newLedgerTest(t)

	// A message long enough to take several chunks
	msg := bytes.Repeat([]byte("Parallax "), 60)
	sig, err := driver.SignText(wallet.DefaultBaseDerivationPath, msg)
	if err != nil {
		t.Fatal(err)
	}
	if sig[64] != 27 && sig[64] != 28 {
		t.Fatalf("V %d, want 27 or 28", sig[64])
	}
	sig[64] -= 27
	pub, err := crypto.SigToPub(wallet.TextHash(msg), sig)
	if err != nil || crypto.PubkeyToAddress(*pub) != addr {
		t.Fatalf("message signed by the wrong key (%v)", err)
	}
	app.deny = true
	if _, err := driver.SignText(wallet.DefaultBaseDerivationPath, []byte("no")); !errors.Is(err, ErrLedgerDenied) {
		t.Fatalf("denied signing: %v, want %v", err, ErrLedgerDenied)
	}
}

func TestLedgerAppOpenedLater(t *testing.T) {
	key, _ := crypto.GenerateKey()
	app := &ledgerApp{key: key, closed: true}
	driver := newLedgerDriver(logging.New()).(*ledgerDriver)
	if err := driver.Open(&fakeLedger{handle: app.handle(t)}, ""); err != nil {
		t.Fatal(err)
	}
	if !driver.offline() {
		t.Fatal("driver online with the app closed")
	}
	if _, err := driver.Derive(wallet.DefaultBaseDerivationPath); !errors.Is(err, ErrLedgerAppClosed) {
		t.Fatalf("derive with the app closed: %v, want %v", err, ErrLedgerAppClosed)
	}
	if err := driver.Heartbeat(); err != nil {
		t.Fatalf("heartbeat failed with the device there: %v", err)
	}
	app.closed = false
	if _, err := driver.Derive(wallet.DefaultBaseDerivationPath); err != nil {
		t.Fatal(err)
	}
	if driver.version != [3]byte{1, 12, 0} {
		t.Fatalf("version %v once the app is open, want 1.12.0", driver.version)
	}
}

func TestLedgerVersionLessThan(t *testing.T) {
	tests := []struct {
		version, than [3]byte
		want          bool
	}{
		{[3]byte{1, 0, 2}, [3]byte{1, 0, 3}, true},
		{[3]byte{1, 0, 3}, [3]byte{1, 0, 3}, false},
		{[3]byte{0, 9, 9}, [3]byte{1, 0, 3}, true},
		{[3]byte{1, 4, 9}, [3]byte{1, 5, 0}, true},
		{[3]byte{2, 0, 0}, [3]byte{1, 5, 0}, false},
		{[3]byte{1, 12, 0}, [3]byte{1, 9, 0}, false},
	}
	for _, tt := range tests {
		if got := ledgerVersionLessThan(tt.version, tt.than[0], tt.than[1], tt.than[2]); got != tt.want {
			t.Errorf("ledgerVersionLessThan(%v, %v) = %v, want %v", tt.version, tt.than, got, tt.want)
		}
	}
}

// fakeTrezor speaks the Trezor framing, handing each message it's sent to
// handle and framing the reply back.
type fakeTrezor struct {
	handle func(kind uint16, data []byte) (uint16, []byte)

	started bool
	kind    uint16
	in      []byte
	need    int
	out     bytes.Buffer
}

func (f *fakeTrezor) Write(chunk []byte) (int, error) {
	payload := chunk[1:]
	if !f.started {
		f.started = true
		f.kind = binary.BigEndian.Uint16(chunk[3:5])
		f.need = int(binary.BigEndian.Uint32(chunk[5:9]))
		f.in, payload = nil, chunk[9:]
	}
	f.in = append(f.in, payload[:min(len(payload), f.need-len(f.in))]...)
	if len(f.in) == f.need {
		f.started = false
		kind, data := f.handle(f.kind, f.in)
		reply := []byte{0x23, 0x23}
		reply = binary.BigEndian.AppendUint16(reply, kind)
		reply = binary.BigEndian.AppendUint32(reply, uint32(len(data)))
		reply = append(reply, data...)
		for len(reply) > 0 {
			frame := make([]byte, 64)
			frame[0] = 0x3f
			reply = reply[copy(frame[1:], reply):]
			f.out.Write(frame)
		}
	}
	return len(chunk), nil
}

func (f *fakeTrezor) Read(p []byte) (int, error) { return f.out.Read(p) }

// trezorDevice is a fake Trezor of a model, protected by a PIN and a passphrase.
type trezorDevice struct {
	t     *testing.T
	key   *ecdsa.PrivateKey
	model string

	unlocked   bool
	passphrase bool // whether the passphrase was given
	onDevice   bool // whether the host asked for it on the device
	deny       bool
}

func (d *trezorDevice) reply(msg proto.Message) (uint16, []byte) {
	data, err := proto.Marshal(msg)
	if err != nil {
		d.t.Fatal(err)
	}
	return trezor.Type(msg), data
}

func (d *trezorDevice) address() (uint16, []byte) {
	hex := crypto.PubkeyToAddress(d.key.PublicKey).Hex()
	return d.reply(&trezor.ParallaxAddress{AddressHex: &hex})
}

func (d *trezorDevice) handle(kind uint16, data []byte) (uint16, []byte) {
	switch trezor.MessageType(kind) {
	case trezor.MessageType_MessageType_Initialize:
		d.unlocked, d.passphrase = false, false
		return d.reply(&trezor.Features{Model: &d.model})

	case trezor.MessageType_MessageType_ParallaxGetAddress:
		if !d.unlocked {
			return d.reply(&trezor.PinMatrixRequest{})
		}
		if !d.passphrase {
			return d.reply(&trezor.PassphraseRequest{})
		}
		return d.address()

	case trezor.MessageType_MessageType_PinMatrixAck:
		ack := new(trezor.PinMatrixAck)
		if err := proto.Unmarshal(data, ack); err != nil {
			d.t.Fatal(err)
		}
		if ack.GetPin() != "1234" {
			code := trezor.Failure_Failure_PinInvalid
			return d.reply(&trezor.Failure{Code: &code})
		}
		d.unlocked = true
		return d.reply(&trezor.PassphraseRequest{})

	case trezor.MessageType_MessageType_PassphraseAck:
		d.onDevice = bytes.Equal(data, passphraseAckOnDevice)
		d.passphrase = true
		return d.address()

	case trezor.MessageType_MessageType_ParallaxSignTx:
		if d.deny {
			code := trezor.Failure_Failure_ActionCancelled
			return d.reply(&trezor.Failure{Code: &code})
		}
		return d.reply(&trezor.ButtonRequest{})

	case trezor.MessageType_MessageType_ButtonAck:
		hash := types.NewEIP155Signer(testChainID).Hash(testTx(nil))
		sig, err := crypto.Sign(hash[:], d.key)
		if err != nil {
			d.t.Fatal(err)
		}
		v := uint32(testChainID.Uint64()*2+35) + uint32(sig[64])
		return d.reply(&trezor.ParallaxTxRequest{SignatureV: &v, SignatureR: sig[:32], SignatureS: sig[32:64]})

	case trezor.MessageType_MessageType_ParallaxSignMessage:
		req := new(trezor.ParallaxSignMessage)
		if err := proto.Unmarshal(data, req); err != nil {
			d.t.Fatal(err)
		}
		sig, err := crypto.Sign(wallet.TextHash(req.GetMessage()), d.key)
		if err != nil {
			d.t.Fatal(err)
		}
		sig[64] += 27
		return d.reply(&trezor.ParallaxMessageSignature{Signature: sig})
	}
	d.t.Fatalf("unexpected message %s", trezor.Name(kind))
	return 0, nil
}

func TestTrezorOpenSignOnDevicePassphrase(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	dev := &trezorDevice{t: t, key: key, model: "T"}
	driver := newTrezorDriver(logging.New()).(*trezorDriver)
	usb := &fakeTrezor{handle: dev.handle}

	if err := driver.Open(usb, ""); err != ErrTrezorPINNeeded {
		t.Fatalf("open: %v, want %v", err, ErrTrezorPINNeeded)
	}
	if err := driver.Open(usb, "0000"); err != ErrTrezorPINInvalid {
		t.Fatalf("wrong PIN: %v, want %v", err, ErrTrezorPINInvalid)
	}
	// A wrong PIN leaves the device usable for another go
	if _, err := driver.Status(); err != nil {
		t.Fatalf("status after a wrong PIN: %v", err)
	}
	if err := driver.Open(usb, ""); err != ErrTrezorPINNeeded {
		t.Fatalf("reopen: %v, want %v", err, ErrTrezorPINNeeded)
	}
	// The passphrase that follows the PIN is asked for on the device's screen
	if err := driver.Open(usb, "1234"); err != nil {
		t.Fatalf("open with the PIN: %v", err)
	}
	if !dev.onDevice {
		t.Fatal("passphrase not asked for on the device")
	}
	sender, signed, err := driver.SignTx(wallet.DefaultBaseDerivationPath, testTx(nil), testChainID)
	if err != nil {
		t.Fatal(err)
	}
	if sender != addr || signed.ChainId().Cmp(testChainID) != 0 {
		t.Fatalf("signed by %s on chain %v, want %s on %v", sender.Hex(), signed.ChainId(), addr.Hex(), testChainID)
	}
	sig, err := driver.SignText(wallet.DefaultBaseDerivationPath, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	sig[64] -= 27
	if pub, err := crypto.SigToPub(wallet.TextHash([]byte("hello")), sig); err != nil || crypto.PubkeyToAddress(*pub) != addr {
		t.Fatalf("message signed by the wrong key (%v)", err)
	}
	dev.deny = true
	if _, _, err := driver.SignTx(wallet.DefaultBaseDerivationPath, testTx(nil), testChainID); err != ErrTrezorDenied {
		t.Fatalf("denied signing: %v, want %v", err, ErrTrezorDenied)
	}
	typed := types.NewTx(&types.AccessListTx{ChainID: testChainID, Nonce: 1, GasPrice: big.NewInt(1), Gas: 21000})
	if _, _, err := driver.SignTx(wallet.DefaultBaseDerivationPath, typed, testChainID); !errors.Is(err, wallet.ErrNotSupported) {
		t.Fatalf("typed transaction: %v, want %v", err, wallet.ErrNotSupported)
	}
}

func TestTrezorOneHostPassphrase(t *testing.T) {
	key, _ := crypto.GenerateKey()
	dev := &trezorDevice{t: t, key: key, model: "1"}
	driver := newTrezorDriver(logging.New()).(*trezorDriver)
	usb := &fakeTrezor{handle: dev.handle}

	if err := driver.Open(usb, ""); err != ErrTrezorPINNeeded {
		t.Fatalf("open: %v, want %v", err, ErrTrezorPINNeeded)
	}
	if err := driver.Open(usb, "1234"); err != ErrTrezorPassphraseNeeded {
		t.Fatalf("open with the PIN: %v, want %v", err, ErrTrezorPassphraseNeeded)
	}
	if err := driver.Open(usb, "secret"); err != nil {
		t.Fatalf("open with the passphrase: %v", err)
	}
	if dev.onDevice {
		t.Fatal("a Trezor One asked for the passphrase on the device")
	}
}
