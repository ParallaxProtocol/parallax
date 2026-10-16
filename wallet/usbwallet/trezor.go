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

// This file contains the implementation for interacting with the Trezor hardware
// wallets. The wire protocol spec can be found on the SatoshiLabs website:
// https://doc.satoshilabs.com/trezor-tech/api-protobuf.html

package usbwallet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"

	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/util/hexutil"
	"github.com/ParallaxProtocol/parallax/v2/wallet"
	"github.com/ParallaxProtocol/parallax/v2/wallet/usbwallet/trezor"
	"google.golang.org/protobuf/proto"
)

// ErrTrezorPINNeeded is returned if opening the trezor requires a PIN code. In
// this case, the calling application should display a pinpad and send back the
// encoded passphrase.
var ErrTrezorPINNeeded = errors.New("trezor: pin needed")

// ErrTrezorPassphraseNeeded is returned if opening the trezor requires a passphrase
var ErrTrezorPassphraseNeeded = errors.New("trezor: passphrase needed")

// ErrTrezorDenied is returned when the user turned the request (or the PIN
// entry) down on the device.
var ErrTrezorDenied = errors.New("trezor: request denied on the device")

// ErrTrezorPINInvalid is returned when the PIN sent to the device was wrong.
var ErrTrezorPINInvalid = errors.New("trezor: invalid PIN")

// errTrezorReplyInvalidHeader is the error message returned by a Trezor data exchange
// if the device replies with a mismatching header. This usually means the device
// is in browser mode.
var errTrezorReplyInvalidHeader = errors.New("trezor: invalid reply header")

// trezorDriver implements the communication with a Trezor hardware wallet.
type trezorDriver struct {
	device         io.ReadWriter  // USB device connection to communicate through
	version        [3]uint32      // Current version of the Trezor firmware
	label          string         // Current textual label of the Trezor device
	model          string         // Hardware model of the Trezor device ("1", "T", "Safe 3", ...)
	pinwait        bool           // Flags whether the device is waiting for PIN entry
	passphrasewait bool           // Flags whether the device is waiting for passphrase entry
	failure        error          // Any failure that would make the device unusable
	log            logging.Logger // Contextual logger to tag the trezor with its id
}

// newTrezorDriver creates a new instance of a Trezor USB protocol driver.
func newTrezorDriver(logger logging.Logger) driver {
	return &trezorDriver{
		log: logger,
	}
}

// Status implements accounts.Wallet, always whether the Trezor is opened, closed
// or whether the Ethereum app was not started on it.
func (w *trezorDriver) Status() (string, error) {
	if w.failure != nil {
		return fmt.Sprintf("Failed: %v", w.failure), w.failure
	}
	if w.device == nil {
		return "Closed", w.failure
	}
	if w.pinwait {
		return fmt.Sprintf("Trezor v%d.%d.%d '%s' waiting for PIN", w.version[0], w.version[1], w.version[2], w.label), w.failure
	}
	return fmt.Sprintf("Trezor v%d.%d.%d '%s' online", w.version[0], w.version[1], w.version[2], w.label), w.failure
}

// Open implements usbwallet.driver, attempting to initialize the connection to
// the Trezor hardware wallet. Initializing the Trezor is a two or three phase operation:
//   - The first phase is to initialize the connection and read the wallet's
//     features. This phase is invoked if the provided passphrase is empty. The
//     device will display the pinpad as a result and will return an appropriate
//     error to notify the user that a second open phase is needed.
//   - The second phase is to unlock access to the Trezor, which is done by the
//     user actually providing a passphrase mapping a keyboard keypad to the pin
//     number of the user (shuffled according to the pinpad displayed).
//   - If needed the device will ask for passphrase which will require calling
//     open again with the actual passphrase (3rd phase)
func (w *trezorDriver) Open(device io.ReadWriter, passphrase string) error {
	w.device, w.failure = device, nil

	// If phase 1 is requested, init the connection and wait for user callback
	if passphrase == "" && !w.passphrasewait {
		// If we're already waiting for a PIN entry, insta-return
		if w.pinwait {
			return ErrTrezorPINNeeded
		}
		// Initialize a connection to the device
		features := new(trezor.Features)
		if _, err := w.trezorExchange(&trezor.Initialize{}, features); err != nil {
			return err
		}
		w.version = [3]uint32{features.GetMajorVersion(), features.GetMinorVersion(), features.GetPatchVersion()}
		w.label = features.GetLabel()
		w.model = features.GetModel()

		// Derive an address, which has the device ask for its PIN and passphrase
		// if it's protected by them. Firmware since 1.9 and 2.3 ignores the
		// Ping's pin_protection and passphrase_protection fields that used to.
		_, err := w.trezorDerive(wallet.DefaultBaseDerivationPath, false)
		return err
	}
	// Phase 2 requested with actual PIN entry, which the derivation that asked
	// for it carries on with (asking for the passphrase next, if need be)
	if w.pinwait {
		w.pinwait = false
		if _, err := w.trezorExchange(&trezor.PinMatrixAck{Pin: &passphrase}, new(trezor.ParallaxAddress)); err != nil {
			w.setFailure(err)
			return err
		}
	} else if w.passphrasewait {
		w.passphrasewait = false
		if _, err := w.trezorExchange(&trezor.PassphraseAck{Passphrase: &passphrase}, new(trezor.ParallaxAddress)); err != nil {
			w.setFailure(err)
			return err
		}
	}
	return nil
}

// setFailure marks the device unusable after err, unless err is one the user
// can put right by opening it again (a wrong PIN, a request turned down, or a
// PIN or passphrase asked for).
func (w *trezorDriver) setFailure(err error) {
	switch err {
	case ErrTrezorPINNeeded, ErrTrezorPassphraseNeeded, ErrTrezorPINInvalid, ErrTrezorDenied:
		return
	}
	w.failure = err
}

// Close implements usbwallet.driver, cleaning up and metadata maintained within
// the Trezor driver.
func (w *trezorDriver) Close() error {
	w.version, w.label, w.model, w.pinwait, w.passphrasewait = [3]uint32{}, "", "", false, false
	return nil
}

// Heartbeat implements usbwallet.driver, performing a sanity check against the
// Trezor to see if it's still online.
func (w *trezorDriver) Heartbeat() error {
	if _, err := w.trezorExchange(&trezor.Ping{}, new(trezor.Success)); err != nil {
		w.failure = err
		return err
	}
	return nil
}

// Derive implements usbwallet.driver, sending a derivation request to the Trezor
// and returning the Ethereum address located on that derivation path.
func (w *trezorDriver) Derive(path wallet.DerivationPath) (util.Address, error) {
	return w.trezorDerive(path, false)
}

// ShowAddress implements usbwallet.driver, showing the address on the given
// derivation path on the device's screen and returning it once the user
// confirms it there.
func (w *trezorDriver) ShowAddress(path wallet.DerivationPath) (util.Address, error) {
	return w.trezorDerive(path, true)
}

// SignTx implements usbwallet.driver, sending the transaction to the Trezor and
// waiting for the user to confirm or deny the transaction.
func (w *trezorDriver) SignTx(path wallet.DerivationPath, tx *types.Transaction, chainID *big.Int) (util.Address, *types.Transaction, error) {
	if w.device == nil {
		return util.Address{}, nil, wallet.ErrWalletClosed
	}
	// The Trezor backend signs legacy transactions only, so a typed one would
	// be signed as if it were one
	if tx.Type() != types.LegacyTxType {
		return util.Address{}, nil, fmt.Errorf("%w: transaction type %d on a Trezor", wallet.ErrNotSupported, tx.Type())
	}
	return w.trezorSign(path, tx, chainID)
}

func (w *trezorDriver) SignTypedMessage(path wallet.DerivationPath, domainHash []byte, messageHash []byte) ([]byte, error) {
	return nil, wallet.ErrNotSupported
}

// SignText implements usbwallet.driver, sending a personal message to the
// Trezor and waiting for the user to sign or deny it. The device hashes it the
// EIP-191 way, with the "\x19Ethereum Signed Message:\n" prefix.
func (w *trezorDriver) SignText(path wallet.DerivationPath, text []byte) ([]byte, error) {
	if w.device == nil {
		return nil, wallet.ErrWalletClosed
	}
	signature := new(trezor.ParallaxMessageSignature)
	if _, err := w.trezorExchange(&trezor.ParallaxSignMessage{AddressN: path, Message: text}, signature); err != nil {
		return nil, err
	}
	if len(signature.GetSignature()) != 65 {
		return nil, errors.New("reply lacks signature")
	}
	return signature.GetSignature(), nil
}

// trezorDerive sends a derivation request to the Trezor device and returns the
// Ethereum address located on that path, shown on the device's screen for the
// user to confirm if display is set.
func (w *trezorDriver) trezorDerive(derivationPath []uint32, display bool) (util.Address, error) {
	address := new(trezor.ParallaxAddress)
	if _, err := w.trezorExchange(&trezor.ParallaxGetAddress{AddressN: derivationPath, ShowDisplay: &display}, address); err != nil {
		return util.Address{}, err
	}
	if addr := address.GetAddressBin(); len(addr) > 0 { // Older firmwares use binary fomats
		return util.BytesToAddress(addr), nil
	}
	if addr := address.GetAddressHex(); len(addr) > 0 { // Newer firmwares use hexadecimal fomats
		return util.HexToAddress(addr), nil
	}
	return util.Address{}, errors.New("missing derived address")
}

// trezorSign sends the transaction to the Trezor wallet, and waits for the user
// to confirm or deny the transaction.
func (w *trezorDriver) trezorSign(derivationPath []uint32, tx *types.Transaction, chainID *big.Int) (util.Address, *types.Transaction, error) {
	// Create the transaction initiation message
	data := tx.Data()
	length := uint32(len(data))

	request := &trezor.ParallaxSignTx{
		AddressN:   derivationPath,
		Nonce:      new(big.Int).SetUint64(tx.Nonce()).Bytes(),
		GasPrice:   tx.GasPrice().Bytes(),
		GasLimit:   new(big.Int).SetUint64(tx.Gas()).Bytes(),
		Value:      tx.Value().Bytes(),
		DataLength: &length,
	}
	if to := tx.To(); to != nil {
		// Non contract deploy, set recipient explicitly
		hex := to.Hex()
		request.ToHex = &hex     // Newer firmwares (old will ignore)
		request.ToBin = (*to)[:] // Older firmwares (new will ignore)
	}
	if length > 1024 { // Send the data chunked if that was requested
		request.DataInitialChunk, data = data[:1024], data[1024:]
	} else {
		request.DataInitialChunk, data = data, nil
	}
	if chainID != nil { // EIP-155 transaction, set chain ID explicitly (only 32 bit is supported!?)
		id := uint32(chainID.Int64())
		request.ChainId = &id
	}
	// Send the initiation message and stream content until a signature is returned
	response := new(trezor.ParallaxTxRequest)
	if _, err := w.trezorExchange(request, response); err != nil {
		return util.Address{}, nil, err
	}
	for response.DataLength != nil && int(*response.DataLength) <= len(data) {
		chunk := data[:*response.DataLength]
		data = data[*response.DataLength:]

		if _, err := w.trezorExchange(&trezor.ParallaxTxAck{DataChunk: chunk}, response); err != nil {
			return util.Address{}, nil, err
		}
	}
	// Extract the Ethereum signature and do a sanity validation
	if len(response.GetSignatureR()) == 0 || len(response.GetSignatureS()) == 0 {
		return util.Address{}, nil, errors.New("reply lacks signature")
	} else if response.GetSignatureV() == 0 && int(chainID.Int64()) <= (math.MaxUint32-36)/2 {
		// for chainId >= (MaxUint32-36)/2, Trezor returns signature bit only
		// https://github.com/trezor/trezor-mcu/pull/399
		return util.Address{}, nil, errors.New("reply lacks signature")
	}
	signature := append(append(response.GetSignatureR(), response.GetSignatureS()...), byte(response.GetSignatureV()))

	// Create the correct signer and signature transform based on the chain ID
	var signer types.Signer
	if chainID == nil {
		signer = new(types.HomesteadSigner)
	} else {
		// Trezor backend does not support typed transactions yet.
		signer = types.NewEIP155Signer(chainID)
		// if chainId is above (MaxUint32 - 36) / 2 then the final v values is returned
		// directly. Otherwise, the returned value is 35 + chainid * 2.
		if signature[64] > 1 && int(chainID.Int64()) <= (math.MaxUint32-36)/2 {
			signature[64] -= byte(chainID.Uint64()*2 + 35)
		}
	}

	// Inject the final signature into the transaction and sanity check the sender
	signed, err := tx.WithSignature(signer, signature)
	if err != nil {
		return util.Address{}, nil, err
	}
	sender, err := types.Sender(signer, signed)
	if err != nil {
		return util.Address{}, nil, err
	}
	return sender, signed, nil
}

// trezorExchange performs a data exchange with the Trezor wallet, sending it a
// message and retrieving the response. If multiple responses are possible, the
// method will also return the index of the destination object used.
func (w *trezorDriver) trezorExchange(req proto.Message, results ...proto.Message) (int, error) {
	data, err := proto.Marshal(req)
	if err != nil {
		return 0, err
	}
	return w.trezorExchangeRaw(trezor.Type(req), data, results...)
}

// passphraseAckOnDevice is a PassphraseAck with on_device (field 3) set, which
// the vendored protocol definitions predate: it has a device that can take the
// passphrase on its own screen ask for it there (firmware 2.3 and later).
var passphraseAckOnDevice = []byte{0x18, 0x01}

// trezorExchangeRaw is trezorExchange for a message already encoded as data,
// of the given type.
//
// A PIN or passphrase the device asks for along the way stops the exchange
// with ErrTrezorPINNeeded or ErrTrezorPassphraseNeeded, for opening the wallet
// again with it, unless the device can take the passphrase itself.
func (w *trezorDriver) trezorExchangeRaw(kind uint16, data []byte, results ...proto.Message) (int, error) {
	// Construct the original message payload to chunk up
	payload := make([]byte, 8+len(data))
	copy(payload, []byte{0x23, 0x23})
	binary.BigEndian.PutUint16(payload[2:], kind)
	binary.BigEndian.PutUint32(payload[4:], uint32(len(data)))
	copy(payload[8:], data)

	// Stream all the chunks to the device
	chunk := make([]byte, 64)
	chunk[0] = 0x3f // Report ID magic number

	for len(payload) > 0 {
		// Construct the new message to stream, padding with zeroes if needed
		if len(payload) > 63 {
			copy(chunk[1:], payload[:63])
			payload = payload[63:]
		} else {
			copy(chunk[1:], payload)
			copy(chunk[1+len(payload):], make([]byte, 63-len(payload)))
			payload = nil
		}
		// Send over to the device
		w.log.Trace("Data chunk sent to the Trezor", "chunk", hexutil.Bytes(chunk))
		if _, err := w.device.Write(chunk); err != nil {
			return 0, err
		}
	}
	// Stream the reply back from the wallet in 64 byte chunks
	var reply []byte
	for {
		// Read the next chunk from the Trezor wallet
		if _, err := io.ReadFull(w.device, chunk); err != nil {
			return 0, err
		}
		w.log.Trace("Data chunk received from the Trezor", "chunk", hexutil.Bytes(chunk))

		// Make sure the transport header matches
		if chunk[0] != 0x3f || (len(reply) == 0 && (chunk[1] != 0x23 || chunk[2] != 0x23)) {
			return 0, errTrezorReplyInvalidHeader
		}
		// If it's the first chunk, retrieve the reply message type and total message length
		var payload []byte

		if len(reply) == 0 {
			kind = binary.BigEndian.Uint16(chunk[3:5])
			reply = make([]byte, 0, int(binary.BigEndian.Uint32(chunk[5:9])))
			payload = chunk[9:]
		} else {
			payload = chunk[1:]
		}
		// Append to the reply and stop when filled up
		if left := cap(reply) - len(reply); left > len(payload) {
			reply = append(reply, payload...)
		} else {
			reply = append(reply, payload[:left]...)
			break
		}
	}
	// Try to parse the reply into the requested reply message
	if kind == uint16(trezor.MessageType_MessageType_Failure) {
		// Trezor returned a failure, extract and return the message
		failure := new(trezor.Failure)
		if err := proto.Unmarshal(reply, failure); err != nil {
			return 0, err
		}
		switch failure.GetCode() {
		case trezor.Failure_Failure_ActionCancelled, trezor.Failure_Failure_PinCancelled:
			return 0, ErrTrezorDenied
		case trezor.Failure_Failure_PinInvalid:
			return 0, ErrTrezorPINInvalid
		}
		return 0, errors.New("trezor: " + failure.GetMessage())
	}
	if kind == uint16(trezor.MessageType_MessageType_ButtonRequest) {
		// Trezor is waiting for user confirmation, ack and wait for the next message
		return w.trezorExchange(&trezor.ButtonAck{}, results...)
	}
	// A PIN or passphrase asked for, unless it's the reply wanted
	wanted := func(kind trezor.MessageType) bool {
		for _, res := range results {
			if trezor.Type(res) == uint16(kind) {
				return true
			}
		}
		return false
	}
	if kind == uint16(trezor.MessageType_MessageType_PinMatrixRequest) && !wanted(trezor.MessageType_MessageType_PinMatrixRequest) {
		w.pinwait = true
		return 0, ErrTrezorPINNeeded
	}
	if kind == uint16(trezor.MessageType_MessageType_PassphraseRequest) && !wanted(trezor.MessageType_MessageType_PassphraseRequest) {
		request := new(trezor.PassphraseRequest)
		if err := proto.Unmarshal(reply, request); err != nil {
			return 0, err
		}
		switch {
		case request.GetOnDevice():
			// Firmware 2.0 to 2.2 has the passphrase entered on the device on
			// its own, and waits for an empty ack
			return w.trezorExchange(&trezor.PassphraseAck{}, results...)
		case w.model != "" && w.model != "1":
			// Every model since the One can take it on its screen
			return w.trezorExchangeRaw(uint16(trezor.MessageType_MessageType_PassphraseAck), passphraseAckOnDevice, results...)
		}
		w.passphrasewait = true
		return 0, ErrTrezorPassphraseNeeded
	}
	for i, res := range results {
		if trezor.Type(res) == kind {
			return i, proto.Unmarshal(reply, res)
		}
	}
	expected := make([]string, len(results))
	for i, res := range results {
		expected[i] = trezor.Name(trezor.Type(res))
	}
	return 0, fmt.Errorf("trezor: expected reply types %s, got %s", expected, trezor.Name(kind))
}
