// Package qrenc implements the offline QR codec (Part 2 §11):
// "PLXC1:" + base45(canonical_cbor(envelope)), CBOR per RFC 8949 §4.2.1
// deterministic encoding, Base45 per RFC 9285. The envelope schema is a
// small fixed map with integer keys, so both codecs are implemented here
// directly — determinism is a golden-vector requirement (same struct MUST
// encode byte-identically on every run and every implementation), not a
// serialization convenience.
package qrenc

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ParallaxProtocol/parallax/v2/util"
)

// Prefix marks a v1 channel QR payload.
const Prefix = "PLXC1:"

// Envelope types (Part 2 §11.1 key 0).
const (
	TypeInvoice           = 1
	TypeProposal          = 2
	TypeAck               = 3
	TypeCoopCloseProposal = 4
	TypeCoopCloseAck      = 5
)

// CBOR map keys (Part 2 §11.1).
const (
	keyType      = 0
	keyVersion   = 1
	keyRegistry  = 2
	keyChainID   = 3
	keyChannelID = 4
	keySeq       = 5
	keyTAB       = 6
	keyTBA       = 7
	keySig1      = 8
	keySig2      = 9
	keyAmount    = 10
	keyInvoiceID = 11
	keyExpiry    = 12
	keyBalA      = 13
	keyBalB      = 14
	keyEVMAddr   = 15
	keyMemo      = 16
)

// Envelope is the offline payload. Which fields are present depends on Type;
// locksRoot/lockedAmount are unrepresentable offline by design (implicitly
// zero in v1).
type Envelope struct {
	Type      uint8
	Registry  util.Address
	ChainID   uint64
	ChannelID uint64
	Seq       uint64       // types 2, 3
	TAB, TBA  *big.Int     // types 2, 3 (cumulative wei)
	Sig1      []byte       // 65 bytes: proposer / closer side
	Sig2      []byte       // 65 bytes: ack types only
	Amount    *big.Int     // type 1
	InvoiceID []byte       // 16 bytes: types 1, 2
	Expiry    uint64       // type 1: unix; types 4, 5: block number
	BalA      *big.Int     // types 4, 5
	BalB      *big.Int     // types 4, 5
	EVMAddr   util.Address // type 1
	Memo      string       // type 1, optional, <= 64 bytes
}

// Encode renders the QR string.
func Encode(env Envelope) (string, error) {
	raw, err := encodeCBOR(env)
	if err != nil {
		return "", err
	}
	return Prefix + base45Encode(raw), nil
}

// Decode parses and validates a QR string.
func Decode(s string) (Envelope, error) {
	rest, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return Envelope{}, errors.New("qrenc: missing PLXC1 prefix")
	}
	raw, err := base45Decode(rest)
	if err != nil {
		return Envelope{}, err
	}
	return decodeCBOR(raw)
}

// ------------------------------------------------------------ CBOR encode

type field struct {
	key  int
	data []byte // encoded value
}

func encodeCBOR(env Envelope) ([]byte, error) {
	if env.Type < TypeInvoice || env.Type > TypeCoopCloseAck {
		return nil, fmt.Errorf("qrenc: bad type %d", env.Type)
	}
	if len(env.Memo) > 64 {
		return nil, errors.New("qrenc: memo exceeds 64 bytes")
	}

	var fields []field
	add := func(key int, data []byte) { fields = append(fields, field{key, data}) }

	add(keyType, encUint(uint64(env.Type)))
	add(keyVersion, encUint(1))
	add(keyRegistry, encBytes(env.Registry[:]))
	add(keyChainID, encUint(env.ChainID))
	add(keyChannelID, encUint(env.ChannelID))

	switch env.Type {
	case TypeInvoice:
		if env.Amount == nil || len(env.InvoiceID) != 16 {
			return nil, errors.New("qrenc: invoice needs amount and 16-byte invoice id")
		}
		add(keyAmount, encBig(env.Amount))
		add(keyInvoiceID, encBytes(env.InvoiceID))
		add(keyExpiry, encUint(env.Expiry))
		add(keyEVMAddr, encBytes(env.EVMAddr[:]))
		if env.Memo != "" {
			add(keyMemo, encText(env.Memo))
		}
	case TypeProposal, TypeAck:
		if env.TAB == nil || env.TBA == nil || len(env.Sig1) != 65 {
			return nil, errors.New("qrenc: state types need tAB, tBA, and sig1")
		}
		add(keySeq, encUint(env.Seq))
		add(keyTAB, encBig(env.TAB))
		add(keyTBA, encBig(env.TBA))
		add(keySig1, encBytes(env.Sig1))
		if env.Type == TypeAck {
			if len(env.Sig2) != 65 {
				return nil, errors.New("qrenc: ack needs sig2")
			}
			add(keySig2, encBytes(env.Sig2))
		}
		if len(env.InvoiceID) == 16 && env.Type == TypeProposal {
			add(keyInvoiceID, encBytes(env.InvoiceID))
		}
	case TypeCoopCloseProposal, TypeCoopCloseAck:
		if env.BalA == nil || env.BalB == nil || len(env.Sig1) != 65 {
			return nil, errors.New("qrenc: close types need balances and sig1")
		}
		add(keyExpiry, encUint(env.Expiry))
		add(keyBalA, encBig(env.BalA))
		add(keyBalB, encBig(env.BalB))
		add(keySig1, encBytes(env.Sig1))
		if env.Type == TypeCoopCloseAck {
			if len(env.Sig2) != 65 {
				return nil, errors.New("qrenc: close ack needs sig2")
			}
			add(keySig2, encBytes(env.Sig2))
		}
	}

	// RFC 8949 §4.2.1: map keys sorted by their encoded bytes — for small
	// unsigned ints, ascending numeric order.
	sort.Slice(fields, func(i, j int) bool { return fields[i].key < fields[j].key })

	var out bytes.Buffer
	writeHead(&out, 5, uint64(len(fields))) // major 5: map
	for _, f := range fields {
		out.Write(encUint(uint64(f.key)))
		out.Write(f.data)
	}
	return out.Bytes(), nil
}

// writeHead writes a major-type head with minimal-length argument encoding.
func writeHead(out *bytes.Buffer, major byte, arg uint64) {
	mt := major << 5
	switch {
	case arg < 24:
		out.WriteByte(mt | byte(arg))
	case arg <= 0xff:
		out.WriteByte(mt | 24)
		out.WriteByte(byte(arg))
	case arg <= 0xffff:
		out.WriteByte(mt | 25)
		out.Write([]byte{byte(arg >> 8), byte(arg)})
	case arg <= 0xffffffff:
		out.WriteByte(mt | 26)
		out.Write([]byte{byte(arg >> 24), byte(arg >> 16), byte(arg >> 8), byte(arg)})
	default:
		out.WriteByte(mt | 27)
		out.Write([]byte{
			byte(arg >> 56), byte(arg >> 48), byte(arg >> 40), byte(arg >> 32),
			byte(arg >> 24), byte(arg >> 16), byte(arg >> 8), byte(arg),
		})
	}
}

func encUint(v uint64) []byte {
	var out bytes.Buffer
	writeHead(&out, 0, v)
	return out.Bytes()
}

func encBytes(b []byte) []byte {
	var out bytes.Buffer
	writeHead(&out, 2, uint64(len(b)))
	out.Write(b)
	return out.Bytes()
}

func encText(s string) []byte {
	var out bytes.Buffer
	writeHead(&out, 3, uint64(len(s)))
	out.WriteString(s)
	return out.Bytes()
}

// encBig encodes wei: plain uint when it fits uint64, else tag 2 bignum
// (big-endian, no leading zeros) per Part 2 §11.1.
func encBig(v *big.Int) []byte {
	if v.Sign() < 0 {
		return nil // unreachable: amounts are unsigned
	}
	if v.IsUint64() {
		return encUint(v.Uint64())
	}
	var out bytes.Buffer
	out.WriteByte(0xc2) // tag 2
	out.Write(encBytes(v.Bytes()))
	return out.Bytes()
}

// ------------------------------------------------------------ CBOR decode

type reader struct {
	buf []byte
	pos int
}

func (r *reader) byte() (byte, error) {
	if r.pos >= len(r.buf) {
		return 0, errors.New("qrenc: truncated cbor")
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *reader) take(n uint64) ([]byte, error) {
	if uint64(len(r.buf)-r.pos) < n {
		return nil, errors.New("qrenc: truncated cbor")
	}
	b := r.buf[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return b, nil
}

// head reads a major type and its argument, enforcing minimal-length
// encoding (canonicality).
func (r *reader) head() (major byte, arg uint64, err error) {
	b, err := r.byte()
	if err != nil {
		return 0, 0, err
	}
	major = b >> 5
	info := b & 0x1f
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info > 27:
		return 0, 0, fmt.Errorf("qrenc: unsupported additional info %d", info)
	}
	n := 1 << (info - 24)
	raw, err := r.take(uint64(n))
	if err != nil {
		return 0, 0, err
	}
	for _, c := range raw {
		arg = arg<<8 | uint64(c)
	}
	min := uint64(24)
	if n > 1 {
		min = 1 << ((n / 2) * 8)
	}
	if arg < min {
		return 0, 0, errors.New("qrenc: non-minimal length encoding")
	}
	return major, arg, nil
}

func (r *reader) uint() (uint64, error) {
	major, arg, err := r.head()
	if err != nil {
		return 0, err
	}
	if major != 0 {
		return 0, fmt.Errorf("qrenc: expected uint, got major %d", major)
	}
	return arg, nil
}

func (r *reader) big() (*big.Int, error) {
	if r.pos < len(r.buf) && r.buf[r.pos] == 0xc2 {
		r.pos++
		major, n, err := r.head()
		if err != nil {
			return nil, err
		}
		if major != 2 {
			return nil, errors.New("qrenc: bignum tag without byte string")
		}
		raw, err := r.take(n)
		if err != nil {
			return nil, err
		}
		if len(raw) == 0 || raw[0] == 0 {
			return nil, errors.New("qrenc: non-canonical bignum")
		}
		// Every amount is a uint256 on the wire and in the digest encoder,
		// which packs it into a 32-byte word; a longer value must fail here,
		// not there.
		if len(raw) > 32 {
			return nil, errors.New("qrenc: bignum exceeds 256 bits")
		}
		v := new(big.Int).SetBytes(raw)
		if v.IsUint64() {
			return nil, errors.New("qrenc: bignum used for uint64-range value")
		}
		return v, nil
	}
	v, err := r.uint()
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetUint64(v), nil
}

func (r *reader) bytesN(want int) ([]byte, error) {
	major, n, err := r.head()
	if err != nil {
		return nil, err
	}
	if major != 2 {
		return nil, fmt.Errorf("qrenc: expected bytes, got major %d", major)
	}
	if want >= 0 && n != uint64(want) {
		return nil, fmt.Errorf("qrenc: expected %d bytes, got %d", want, n)
	}
	raw, err := r.take(n)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, raw)
	return out, nil
}

func decodeCBOR(raw []byte) (Envelope, error) {
	var env Envelope
	r := &reader{buf: raw}
	major, count, err := r.head()
	if err != nil {
		return env, err
	}
	if major != 5 {
		return env, errors.New("qrenc: not a cbor map")
	}

	prevKey := -1
	for i := uint64(0); i < count; i++ {
		key, err := r.uint()
		if err != nil {
			return env, err
		}
		if int(key) <= prevKey {
			return env, errors.New("qrenc: map keys not in canonical order")
		}
		prevKey = int(key)

		switch key {
		case keyType:
			v, err := r.uint()
			if err != nil {
				return env, err
			}
			env.Type = uint8(v)
		case keyVersion:
			v, err := r.uint()
			if err != nil {
				return env, err
			}
			if v != 1 {
				return env, fmt.Errorf("qrenc: unsupported version %d", v)
			}
		case keyRegistry:
			b, err := r.bytesN(20)
			if err != nil {
				return env, err
			}
			env.Registry = util.BytesToAddress(b)
		case keyChainID:
			if env.ChainID, err = r.uint(); err != nil {
				return env, err
			}
		case keyChannelID:
			if env.ChannelID, err = r.uint(); err != nil {
				return env, err
			}
		case keySeq:
			if env.Seq, err = r.uint(); err != nil {
				return env, err
			}
		case keyTAB:
			if env.TAB, err = r.big(); err != nil {
				return env, err
			}
		case keyTBA:
			if env.TBA, err = r.big(); err != nil {
				return env, err
			}
		case keySig1:
			if env.Sig1, err = r.bytesN(65); err != nil {
				return env, err
			}
		case keySig2:
			if env.Sig2, err = r.bytesN(65); err != nil {
				return env, err
			}
		case keyAmount:
			if env.Amount, err = r.big(); err != nil {
				return env, err
			}
		case keyInvoiceID:
			if env.InvoiceID, err = r.bytesN(16); err != nil {
				return env, err
			}
		case keyExpiry:
			if env.Expiry, err = r.uint(); err != nil {
				return env, err
			}
		case keyBalA:
			if env.BalA, err = r.big(); err != nil {
				return env, err
			}
		case keyBalB:
			if env.BalB, err = r.big(); err != nil {
				return env, err
			}
		case keyEVMAddr:
			b, err := r.bytesN(20)
			if err != nil {
				return env, err
			}
			env.EVMAddr = util.BytesToAddress(b)
		case keyMemo:
			major, n, err := r.head()
			if err != nil {
				return env, err
			}
			if major != 3 || n > 64 {
				return env, errors.New("qrenc: bad memo")
			}
			raw, err := r.take(n)
			if err != nil {
				return env, err
			}
			env.Memo = string(raw)
		default:
			return env, fmt.Errorf("qrenc: unknown key %d", key)
		}
	}
	if r.pos != len(r.buf) {
		return env, errors.New("qrenc: trailing bytes")
	}

	// Re-encode and byte-compare: only canonical encodings of valid
	// envelopes are accepted.
	canonical, err := encodeCBOR(env)
	if err != nil {
		return env, err
	}
	if !bytes.Equal(canonical, raw) {
		return env, errors.New("qrenc: non-canonical encoding")
	}
	return env, nil
}

// ------------------------------------------------------------- Base45

const base45Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

var base45Rev = func() [256]int8 {
	var rev [256]int8
	for i := range rev {
		rev[i] = -1
	}
	for i, c := range base45Alphabet {
		rev[c] = int8(i)
	}
	return rev
}()

func base45Encode(data []byte) string {
	var out strings.Builder
	for i := 0; i+1 < len(data); i += 2 {
		v := uint32(data[i])<<8 | uint32(data[i+1])
		out.WriteByte(base45Alphabet[v%45])
		out.WriteByte(base45Alphabet[(v/45)%45])
		out.WriteByte(base45Alphabet[v/(45*45)])
	}
	if len(data)%2 == 1 {
		v := uint32(data[len(data)-1])
		out.WriteByte(base45Alphabet[v%45])
		out.WriteByte(base45Alphabet[v/45])
	}
	return out.String()
}

func base45Decode(s string) ([]byte, error) {
	switch len(s) % 3 {
	case 1:
		return nil, errors.New("qrenc: bad base45 length")
	}
	out := make([]byte, 0, len(s)/3*2+1)
	for i := 0; i < len(s); {
		c0 := base45Rev[s[i]]
		c1 := int8(-1)
		if i+1 < len(s) {
			c1 = base45Rev[s[i+1]]
		}
		if c0 < 0 || c1 < 0 {
			return nil, errors.New("qrenc: bad base45 character")
		}
		if i+2 < len(s) || (len(s)-i) == 3 {
			c2 := base45Rev[s[i+2]]
			if c2 < 0 {
				return nil, errors.New("qrenc: bad base45 character")
			}
			v := uint32(c0) + 45*uint32(c1) + 45*45*uint32(c2)
			if v > 0xffff {
				return nil, errors.New("qrenc: base45 triple out of range")
			}
			out = append(out, byte(v>>8), byte(v))
			i += 3
		} else {
			v := uint32(c0) + 45*uint32(c1)
			if v > 0xff {
				return nil, errors.New("qrenc: base45 pair out of range")
			}
			out = append(out, byte(v))
			i += 2
		}
	}
	return out, nil
}
