package qrenc

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/util"
)

func sig(fill byte) []byte { return bytes.Repeat([]byte{fill}, 65) }

func wei(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(s)
	}
	return v
}

func sampleProposal() Envelope {
	return Envelope{
		Type:      TypeProposal,
		Registry:  util.HexToAddress("0x00000000000000000000000000000000000021ff"),
		ChainID:   2110,
		ChannelID: 17,
		Seq:       42,
		TAB:       wei("125000000000000000000"), // > uint64: bignum path
		TBA:       wei("40000000000000000000"),
		Sig1:      sig(0xaa),
		InvoiceID: bytes.Repeat([]byte{0x11}, 16),
	}
}

func samples() []Envelope {
	return []Envelope{
		{
			Type:      TypeInvoice,
			Registry:  util.HexToAddress("0x00000000000000000000000000000000000021ff"),
			ChainID:   2110,
			ChannelID: 17,
			Amount:    wei("1500000000000000000"),
			InvoiceID: bytes.Repeat([]byte{0x42}, 16),
			Expiry:    1_766_000_000,
			EVMAddr:   util.HexToAddress("0xaa00000000000000000000000000000000000aa0"),
			Memo:      "espresso",
		},
		sampleProposal(),
		func() Envelope {
			e := sampleProposal()
			e.Type = TypeAck
			e.InvoiceID = nil
			e.Sig2 = sig(0xbb)
			return e
		}(),
		{
			Type:      TypeCoopCloseProposal,
			Registry:  util.HexToAddress("0x00000000000000000000000000000000000021ff"),
			ChainID:   2110,
			ChannelID: 17,
			Expiry:    123456,
			BalA:      wei("8500000000000000000"),
			BalB:      wei("6500000000000000000"),
			Sig1:      sig(0xcc),
		},
		{
			Type:      TypeCoopCloseAck,
			Registry:  util.HexToAddress("0x00000000000000000000000000000000000021ff"),
			ChainID:   2110,
			ChannelID: 17,
			Expiry:    123456,
			BalA:      wei("8500000000000000000"),
			BalB:      wei("6500000000000000000"),
			Sig1:      sig(0xcc),
			Sig2:      sig(0xdd),
		},
	}
}

func TestRoundtripAllTypes(t *testing.T) {
	for _, env := range samples() {
		s, err := Encode(env)
		if err != nil {
			t.Fatalf("type %d: %v", env.Type, err)
		}
		got, err := Decode(s)
		if err != nil {
			t.Fatalf("type %d: decode: %v", env.Type, err)
		}
		s2, err := Encode(got)
		if err != nil {
			t.Fatalf("type %d: re-encode: %v", env.Type, err)
		}
		if s != s2 {
			t.Fatalf("type %d: roundtrip not stable", env.Type)
		}
	}
}

func TestDeterminism(t *testing.T) {
	for i := 0; i < 50; i++ {
		a, _ := Encode(sampleProposal())
		b, _ := Encode(sampleProposal())
		if a != b {
			t.Fatal("encoding not deterministic")
		}
	}
}

// TestSizeAndCharset pins the Part 2 §11.1 envelope budget (a proposal MUST
// stay comfortably inside one phone-scannable QR: <=260 CBOR bytes, <=420
// Base45 chars) and the QR alphanumeric charset.
func TestSizeAndCharset(t *testing.T) {
	raw, err := encodeCBOR(sampleProposal())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 100 || len(raw) > 260 {
		t.Fatalf("proposal cbor size %d outside budget", len(raw))
	}
	s, _ := Encode(sampleProposal())
	body := strings.TrimPrefix(s, Prefix)
	if len(body) < 150 || len(body) > 420 {
		t.Fatalf("base45 size %d outside budget", len(body))
	}
	for _, c := range s {
		if !strings.ContainsRune(base45Alphabet+":LXCP", c) {
			t.Fatalf("character %q outside QR alphanumeric set", c)
		}
	}
}

// Golden vectors: pinned outputs — any codec change that alters bytes is a
// compatibility break and must fail here.
func TestGoldenVectors(t *testing.T) {
	small := Envelope{
		Type:      TypeProposal,
		Registry:  util.HexToAddress("0x00000000000000000000000000000000000021ff"),
		ChainID:   2110,
		ChannelID: 1,
		Seq:       1,
		TAB:       big.NewInt(1000), // uint64 path
		TBA:       big.NewInt(0),
		Sig1:      sig(0x01),
	}
	got, err := Encode(small)
	if err != nil {
		t.Fatal(err)
	}
	const want = "PLXC1:JGLIB0X50*RA000000000000000000000000X00XAWI73 $7 50$50D73:ET80037BW50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W50W5010"
	if got != want {
		t.Fatalf("golden vector changed:\n got  %s\n want %s", got, want)
	}
}

// RFC 9285 §4.3 / §4.4 examples.
func TestBase45RFCVectors(t *testing.T) {
	cases := []struct{ raw, enc string }{
		{"AB", "BB8"},
		{"Hello!!", "%69 VD92EX0"},
		{"base-45", "UJCLQE7W581"},
		{"ietf!", "QED8WEX0"},
	}
	for _, tc := range cases {
		if got := base45Encode([]byte(tc.raw)); got != tc.enc {
			t.Fatalf("encode %q: got %q want %q", tc.raw, got, tc.enc)
		}
		dec, err := base45Decode(tc.enc)
		if err != nil || string(dec) != tc.raw {
			t.Fatalf("decode %q: got %q err %v", tc.enc, dec, err)
		}
	}
	// Invalid: triple decoding above 0xffff must be rejected (RFC 9285 §6).
	if _, err := base45Decode("GGW"); err == nil {
		t.Fatal("out-of-range triple accepted")
	}
	if _, err := base45Decode("A"); err == nil {
		t.Fatal("length 1 accepted")
	}
}

func TestDecodeRejections(t *testing.T) {
	valid, _ := Encode(sampleProposal())

	if _, err := Decode("NOPE" + valid); err == nil {
		t.Fatal("bad prefix accepted")
	}
	if _, err := Decode(Prefix + "abc"); err == nil {
		t.Fatal("lowercase (non-alphabet) accepted")
	}

	// Bit-flip anywhere in the payload must not decode to a *different*
	// valid envelope silently: either decode fails, or the canonical
	// re-encode check fails.
	raw, _ := encodeCBOR(sampleProposal())
	for i := 0; i < len(raw); i++ {
		mutated := append([]byte(nil), raw...)
		mutated[i] ^= 0x01
		env, err := decodeCBOR(mutated)
		if err != nil {
			continue
		}
		re, err := encodeCBOR(env)
		if err == nil && bytes.Equal(re, mutated) && bytes.Equal(re, raw) {
			t.Fatalf("byte %d: mutation invisible", i)
		}
	}

	// Non-canonical: padded length encoding of the map head must be
	// rejected (0xb8 0x09 spells "map, 9 entries" non-minimally).
	if _, err := decodeCBOR(append([]byte{0xb8, 0x09}, raw[1:]...)); err == nil {
		t.Fatal("non-minimal map head accepted")
	}

	// Missing required field: proposal without sig1.
	env := sampleProposal()
	env.Sig1 = nil
	if _, err := encodeCBOR(env); err == nil {
		t.Fatal("proposal without sig1 encoded")
	}
	env = sampleProposal()
	env.Memo = strings.Repeat("x", 65)
	env.Type = TypeInvoice
	if _, err := encodeCBOR(env); err == nil {
		t.Fatal("oversized memo encoded")
	}
}

// TestDecodeRejectsOversizedBignum: every amount is a uint256 on the wire
// and in the EIP-712 encoder, which packs it into a 32-byte word and panics
// on a wider value. A scanned envelope carrying a 33-byte bignum must fail
// to decode rather than reach the digest.
func TestDecodeRejectsOversizedBignum(t *testing.T) {
	env := sampleProposal()
	env.TAB = new(big.Int).Lsh(big.NewInt(1), 256) // 2^256: 33 bytes
	s, err := Encode(env)
	if err != nil {
		return // the encoder refusing it is equally acceptable
	}
	if _, err := Decode(s); err == nil {
		t.Fatal("envelope with a 257-bit amount decoded")
	}
	env.TAB = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)) // 2^256-1 fits
	s, err = Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(s)
	if err != nil {
		t.Fatalf("max uint256 rejected: %v", err)
	}
	if got.TAB.Cmp(env.TAB) != 0 {
		t.Fatalf("max uint256 roundtrip: got %s", got.TAB)
	}
}
