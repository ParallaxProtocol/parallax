// Package registry is the Go mirror of the ParallaxChannelRegistry contract:
// EIP-712 digests and settlement math, differentially tested against the
// contract's hash* and settlementPreview views (SPEC-003 §1, SPEC-005 A.3).
// The wallet signs and verifies exclusively through this package so that the
// off-chain and on-chain digest computations can never diverge silently.
package registry

import (
	"math/big"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/util"
)

// Domain constants fixed by SPEC-001 §5.
const (
	DomainName    = "ParallaxChannels"
	DomainVersion = "1"
)

var (
	eip712DomainTypeHash = crypto.Keccak256(
		[]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
	balanceProofTypeHash = crypto.Keccak256(
		[]byte("BalanceProof(uint256 channelId,uint64 seq,uint256 transferredAtoB,uint256 transferredBtoA,bytes32 locksRoot,uint256 lockedAmount)"))
	withdrawTypeHash = crypto.Keccak256(
		[]byte("Withdraw(uint256 channelId,address participant,uint256 totalWithdrawn,uint64 expiryBlock)"))
	cooperativeCloseTypeHash = crypto.Keccak256(
		[]byte("CooperativeClose(uint256 channelId,uint256 balanceA,uint256 balanceB,uint64 expiryBlock)"))
)

// Domain identifies one registry deployment on one chain. Every signature is
// bound to it; cross-chain and cross-registry replay is impossible by
// construction.
type Domain struct {
	ChainID  *big.Int
	Registry util.Address
}

// Separator returns the EIP-712 domain separator hash.
func (d Domain) Separator() util.Hash {
	return util.BytesToHash(crypto.Keccak256(
		eip712DomainTypeHash,
		crypto.Keccak256([]byte(DomainName)),
		crypto.Keccak256([]byte(DomainVersion)),
		encUint(d.ChainID),
		encAddress(d.Registry),
	))
}

// BalanceProof mirrors the contract struct. Cumulative transferred amounts
// over the channel lifetime; locks fields are reserved and MUST be zero in v1.
type BalanceProof struct {
	ChannelID       *big.Int
	Seq             uint64
	TransferredAtoB *big.Int
	TransferredBtoA *big.Int
	LocksRoot       util.Hash
	LockedAmount    *big.Int
}

// HashBalanceProof returns the EIP-712 digest both participants sign.
func (d Domain) HashBalanceProof(p BalanceProof) util.Hash {
	structHash := crypto.Keccak256(
		balanceProofTypeHash,
		encUint(p.ChannelID),
		encUint64(p.Seq),
		encUint(p.TransferredAtoB),
		encUint(p.TransferredBtoA),
		p.LocksRoot[:],
		encUint(p.LockedAmount),
	)
	return d.typedDigest(structHash)
}

// HashWithdraw returns the digest authorizing a cumulative withdrawal.
func (d Domain) HashWithdraw(channelID *big.Int, participant util.Address, totalWithdrawn *big.Int, expiryBlock uint64) util.Hash {
	structHash := crypto.Keccak256(
		withdrawTypeHash,
		encUint(channelID),
		encAddress(participant),
		encUint(totalWithdrawn),
		encUint64(expiryBlock),
	)
	return d.typedDigest(structHash)
}

// HashCooperativeClose returns the digest over explicit final balances.
func (d Domain) HashCooperativeClose(channelID, balanceA, balanceB *big.Int, expiryBlock uint64) util.Hash {
	structHash := crypto.Keccak256(
		cooperativeCloseTypeHash,
		encUint(channelID),
		encUint(balanceA),
		encUint(balanceB),
		encUint64(expiryBlock),
	)
	return d.typedDigest(structHash)
}

func (d Domain) typedDigest(structHash []byte) util.Hash {
	return util.BytesToHash(crypto.Keccak256([]byte("\x19\x01"), d.Separator().Bytes(), structHash))
}

// encUint ABI-encodes a uint256 into its 32-byte big-endian word. nil counts
// as zero. Values wider than 256 bits do not fit and FillBytes panics, so
// every decoder that admits a peer-supplied amount (proofstore.U256,
// protocol's parseWei, qrenc's bignum reader) bounds it before it can reach
// a digest.
func encUint(x *big.Int) []byte {
	var word [32]byte
	if x != nil {
		x.FillBytes(word[:])
	}
	return word[:]
}

func encUint64(x uint64) []byte {
	return encUint(new(big.Int).SetUint64(x))
}

// encAddress ABI-encodes an address left-padded to a 32-byte word.
func encAddress(a util.Address) []byte {
	var word [32]byte
	copy(word[12:], a[:])
	return word[:]
}
