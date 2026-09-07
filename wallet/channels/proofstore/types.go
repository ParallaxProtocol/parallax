package proofstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/registry"
)

// U256 is a non-negative big integer that marshals to a decimal string, per
// the wire convention (Part 2 §4): JSON numbers lose precision past 2^53.
// Unmarshalling enforces the 256-bit width: a wider value cannot be a
// uint256, and the EIP-712 encoder packs into a 32-byte word (FillBytes
// panics past it).
type U256 struct {
	*big.Int
}

func NewU256(x *big.Int) U256 {
	if x == nil {
		x = new(big.Int)
	}
	return U256{new(big.Int).Set(x)}
}

func (u U256) MarshalJSON() ([]byte, error) {
	if u.Int == nil {
		return []byte(`"0"`), nil
	}
	if u.Sign() < 0 {
		return nil, errors.New("proofstore: negative U256")
	}
	return json.Marshal(u.String())
}

func (u *U256) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	x, ok := new(big.Int).SetString(s, 10)
	if !ok || x.Sign() < 0 || x.BitLen() > 256 {
		return fmt.Errorf("proofstore: invalid U256 %q", s)
	}
	u.Int = x
	return nil
}

// BigInt returns the wrapped value, never nil.
func (u U256) BigInt() *big.Int {
	if u.Int == nil {
		return new(big.Int)
	}
	return u.Int
}

// Role identifies which on-chain participant this wallet is in a channel.
type Role string

const (
	RoleA Role = "A" // opener
	RoleB Role = "B"
)

// ChannelKey uniquely identifies a channel across coexisting registries and
// chains. The raw on-chain channelId alone is ambiguous when multiple
// registry deployments are configured (Part 3 §11).
type ChannelKey struct {
	ChainID   string       // decimal
	Registry  util.Address //
	ChannelID uint64       // registry ids are a monotonic counter; 2^64 is unreachable
}

func (k ChannelKey) String() string {
	return fmt.Sprintf("%s:%s:%d", k.ChainID, k.Registry.Hex(), k.ChannelID)
}

// Domain returns the channel's EIP-712 signing domain. Every digest
// (payment state, withdraw, cooperative close) binds to it, and every
// package computing one goes through here rather than assembling the
// domain from parts.
func (k ChannelKey) Domain() (registry.Domain, error) {
	chainID, ok := new(big.Int).SetString(k.ChainID, 10)
	if !ok {
		return registry.Domain{}, fmt.Errorf("proofstore: invalid chain id %q", k.ChainID)
	}
	return registry.Domain{ChainID: chainID, Registry: k.Registry}, nil
}

// Status is the watcher-owned view of the channel's on-chain state,
// recomputed from canonical logs (Part 3 §7).
type Status string

const (
	StatusOpen    Status = "open"
	StatusClosing Status = "closing"
	StatusSettled Status = "settled"
)

// ChannelMeta is the per-channel metadata record (Part 3 §4.1). Poisoned and
// FrozenUntilBlock are persisted so both survive restarts (Part 3 §5).
type ChannelMeta struct {
	Key              ChannelKey   `json:"key"`
	Role             Role         `json:"role"`
	Status           Status       `json:"status"`
	PeerNpub         string       `json:"peerNpub"` // 64-char x-only hex
	PeerAddress      util.Address `json:"peerAddress"`
	ChallengePeriod  uint32       `json:"challengePeriodBlocks"`
	OpenedAtBlock    uint64       `json:"openedAtBlock"`
	FrozenUntilBlock uint64       `json:"frozenUntilBlock"` // coop-close freeze; 0 = unfrozen
	Poisoned         bool         `json:"poisoned"`

	// PendingClose is the outstanding cooperative-close negotiation, kept so
	// a restart can neither forget the freeze nor re-sign different
	// balances while a signed close is live (Part 1 §7.4, Part 4 R5).
	PendingClose *PendingCoopClose `json:"pendingClose,omitempty"`

	// PendingWithdraw is the outstanding withdraw negotiation this wallet
	// proposed (Part 2 §6.10); needed to verify the countersign and to
	// assemble the on-chain submission after a restart.
	PendingWithdraw *PendingWithdraw `json:"pendingWithdraw,omitempty"`

	// PeerPendingWithdraw is the peer-proposed withdraw this wallet
	// countersigned (Part 2 §6.10, responder side). Until it expires or the
	// confirmed on-chain figures catch up, the peer holds a submittable
	// dual-signed voucher, so the entitlement it spends must be accounted
	// as already withdrawn — otherwise pay-then-withdraw double-spends it.
	PeerPendingWithdraw *PendingWithdraw `json:"peerPendingWithdraw,omitempty"`
}

// PendingWithdraw records a proposed cooperative withdraw until submission
// or expiry.
type PendingWithdraw struct {
	Participant    util.Address `json:"participant"`
	TotalWithdrawn U256         `json:"totalWithdrawn"`
	ExpiryBlock    uint64       `json:"expiryBlock"`
	MySig          []byte       `json:"mySig,omitempty"`
	PeerSig        []byte       `json:"peerSig,omitempty"`
}

// PendingCoopClose records a signed cooperative close from proposal until
// on-chain settle or expiry.
type PendingCoopClose struct {
	BalanceA    U256   `json:"balanceA"`
	BalanceB    U256   `json:"balanceB"`
	ExpiryBlock uint64 `json:"expiryBlock"`
	MySig       []byte `json:"mySig,omitempty"`
	PeerSig     []byte `json:"peerSig,omitempty"`
}

// SignedState is the canonical off-chain state object (Part 2 §5). A state
// is complete when both signatures are present; a proposal carries exactly
// one.
type SignedState struct {
	Key             ChannelKey `json:"key"`
	Seq             uint64     `json:"seq"`
	TransferredAtoB U256       `json:"transferredAtoB"`
	TransferredBtoA U256       `json:"transferredBtoA"`
	LocksRoot       util.Hash  `json:"locksRoot"`
	LockedAmount    U256       `json:"lockedAmount"`
	SigA            []byte     `json:"sigA,omitempty"` // 65-byte (r,s,v), participantA
	SigB            []byte     `json:"sigB,omitempty"`
}

// Digest returns the EIP-712 digest for this state, computed by the same
// mirror that is differentially tested against the contract. Two states are
// "the same payload" iff their digests are equal.
func (s *SignedState) Digest() (util.Hash, error) {
	d, err := s.Key.Domain()
	if err != nil {
		return util.Hash{}, err
	}
	return d.HashBalanceProof(registry.BalanceProof{
		ChannelID:       new(big.Int).SetUint64(s.Key.ChannelID),
		Seq:             s.Seq,
		TransferredAtoB: s.TransferredAtoB.BigInt(),
		TransferredBtoA: s.TransferredBtoA.BigInt(),
		LocksRoot:       s.LocksRoot,
		LockedAmount:    s.LockedAmount.BigInt(),
	}), nil
}

// ContractProof renders the state as the contract's BalanceProof argument
// (startClose/challenge submissions).
func (s *SignedState) ContractProof() registry.ParallaxChannelRegistryBalanceProof {
	return registry.ParallaxChannelRegistryBalanceProof{
		ChannelId:       new(big.Int).SetUint64(s.Key.ChannelID),
		Seq:             s.Seq,
		TransferredAtoB: s.TransferredAtoB.BigInt(),
		TransferredBtoA: s.TransferredBtoA.BigInt(),
		LocksRoot:       s.LocksRoot,
		LockedAmount:    s.LockedAmount.BigInt(),
	}
}

// Complete reports whether both signatures are present.
func (s *SignedState) Complete() bool {
	return len(s.SigA) == 65 && len(s.SigB) == 65
}

// SigOf returns the signature slot for the given role.
func (s *SignedState) SigOf(r Role) []byte {
	if r == RoleA {
		return s.SigA
	}
	return s.SigB
}

// Deposits is the confirmed on-chain funding view used for balance
// sufficiency (Part 3 §8): only ≥3-conf figures, plus the scan watermark.
type Deposits struct {
	DepositA         U256   `json:"depositA"`
	DepositB         U256   `json:"depositB"`
	WithdrawnA       U256   `json:"withdrawnA"`
	WithdrawnB       U256   `json:"withdrawnB"`
	LastScannedBlock uint64 `json:"lastScannedBlock"`
}

// WithdrawnOf returns the confirmed cumulative withdrawals for a role.
func (d Deposits) WithdrawnOf(r Role) U256 {
	if r == RoleA {
		return d.WithdrawnA
	}
	return d.WithdrawnB
}

// Invoice is the merchant-mode invoice record (Part 2 §6.1).
type Invoice struct {
	ID        string `json:"invoiceId"` // 16-byte hex
	AmountWei U256   `json:"amount"`
	Memo      string `json:"memo,omitempty"`
	ExpiresAt int64  `json:"expiresAt"` // unix
	ChannelID uint64 `json:"channelId,omitempty"`
	// Registry and ChainID qualify a nonzero ChannelID pin: the bare id is
	// ambiguous across coexisting registries, which each number channels
	// from 1. Zero values (records predating the qualifier) leave the pin
	// enforced by bare id alone.
	Registry util.Address `json:"registry,omitzero"`
	ChainID  string       `json:"chainId,omitempty"`
	Paid     bool         `json:"paid"`
	PaidBy   *ChannelKey  `json:"paidBy,omitempty"`
	PaidSeq  uint64       `json:"paidSeq,omitempty"`
	Merchant util.Address `json:"evmAddress"`
}

// PinMatches reports whether the invoice's channel pin admits key. An
// unpinned invoice (ChannelID 0) admits any channel.
func (inv Invoice) PinMatches(key ChannelKey) bool {
	return PinMatches(inv.ChannelID, inv.Registry, inv.ChainID, key)
}

// PinMatches is the one definition of a channel pin: a bare id qualified
// by an optional registry and chain. Zero qualifiers (records or wire
// messages predating them) fall back to the bare id, and id 0 means
// unpinned. Both payer and merchant resolve pins through it, so the two
// sides cannot disagree on which channel an invoice is payable on.
func PinMatches(channelID uint64, registry util.Address, chainID string, key ChannelKey) bool {
	if channelID == 0 {
		return true
	}
	return channelID == key.ChannelID &&
		(registry == (util.Address{}) || registry == key.Registry) &&
		(chainID == "" || chainID == key.ChainID)
}

// Delegation is a tower-mode record: the max-seq complete state a delegator
// has entrusted for watch-and-challenge (Part 2 §6.6).
type Delegation struct {
	State          SignedState `json:"state"`
	DelegatorNpub  string      `json:"delegatorNpub"`
	ReceivedAtUnix int64       `json:"receivedAt"`
}
