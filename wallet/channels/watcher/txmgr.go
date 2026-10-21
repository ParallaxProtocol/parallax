package watcher

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind"
	"github.com/ParallaxProtocol/parallax/v2/util"
)

// TxBackend is the chain access the manager needs.
type TxBackend interface {
	bind.ContractBackend
	bind.DeployBackend // receipt lookups
}

// Fee-bump policy: resubmit an unmined transaction with a 25% higher gas
// price after bumpAfterBlocks, capped at maxBumps (the final price is
// ~9.3x the starting one — beyond that something other than fees is wrong
// and the alarm has long fired).
const (
	bumpAfterBlocks = 2
	bumpPercent     = 25
	maxBumps        = 10
)

// transferGas is the intrinsic gas of a plain value transfer (the nonce
// filler's whole cost).
const transferGas = 21000

// pendingTx is one tracked intent.
type pendingTx struct {
	build       func(*bind.TransactOpts) (*types.Transaction, error)
	nonce       uint64
	gasPrice    *big.Int
	txHashes    []util.Hash // every attempt, oldest first: ANY of them mining resolves the intent
	submittedAt uint64      // head at last (re)submission
	retryAt     uint64      // earliest head for the next bump after a failed send
	bumps       int
	deadline    uint64 // 0 = none; alarm fires as head approaches it
	noBump      bool   // synchronous Transact intent: the caller owns retries
	missingAt   uint64 // head a noBump broadcast was first seen absent from the pool (0 = present)
}

// nonceReader is the mined-nonce lookup Tick uses to spot intents whose
// nonce another transaction consumed. *client.Client and the simulated
// backend provide it; a backend without it skips that check and relies on
// the "nonce too low" resubmit path alone.
type nonceReader interface {
	NonceAt(ctx context.Context, account util.Address, blockNumber *big.Int) (uint64, error)
}

// TxManager tracks keyed transaction intents until they are mined,
// resubmitting with escalating fees (Part 3 §7: the challenge path is the
// one loss-capable failure, so it never fire-and-forgets).
type TxManager struct {
	backend TxBackend
	key     *ecdsa.PrivateKey
	from    util.Address
	chainID *big.Int

	// Alarm receives operator-grade alerts. Optional.
	Alarm func(format string, args ...any)

	mu      sync.Mutex
	pending map[string]*pendingTx

	// tickMu serializes Tick against itself: in tower mode the node's watch
	// loop and the tower's tick loop drive the same shared per-chain manager
	// from two goroutines, and the bump path mutates per-intent state
	// (gasPrice, bumps, txHashes) that only this lock guards.
	tickMu sync.Mutex

	// submitMu serializes nonce allocation-to-send across Submit calls:
	// PendingNonceAt alone lags behind a broadcast the pool has not yet
	// registered, and two intents allocated against that stale view would
	// pick the same nonce — one silently replacing the other. The live
	// pending intents are the reservation set, so an abandoned intent's
	// nonce is released rather than left as a permanent gap.
	submitMu sync.Mutex
}

func NewTxManager(backend TxBackend, key *ecdsa.PrivateKey, chainID *big.Int) *TxManager {
	return &TxManager{
		backend: backend,
		key:     key,
		from:    crypto.PubkeyToAddress(key.PublicKey),
		chainID: chainID,
		pending: make(map[string]*pendingTx),
	}
}

func (m *TxManager) alarm(format string, args ...any) {
	if m.Alarm != nil {
		m.Alarm(format, args...)
	}
}

// Pending reports whether an intent is being tracked.
func (m *TxManager) Pending(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.pending[id]
	return ok
}

// Done drops an intent whose effect was observed on-chain by other means
// (e.g. the counterparty's transaction achieved the same outcome).
func (m *TxManager) Done(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pending, id)
}

// Submit registers an intent and sends its first transaction. Idempotent
// while the intent is pending. deadline (0 = none) drives the near-deadline
// alarm; the caller stops caring via Done or a mined receipt.
func (m *TxManager) Submit(ctx context.Context, id string, head, deadline uint64,
	build func(*bind.TransactOpts) (*types.Transaction, error)) error {
	m.mu.Lock()
	if _, ok := m.pending[id]; ok {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	m.submitMu.Lock()
	defer m.submitMu.Unlock()

	nonce, err := m.allocateNonce(ctx)
	if err != nil {
		return err
	}
	gasPrice, err := m.backend.SuggestGasPrice(ctx)
	if err != nil {
		return err
	}
	p := &pendingTx{build: build, nonce: nonce, gasPrice: gasPrice, deadline: deadline}
	if _, err := m.send(ctx, id, p, head); err != nil {
		return err
	}
	m.mu.Lock()
	m.pending[id] = p
	m.mu.Unlock()
	return nil
}

// allocateNonce picks the next free nonce: the higher of the chain's pending
// view and the nonces reserved by live pending intents. The chain view wins
// after external transactions or mined history; the reservations win while a
// broadcast is still propagating. An intent dropped via Done releases its
// reservation, so a permanently lost broadcast never wedges later
// submissions behind an unfillable gap. Caller holds submitMu.
func (m *TxManager) allocateNonce(ctx context.Context) (uint64, error) {
	nonce, err := m.backend.PendingNonceAt(ctx, m.from)
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	for _, p := range m.pending {
		if p.nonce >= nonce {
			nonce = p.nonce + 1
		}
	}
	m.mu.Unlock()
	return nonce, nil
}

func (m *TxManager) send(ctx context.Context, id string, p *pendingTx, head uint64) (*types.Transaction, error) {
	auth, err := bind.NewKeyedTransactorWithChainID(m.key, m.chainID)
	if err != nil {
		return nil, err
	}
	auth.Context = ctx
	auth.Nonce = new(big.Int).SetUint64(p.nonce)
	auth.GasPrice = new(big.Int).Set(p.gasPrice)
	tx, err := p.build(auth)
	if err != nil {
		return nil, fmt.Errorf("tx %s: %w", id, err)
	}
	p.txHashes = append(p.txHashes, tx.Hash())
	p.submittedAt = head
	return tx, nil
}

// Transact runs one synchronous keyed transaction through the manager's
// nonce serialization and waits for it to mine. Everything submitting with
// the manager's key on its chain MUST allocate nonces here — bind's
// auto-nonce reads the chain's lagging pending view and silently replaces a
// challenge the manager just broadcast. The intent is tracked until mined so
// concurrent Submits never reuse its nonce, but it is never fee-bumped: the
// caller is waiting and owns retries.
func (m *TxManager) Transact(ctx context.Context, label string,
	build func(*bind.TransactOpts) (*types.Transaction, error)) (*types.Receipt, error) {
	m.submitMu.Lock()
	tx, id, err := func() (*types.Transaction, string, error) {
		defer m.submitMu.Unlock()
		nonce, err := m.allocateNonce(ctx)
		if err != nil {
			return nil, "", err
		}
		gasPrice, err := m.backend.SuggestGasPrice(ctx)
		if err != nil {
			return nil, "", err
		}
		id := fmt.Sprintf("%s:nonce-%d", label, nonce)
		p := &pendingTx{build: build, nonce: nonce, gasPrice: gasPrice, noBump: true}
		tx, err := m.send(ctx, id, p, 0)
		if err != nil {
			return nil, "", err
		}
		m.mu.Lock()
		m.pending[id] = p
		m.mu.Unlock()
		return tx, id, nil
	}()
	if err != nil {
		return nil, err
	}

	receipt, err := bind.WaitMined(ctx, m.backend, tx)
	if err != nil {
		// The broadcast may still mine: keep the reservation until a Tick
		// reaps its receipt, so the nonce is not reused underneath it. If
		// it never reaches the pool, Tick fills the nonce instead.
		return nil, err
	}
	m.Done(id)
	return receipt, nil
}

// Tick drives every pending intent: reap mined ones, drop ones whose nonce
// another transaction consumed, fill the nonce of a Transact lost from the
// pool, fee-bump stale ones, and alarm when a deadline closes in.
func (m *TxManager) Tick(ctx context.Context, head uint64) {
	m.tickMu.Lock()
	defer m.tickMu.Unlock()

	m.mu.Lock()
	ids := make([]string, 0, len(m.pending))
	for id := range m.pending {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	// The account's nonces, read BEFORE the receipt checks: a nonce below
	// the mined one whose own receipts are then still absent was consumed
	// by some other transaction, never by a race with this tick. Either
	// read failing just skips the checks that need it.
	mined, haveMined := uint64(0), false
	if nr, ok := m.backend.(nonceReader); ok {
		if n, err := nr.NonceAt(ctx, m.from, nil); err == nil {
			mined, haveMined = n, true
		}
	}
	pooled, perr := m.backend.PendingNonceAt(ctx, m.from)

	for _, id := range ids {
		m.mu.Lock()
		p, ok := m.pending[id]
		m.mu.Unlock()
		if !ok {
			continue
		}

		if m.reap(ctx, id, p) {
			continue
		}

		// The nonce went to another transaction (another wallet on the same
		// key, or a lost broadcast the node later replaced): none of this
		// intent's attempts can ever mine. Dropping it releases the
		// reservation and lets the caller's next Submit pick a fresh nonce;
		// bumping on would only collect "nonce too low" until the deadline.
		if haveMined && p.nonce < mined {
			m.alarm("transaction %s lost nonce %d to another transaction; intent dropped, caller will re-evaluate", id, p.nonce)
			m.Done(id)
			continue
		}

		// A Transact broadcast missing from the pool (lost, evicted, or its
		// caller gave up waiting) is never resent, so its reservation would
		// stand as a permanent gap that every later intent queues behind.
		// The pool's pending nonce sitting exactly on it means everything
		// below is in place and this one is absent; once that has held for
		// a bump window, fill the nonce with a 0-value self-transfer rather
		// than resending the call — its caller may already have retried it
		// at a fresh nonce, and a deposit must never land twice.
		if p.noBump && perr == nil {
			switch {
			case pooled != p.nonce:
				p.missingAt = 0
			case p.missingAt == 0:
				p.missingAt = head
			case head >= p.missingAt+bumpAfterBlocks:
				m.alarm("transaction %s (nonce %d) is missing from the pool; filling its nonce with a 0-value self-transfer", id, p.nonce)
				p.build = m.fillNonce
				p.noBump = false
			}
		}

		if p.deadline > 0 && head+alarmBlocksBeforeDeadline > p.deadline {
			m.alarm("transaction %s still unmined with %d blocks to deadline (tx %s, %d bumps)",
				id, int64(p.deadline)-int64(head), p.txHashes[len(p.txHashes)-1].Hex(), p.bumps)
		}

		if !p.noBump && head >= p.submittedAt+bumpAfterBlocks && head >= p.retryAt {
			// Same nonce, 25% higher price: replaces the stuck transaction.
			// The bump budget is consumed by a successful handoff to the
			// RPC, never by the attempt — burning it on failed sends would
			// let a long RPC outage exhaust maxBumps with only the original
			// low-fee transaction in the mempool, halting escalation exactly
			// when the recovered RPC needs it. Past the cap the transaction
			// is rebroadcast at its final price, so one lost from the pool
			// after the last bump is not stranded there.
			prev := new(big.Int).Set(p.gasPrice)
			if p.bumps < maxBumps {
				p.gasPrice.Add(p.gasPrice, new(big.Int).Div(new(big.Int).Mul(p.gasPrice, big.NewInt(bumpPercent)), big.NewInt(100)))
			}
			if _, err := m.send(ctx, id, p, head); err != nil {
				// A nonce consumed underneath the intent: settled if one of
				// its own attempts mined, otherwise dropped so the caller's
				// next Submit re-nonces. Bumping on would burn the budget
				// on a nonce that can never mine again.
				if nonceTooLow(err) {
					if !m.reap(ctx, id, p) {
						m.alarm("transaction %s lost nonce %d to another transaction; intent dropped, caller will re-evaluate", id, p.nonce)
						m.Done(id)
					}
					continue
				}
				// "already known" / "underpriced" races are benign (the
				// price sticks so the next tick compounds another 25%);
				// anything else rolls back the price and retries at the
				// next block. A build that fails deterministically (the
				// channel was settled under a lingering challenge, so
				// estimateGas reverts) is thereby retried and alarmed once
				// per block, not on every tick for the life of the intent,
				// while a transient RPC failure delays escalation by one
				// block at most. Near the deadline every tick retries.
				if benignResubmitError(err) {
					m.countBump(p)
				} else {
					p.gasPrice.Set(prev)
					p.retryAt = head + 1
					if p.deadline > 0 && head+alarmBlocksBeforeDeadline > p.deadline {
						p.retryAt = head
					}
					m.alarm("fee-bump for %s failed: %v", id, err)
				}
				continue
			}
			m.countBump(p)
		}
	}
}

// reap resolves an intent if any of its attempts has a receipt. Any attempt
// mining resolves it: after a fee bump, the replaced original can still be
// the one that lands, and watching only the newest hash would leave the
// intent pending forever.
func (m *TxManager) reap(ctx context.Context, id string, p *pendingTx) bool {
	for _, hash := range p.txHashes {
		if receipt, err := m.backend.TransactionReceipt(ctx, hash); err == nil && receipt != nil {
			if receipt.Status != types.ReceiptStatusSuccessful {
				m.alarm("transaction %s reverted (tx %s); intent dropped, caller will re-evaluate", id, hash.Hex())
			}
			m.Done(id)
			return true
		}
	}
	return false
}

// countBump consumes one unit of the bump budget; rebroadcasts past the cap
// are free.
func (m *TxManager) countBump(p *pendingTx) {
	if p.bumps < maxBumps {
		p.bumps++
	}
}

// fillNonce builds and sends a 0-value self-transfer at the reserved nonce:
// the stand-in for a Transact broadcast that went missing from the pool.
func (m *TxManager) fillNonce(auth *bind.TransactOpts) (*types.Transaction, error) {
	tx := types.NewTransaction(auth.Nonce.Uint64(), m.from, new(big.Int), transferGas, auth.GasPrice, nil)
	signed, err := auth.Signer(m.from, tx)
	if err != nil {
		return nil, err
	}
	if err := m.backend.SendTransaction(auth.Context, signed); err != nil {
		return nil, err
	}
	return signed, nil
}

func benignResubmitError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "already known") ||
		strings.Contains(s, "underpriced")
}

func nonceTooLow(err error) bool {
	return strings.Contains(err.Error(), "nonce too low")
}
