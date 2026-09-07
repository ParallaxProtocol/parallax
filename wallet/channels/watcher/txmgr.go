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

// pendingTx is one tracked intent.
type pendingTx struct {
	build       func(*bind.TransactOpts) (*types.Transaction, error)
	nonce       uint64
	gasPrice    *big.Int
	txHashes    []util.Hash // every attempt, oldest first: ANY of them mining resolves the intent
	submittedAt uint64      // head at last (re)submission
	bumps       int
	deadline    uint64 // 0 = none; alarm fires as head approaches it
	noBump      bool   // synchronous Transact intent: the caller owns retries
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
		// reaps its receipt, so the nonce is not reused underneath it.
		return nil, err
	}
	m.Done(id)
	return receipt, nil
}

// Tick drives every pending intent: reap mined ones, fee-bump stale ones,
// and alarm when a deadline closes in.
func (m *TxManager) Tick(ctx context.Context, head uint64) {
	m.tickMu.Lock()
	defer m.tickMu.Unlock()

	m.mu.Lock()
	ids := make([]string, 0, len(m.pending))
	for id := range m.pending {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	for _, id := range ids {
		m.mu.Lock()
		p, ok := m.pending[id]
		m.mu.Unlock()
		if !ok {
			continue
		}

		// Any attempt mining resolves the intent: after a fee bump, the
		// replaced original can still be the one that lands, and watching
		// only the newest hash would leave the intent pending forever.
		mined := false
		for _, hash := range p.txHashes {
			if receipt, err := m.backend.TransactionReceipt(ctx, hash); err == nil && receipt != nil {
				if receipt.Status != types.ReceiptStatusSuccessful {
					m.alarm("transaction %s reverted (tx %s); intent dropped, caller will re-evaluate", id, hash.Hex())
				}
				m.Done(id)
				mined = true
				break
			}
		}
		if mined {
			continue
		}

		if p.deadline > 0 && head+alarmBlocksBeforeDeadline > p.deadline {
			m.alarm("transaction %s still unmined with %d blocks to deadline (tx %s, %d bumps)",
				id, int64(p.deadline)-int64(head), p.txHashes[len(p.txHashes)-1].Hex(), p.bumps)
		}

		if !p.noBump && head >= p.submittedAt+bumpAfterBlocks && p.bumps < maxBumps {
			// Same nonce, 25% higher price: replaces the stuck transaction.
			// The bump budget is consumed by a successful handoff to the
			// RPC, never by the attempt — burning it on failed sends would
			// let a long RPC outage exhaust maxBumps with only the original
			// low-fee transaction in the mempool, halting escalation exactly
			// when the recovered RPC needs it.
			prev := new(big.Int).Set(p.gasPrice)
			p.gasPrice.Add(p.gasPrice, new(big.Int).Div(new(big.Int).Mul(p.gasPrice, big.NewInt(bumpPercent)), big.NewInt(100)))
			if _, err := m.send(ctx, id, p, head); err != nil {
				// "already known" / "underpriced" races are benign (the
				// price sticks so the next tick compounds another 25%);
				// anything else rolls back the price and waits another
				// bumpAfterBlocks before the next attempt. A build that
				// fails deterministically (the channel was settled under
				// a lingering challenge, so estimateGas reverts) is thereby
				// retried and alarmed once per bump window, not on every
				// tick for the life of the intent.
				if benignResubmitError(err) {
					p.bumps++
				} else {
					p.gasPrice.Set(prev)
					p.submittedAt = head
					m.alarm("fee-bump for %s failed: %v", id, err)
				}
				continue
			}
			p.bumps++
		}
	}
}

func benignResubmitError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "already known") ||
		strings.Contains(s, "underpriced") ||
		strings.Contains(s, "nonce too low") // mined between receipt check and resubmit
}
