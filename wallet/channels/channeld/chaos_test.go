package channeld

// The Phase B chaos harness: two full wallet nodes exchange payments over a
// relay while the driver crashes either (or both) at randomized points —
// including the W1 window (proposal committed, never published) and the W2
// window (countersigned and committed, ACK never sent) — restarts them from
// disk, and asserts after every cycle:
//
//   - no equivocation ever became durable: no signer has two payloads at one
//     seq, simultaneous proposals included;
//   - no complete-state regression: a completed seq's digest never changes
//     and the latest seq never moves backwards;
//   - every interrupted payment resolves to COMPLETE or clean supersession;
//   - the poisoned flag survives restarts and clears only through a cure;
//   - conservation: both sides' close balances always sum to the deposits.
//
// Run the full gate with: go test -run TestChaos -chaos.cycles=10000

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/keys"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/nostrmod"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/protocol"
)

var (
	chaosCycles  = flag.Int("chaos.cycles", 240, "total chaos cycles across all workers")
	chaosWorkers = flag.Int("chaos.workers", 8, "parallel chaos workers (independent channel pairs)")
	chaosSeed    = flag.Int64("chaos.seed", 0, "rng seed (0 = time-based)")
)

const chaosDeposit = int64(1e15) // per side, wei

// chaosParty is a restartable wallet bound to a fixed data dir and key.
type chaosParty struct {
	t       *testing.T
	h       *hub
	key     *ecdsa.PrivateKey
	dataDir string
	role    proofstore.Role

	node   *Node
	cancel context.CancelFunc
}

var discardLog = slog.New(slog.NewTextHandler(io.Discard, nil))

func (p *chaosParty) start(chKey proofstore.ChannelKey) {
	cfg := DefaultConfig()
	cfg.Registries = map[string][]RegistryEntry{
		"v1": {{Address: chKey.Registry.Hex(), ChainID: 2110}},
	}
	cfg.Nostr.Relays = []string{"wss://hub"}
	cfg.Merchant.PushPayments = true
	cfg.Backup.Enabled = false // backups are exercised elsewhere; keep cycles tight

	node, err := New(cfg, p.dataDir, p.key, nil, discardLog)
	if err != nil {
		p.t.Fatal(err)
	}
	node.Pool = newHubPool(p.h, node.SelfPub)
	node.Transmitter = newHubTransmitter(node)
	node.TransmitInterval = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	p.node, p.cancel = node, cancel
	go node.Run(ctx, time.Hour)
}

// crash abandons the node abruptly: loops die on context cancellation and
// the store handle closes under them; only fsync'd state survives, exactly
// as after kill -9.
func (p *chaosParty) crash() {
	p.cancel()
	p.node.Close()
}

func (p *chaosParty) restart(chKey proofstore.ChannelKey) {
	p.crash()
	p.start(chKey)
}

// invariants tracks durable signatures across the whole run.
type invariants struct {
	t *testing.T
	// completed[seq] = digest of the complete state at that seq
	completed map[uint64]util.Hash
	// selfSigned[role][seq] = digest journaled by that signer at that seq
	selfSigned map[proofstore.Role]map[uint64]util.Hash
	maxSeq     map[proofstore.Role]uint64
}

func newInvariants(t *testing.T) *invariants {
	return &invariants{
		t:         t,
		completed: map[uint64]util.Hash{},
		selfSigned: map[proofstore.Role]map[uint64]util.Hash{
			proofstore.RoleA: {}, proofstore.RoleB: {},
		},
		maxSeq: map[proofstore.Role]uint64{},
	}
}

// observe scans both stores and checks the durable-signature invariants.
func (inv *invariants) observe(cycle int, parties []*chaosParty, chKey proofstore.ChannelKey) {
	for _, p := range parties {
		latest, err := p.node.Store.LatestState(chKey)
		if err == nil {
			d, derr := latest.Digest()
			if derr != nil {
				inv.t.Fatalf("cycle %d: digest: %v", cycle, derr)
			}
			if prev, ok := inv.completed[latest.Seq]; ok && prev != d {
				inv.t.Fatalf("cycle %d: COMPLETE-STATE CONFLICT at seq %d: %s vs %s",
					cycle, latest.Seq, prev.Hex(), d.Hex())
			}
			inv.completed[latest.Seq] = d
			if latest.Seq < inv.maxSeq[p.role] {
				inv.t.Fatalf("cycle %d: REGRESSION on %s: latest seq %d < previously observed %d",
					cycle, p.role, latest.Seq, inv.maxSeq[p.role])
			}
			inv.maxSeq[p.role] = latest.Seq
		}
		journal, err := p.node.Store.SelfSigned(chKey)
		if err != nil {
			inv.t.Fatalf("cycle %d: journal: %v", cycle, err)
		}
		for _, st := range journal {
			d, derr := st.Digest()
			if derr != nil {
				inv.t.Fatalf("cycle %d: digest: %v", cycle, derr)
			}
			if prev, ok := inv.selfSigned[p.role][st.Seq]; ok && prev != d {
				inv.t.Fatalf("cycle %d: EQUIVOCATION by %s at seq %d: %s vs %s",
					cycle, p.role, st.Seq, prev.Hex(), d.Hex())
			}
			inv.selfSigned[p.role][st.Seq] = d
			// A journaled payload differing from the completed one at the
			// same seq is an equivocation for either role.
			if cd, ok := inv.completed[st.Seq]; ok && cd != d {
				inv.t.Fatalf("cycle %d: %s signed a variant at completed seq %d", cycle, p.role, st.Seq)
			}
		}
	}
}

// chaosWorker runs one independent channel pair for n cycles.
func chaosWorker(t *testing.T, seed int64, cycles int) {
	rng := rand.New(rand.NewSource(seed))
	h := newHub()
	h.maxRetained = 128

	chKey := proofstore.ChannelKey{
		ChainID:   "2110",
		Registry:  util.HexToAddress("0x00000000000000000000000000000000000021ff"),
		ChannelID: 1,
	}
	keyA, _ := crypto.GenerateKey()
	keyB, _ := crypto.GenerateKey()
	alice := &chaosParty{t: t, h: h, key: keyA, dataDir: t.TempDir(), role: proofstore.RoleA}
	bob := &chaosParty{t: t, h: h, key: keyB, dataDir: t.TempDir(), role: proofstore.RoleB}
	alice.start(chKey)
	bob.start(chKey)
	defer func() { alice.crash(); bob.crash() }()

	deposits := proofstore.Deposits{
		DepositA:         proofstore.NewU256(big.NewInt(chaosDeposit)),
		DepositB:         proofstore.NewU256(big.NewInt(chaosDeposit)),
		LastScannedBlock: 1,
	}
	for _, p := range []struct {
		who  *chaosParty
		peer *chaosParty
	}{{alice, bob}, {bob, alice}} {
		err := p.who.node.Store.CreateChannel(proofstore.ChannelMeta{
			Key:             chKey,
			Role:            p.who.role,
			Status:          proofstore.StatusOpen,
			PeerNpub:        mustSelfPub(t, p.peer.key),
			PeerAddress:     crypto.PubkeyToAddress(p.peer.key.PublicKey),
			ChallengePeriod: 144,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.who.node.Store.PutDeposits(chKey, deposits); err != nil {
			t.Fatal(err)
		}
	}

	inv := newInvariants(t)
	parties := []*chaosParty{alice, bob}
	total := new(big.Int).Mul(big.NewInt(2), big.NewInt(chaosDeposit))

	// resolve waits for full convergence: identical latest states, empty
	// journals, and no live queue entries for seqs at or below the latest.
	resolve := func(cycle int) proofstore.SignedState {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			la, errA := alice.node.Store.LatestState(chKey)
			lb, errB := bob.node.Store.LatestState(chKey)
			okStates := errA == nil && errB == nil && la.Seq == lb.Seq
			if okStates {
				da, _ := la.Digest()
				db, _ := lb.Digest()
				okStates = da == db
			}
			if okStates {
				ja, _ := alice.node.Store.SelfSigned(chKey)
				jb, _ := bob.node.Store.SelfSigned(chKey)
				qa, _ := alice.node.Store.OutboundLen()
				qb, _ := bob.node.Store.OutboundLen()
				if len(ja) == 0 && len(jb) == 0 && qa == 0 && qb == 0 {
					return la
				}
			}
			time.Sleep(3 * time.Millisecond)
		}
		t.Fatalf("cycle %d: did not resolve", cycle)
		return proofstore.SignedState{}
	}

	balanceOfPayer := func(payer *chaosParty) *big.Int {
		balA, balB, err := payer.node.Engine.CloseBalances(chKey)
		if err != nil {
			t.Fatal(err)
		}
		if payer.role == proofstore.RoleA {
			return balA
		}
		return balB
	}

	for cycle := 0; cycle < cycles; cycle++ {
		payer, responder := alice, bob
		if rng.Intn(2) == 0 {
			payer, responder = bob, alice
		}
		amount := big.NewInt(int64(rng.Intn(1000) + 1))
		if balanceOfPayer(payer).Cmp(amount) < 0 {
			payer, responder = responder, payer // the other side has the funds
		}
		before := resolveStateOrZero(t, payer, chKey)

		switch scenario := rng.Intn(10); {
		case scenario < 5: // plain payment, random crash of either/both/none
			if err := payer.node.Pay(context.Background(), chKey, amount, ""); err != nil {
				t.Fatalf("cycle %d: pay: %v", cycle, err)
			}
			switch rng.Intn(4) {
			case 0: // crash payer mid-flight (samples the W1 window too)
				time.Sleep(time.Duration(rng.Intn(12)) * time.Millisecond)
				payer.restart(chKey)
			case 1: // crash responder mid-flight
				time.Sleep(time.Duration(rng.Intn(12)) * time.Millisecond)
				responder.restart(chKey)
			case 2: // crash both
				time.Sleep(time.Duration(rng.Intn(12)) * time.Millisecond)
				payer.restart(chKey)
				responder.restart(chKey)
			}
			final := resolve(cycle)
			assertDelta(t, cycle, before, final, payer.role, amount)

		case scenario < 6: // deterministic W1 window: committed, never published
			if err := payer.node.Pay(context.Background(), chKey, amount, ""); err != nil {
				t.Fatalf("cycle %d: pay: %v", cycle, err)
			}
			payer.restart(chKey) // no sleep: overwhelmingly pre-publish
			final := resolve(cycle)
			assertDelta(t, cycle, before, final, payer.role, amount)

		case scenario < 7: // deterministic W2 window: countersigned, ACK never sent
			prop, err := payer.node.Engine.ProposePayment(chKey, amount, "", 0)
			if err != nil {
				t.Fatalf("cycle %d: propose: %v", cycle, err)
			}
			// Deliver straight into the responder's engine: W2 commits, but
			// the ACK is discarded (the "crash before ACK send" point).
			res, err := responder.node.Engine.HandleProposal(*prop, payer.node.SelfPub, 0, time.Now().Unix())
			if err != nil || res.Ack == nil {
				t.Fatalf("cycle %d: countersign: %+v %v", cycle, res, err)
			}
			responder.restart(chKey)
			// The payer never transmitted either; queue the proposal now as
			// Pay would have (its persisted journal entry already exists).
			if err := payer.node.enqueueProposal(chKey, prop); err != nil {
				t.Fatalf("cycle %d: enqueue: %v", cycle, err)
			}
			final := resolve(cycle) // duplicate proposal -> idempotent re-ACK
			assertDelta(t, cycle, before, final, payer.role, amount)

		case scenario < 8: // simultaneous proposals: A wins, both land
			ja, _ := alice.node.Store.SelfSigned(chKey)
			jb, _ := bob.node.Store.SelfSigned(chKey)
			if len(ja) > 0 || len(jb) > 0 {
				continue
			}
			amountB := big.NewInt(int64(rng.Intn(1000) + 1))
			if err := alice.node.Pay(context.Background(), chKey, amount, ""); err != nil {
				t.Fatalf("cycle %d: payA: %v", cycle, err)
			}
			if err := bob.node.Pay(context.Background(), chKey, amountB, ""); err != nil {
				t.Fatalf("cycle %d: payB: %v", cycle, err)
			}
			// A re-issues above the conflict; B's countersignature voids
			// its own variant, then B rebases.
			waitJournalEmpty(t, cycle, bob, chKey)
			if err := bob.node.Pay(context.Background(), chKey, amountB, ""); err != nil &&
				!errors.Is(err, protocol.ErrProposalPending) {
				t.Fatalf("cycle %d: rebase: %v", cycle, err)
			}
			final := resolve(cycle)
			bstate := stateOrZero(before)
			wantAB := new(big.Int).Add(bstate.TransferredAtoB.BigInt(), amount)
			wantBA := new(big.Int).Add(bstate.TransferredBtoA.BigInt(), amountB)
			if final.TransferredAtoB.BigInt().Cmp(wantAB) != 0 || final.TransferredBtoA.BigInt().Cmp(wantBA) != 0 {
				t.Fatalf("cycle %d: tiebreak totals: got (%s,%s) want (%s,%s)", cycle,
					final.TransferredAtoB.BigInt(), final.TransferredBtoA.BigInt(), wantAB, wantBA)
			}

		default: // NACK -> poisoned -> crash -> flag survives -> cure
			if err := responder.node.Store.UpdateMeta(chKey, func(m *proofstore.ChannelMeta) {
				m.FrozenUntilBlock = 1 << 40
			}); err != nil {
				t.Fatal(err)
			}
			if err := payer.node.Pay(context.Background(), chKey, amount, ""); err != nil {
				t.Fatalf("cycle %d: pay: %v", cycle, err)
			}
			waitPoisoned(t, cycle, payer, chKey)
			payer.restart(chKey)
			meta, err := payer.node.Store.Meta(chKey)
			if err != nil || !meta.Poisoned {
				t.Fatalf("cycle %d: poisoned flag lost across restart: %+v %v", cycle, meta, err)
			}
			// Stop retransmitting the doomed proposal, unfreeze, cure.
			journal, _ := payer.node.Store.SelfSigned(chKey)
			for _, st := range journal {
				payer.node.settleOutbound(protocol.KindProposal, chKey, st.Seq)
			}
			if err := responder.node.Store.UpdateMeta(chKey, func(m *proofstore.ChannelMeta) {
				m.FrozenUntilBlock = 0
			}); err != nil {
				t.Fatal(err)
			}
			if err := payer.node.CureBySupersession(context.Background(), chKey); err != nil {
				t.Fatalf("cycle %d: cure: %v", cycle, err)
			}
			final := resolve(cycle)
			assertDelta(t, cycle, before, final, payer.role, new(big.Int)) // net no-op
			meta, _ = payer.node.Store.Meta(chKey)
			if meta.Poisoned {
				t.Fatalf("cycle %d: poisoned flag not cleared after cure", cycle)
			}
		}

		inv.observe(cycle, parties, chKey)

		// Conservation on both sides, every cycle.
		for _, p := range parties {
			balA, balB, err := p.node.Engine.CloseBalances(chKey)
			if err != nil {
				t.Fatalf("cycle %d: balances: %v", cycle, err)
			}
			if new(big.Int).Add(balA, balB).Cmp(total) != 0 {
				t.Fatalf("cycle %d: conservation violated on %s: %s + %s != %s",
					cycle, p.role, balA, balB, total)
			}
		}
	}
}

func TestChaos(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos harness skipped in -short")
	}
	seed := *chaosSeed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	t.Logf("chaos: %d cycles, %d workers, seed %d", *chaosCycles, *chaosWorkers, seed)
	restore := nostrmod.SetRetransmitBackoffForTesting(1, 2)
	defer restore()

	perWorker := *chaosCycles / *chaosWorkers
	for w := 0; w < *chaosWorkers; w++ {
		w := w
		t.Run(fmt.Sprintf("worker%d", w), func(t *testing.T) {
			t.Parallel()
			chaosWorker(t, seed+int64(w), perWorker)
		})
	}
}

// --------------------------------------------------------------- helpers

func mustSelfPub(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	nk, err := keys.DeriveNostrKey(crypto.FromECDSA(key))
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(nk.PubX[:])
}

func resolveStateOrZero(t *testing.T, p *chaosParty, key proofstore.ChannelKey) *proofstore.SignedState {
	st, err := p.node.Store.LatestState(key)
	if err != nil {
		return nil
	}
	return &st
}

func stateOrZero(st *proofstore.SignedState) proofstore.SignedState {
	if st == nil {
		return proofstore.SignedState{
			TransferredAtoB: proofstore.NewU256(nil),
			TransferredBtoA: proofstore.NewU256(nil),
		}
	}
	return *st
}

// assertDelta checks the payer's outbound total advanced by exactly amount.
func assertDelta(t *testing.T, cycle int, before *proofstore.SignedState, final proofstore.SignedState, payerRole proofstore.Role, amount *big.Int) {
	t.Helper()
	b := stateOrZero(before)
	var prev, now *big.Int
	if payerRole == proofstore.RoleA {
		prev, now = b.TransferredAtoB.BigInt(), final.TransferredAtoB.BigInt()
	} else {
		prev, now = b.TransferredBtoA.BigInt(), final.TransferredBtoA.BigInt()
	}
	if got := new(big.Int).Sub(now, prev); got.Cmp(amount) != 0 {
		t.Fatalf("cycle %d: payment delta: got %s want %s", cycle, got, amount)
	}
}

func waitJournalEmpty(t *testing.T, cycle int, p *chaosParty, key proofstore.ChannelKey) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		j, err := p.node.Store.SelfSigned(key)
		if err == nil && len(j) == 0 {
			return
		}
		time.Sleep(3 * time.Millisecond)
	}
	t.Fatalf("cycle %d: journal never cleared", cycle)
}

func waitPoisoned(t *testing.T, cycle int, p *chaosParty, key proofstore.ChannelKey) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		meta, err := p.node.Store.Meta(key)
		if err == nil && meta.Poisoned {
			return
		}
		time.Sleep(3 * time.Millisecond)
	}
	t.Fatalf("cycle %d: never poisoned", cycle)
}
