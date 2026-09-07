package nostrmod

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
)

type capturePublisher struct {
	mu     sync.Mutex
	wraps  []nostr.Event
	accept bool
}

func (c *capturePublisher) Publish(ctx context.Context, ev nostr.Event) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wraps = append(c.wraps, ev)
	if c.accept {
		return 1
	}
	return 0
}

func (c *capturePublisher) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.wraps)
}

func openTestStore(t *testing.T) *proofstore.Store {
	t.Helper()
	s, err := proofstore.Open(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestTransmitterRetransmitsWithBackoff(t *testing.T) {
	store := openTestStore(t)
	pub := &capturePublisher{accept: true}
	senderPriv, _ := newPair(t)
	recipientPriv, recipientPub := newPair(t)

	tx := NewTransmitter(store, pub, senderPriv)
	now := int64(1_000_000)
	tx.Now = func() int64 { return now }

	_, err := store.EnqueueOutbound(proofstore.OutboundItem{
		DedupeKey: "21902:test:1",
		ToNpub:    recipientPub,
		Kind:      21902,
		Content:   `{"v":1,"seq":"1"}`,
		Tags:      [][]string{{"ch", "17"}},
		RumorTime: now,
		ExpiresAt: now + 3600,
	})
	if err != nil {
		t.Fatal(err)
	}

	// First tick sends immediately.
	if n, _, err := tx.Tick(context.Background()); err != nil || n != 1 {
		t.Fatalf("first tick: %d %v", n, err)
	}
	// Next tick is inside the 2s backoff: nothing due.
	now++
	if n, _, err := tx.Tick(context.Background()); err != nil || n != 0 {
		t.Fatalf("backoff not respected: %d %v", n, err)
	}
	// 2s after the first attempt it retransmits; then 4s, capped at 60s.
	now += 2
	if n, _, _ := tx.Tick(context.Background()); n != 1 {
		t.Fatal("no retransmission at 2s")
	}
	now += 4
	if n, _, _ := tx.Tick(context.Background()); n != 1 {
		t.Fatal("no retransmission at +4s")
	}

	// Every attempt is the identical rumor under a fresh seal/wrap.
	if pub.count() != 3 {
		t.Fatalf("wraps: %d", pub.count())
	}
	pub.mu.Lock()
	defer pub.mu.Unlock()
	seenWrapIDs := map[string]bool{}
	for _, wrap := range pub.wraps {
		if seenWrapIDs[wrap.ID] {
			t.Fatal("wrap reused across attempts")
		}
		seenWrapIDs[wrap.ID] = true
		rumor, _, err := Unwrap(wrap, recipientPriv)
		if err != nil {
			t.Fatal(err)
		}
		if rumor.Kind != 21902 || rumor.Content != `{"v":1,"seq":"1"}` {
			t.Fatalf("rumor mutated: %+v", rumor)
		}
		if tag := rumor.Tags.Find("ch"); tag == nil || tag[1] != "17" {
			t.Fatalf("rumor tags lost: %v", rumor.Tags)
		}
	}
}

func TestTransmitterStopsOnDedupeRemoval(t *testing.T) {
	store := openTestStore(t)
	pub := &capturePublisher{accept: true}
	senderPriv, _ := newPair(t)
	_, recipientPub := newPair(t)
	tx := NewTransmitter(store, pub, senderPriv)
	now := int64(1_000_000)
	tx.Now = func() int64 { return now }

	if _, err := store.EnqueueOutbound(proofstore.OutboundItem{
		DedupeKey: "21902:test:5", ToNpub: recipientPub, Kind: 21902,
		Content: "{}", RumorTime: now, ExpiresAt: now + 3600,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tx.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The ACK arrived: the wallet removes by dedupe key; nothing retransmits.
	removed, err := store.RemoveOutboundByDedupe("21902:test:5")
	if err != nil || removed != 1 {
		t.Fatalf("removed %d %v", removed, err)
	}
	now += 120
	if n, _, _ := tx.Tick(context.Background()); n != 0 {
		t.Fatal("retransmitted after removal")
	}
	if qlen, _ := store.OutboundLen(); qlen != 0 {
		t.Fatalf("queue not empty: %d", qlen)
	}
}

func TestTransmitterGivesUpAtExpiry(t *testing.T) {
	store := openTestStore(t)
	pub := &capturePublisher{accept: true}
	senderPriv, _ := newPair(t)
	_, recipientPub := newPair(t)
	tx := NewTransmitter(store, pub, senderPriv)
	now := int64(1_000_000)
	tx.Now = func() int64 { return now }

	if _, err := store.EnqueueOutbound(proofstore.OutboundItem{
		DedupeKey: "21902:test:9", ToNpub: recipientPub, Kind: 21902,
		Content: "{}", RumorTime: now, ExpiresAt: now + 10,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tx.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}

	now += 11
	_, gaveUp, err := tx.Tick(context.Background())
	if err != nil || len(gaveUp) != 1 || gaveUp[0].DedupeKey != "21902:test:9" {
		t.Fatalf("give-up: %+v %v", gaveUp, err)
	}
	if qlen, _ := store.OutboundLen(); qlen != 0 {
		t.Fatalf("expired item still queued: %d", qlen)
	}
}

func TestQueueSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "q.db")
	s, err := proofstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueOutbound(proofstore.OutboundItem{
		DedupeKey: "d", ToNpub: "n", Kind: 21906, Content: "{}",
		RumorTime: 1, ExpiresAt: 1 << 40,
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := proofstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	due, _, err := s2.DueOutbound(100, 10)
	if err != nil || len(due) != 1 || due[0].DedupeKey != "d" {
		t.Fatalf("queue lost across reopen: %+v %v", due, err)
	}
}

// closingPublisher closes the store while publishing, so the reschedule
// that follows fails with a genuine store error (not the benign mid-pass
// settle that Tick already tolerates) and the pass returns an error
// alongside its give-ups.
type closingPublisher struct {
	store *proofstore.Store
}

func (p *closingPublisher) Publish(ctx context.Context, ev nostr.Event) int {
	_ = p.store.Close()
	return 1
}

// TestGiveUpSurvivesTickError: DueOutbound deletes expired items in its own
// transaction, so they surface exactly once — as Tick's gaveUp list. Run
// dropped that list whenever the same pass also returned an error, and for
// a 21902 the give-up is the MANDATORY MarkPoisoned trigger (Part 3 §5): a
// channel with an outstanding un-ACKed proposal stayed unpoisoned and the
// user never saw the exposure. The erroring pass here is one whose
// reschedule write fails against a closed store: Tick returns the give-ups
// together with the error, and Run must still deliver them.
func TestGiveUpSurvivesTickError(t *testing.T) {
	store := openTestStore(t)
	senderPriv, _ := newPair(t)
	_, recipientPub := newPair(t)

	tx := NewTransmitter(store, nil, senderPriv)
	now := int64(1_000_000)
	tx.Now = func() int64 { return now }

	// One expired proposal (the give-up that must reach the callback)...
	_, err := store.EnqueueOutbound(proofstore.OutboundItem{
		DedupeKey: "21902:expired:1",
		ToNpub:    recipientPub,
		Kind:      21902,
		Content:   `{"v":1,"seq":"1"}`,
		RumorTime: now - 100,
		ExpiresAt: now - 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	// ...and one due item whose reschedule will fail this pass because the
	// store goes away mid-publish.
	_, err = store.EnqueueOutbound(proofstore.OutboundItem{
		DedupeKey: "21903:due:1",
		ToNpub:    recipientPub,
		Kind:      21903,
		Content:   `{"v":1,"seq":"1"}`,
		RumorTime: now,
		ExpiresAt: now + 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx.pool = &closingPublisher{store: store}

	// The pass must actually error: a clean pass would not exercise Run's
	// error tolerance at all.
	if _, gaveUp, err := tx.Tick(context.Background()); err == nil {
		t.Fatal("tick did not error against the closed store")
	} else if len(gaveUp) != 1 || gaveUp[0].DedupeKey != "21902:expired:1" {
		t.Fatalf("tick give-ups: %+v", gaveUp)
	}

	// Re-arm: a fresh store with the same two items, closed again by the
	// publisher, so the Run loop sees the identical erroring pass.
	store = openTestStore(t)
	tx.store = store
	tx.pool = &closingPublisher{store: store}
	for _, item := range []proofstore.OutboundItem{
		{DedupeKey: "21902:expired:1", ToNpub: recipientPub, Kind: 21902,
			Content: `{"v":1,"seq":"1"}`, RumorTime: now - 100, ExpiresAt: now - 1},
		{DedupeKey: "21903:due:1", ToNpub: recipientPub, Kind: 21903,
			Content: `{"v":1,"seq":"1"}`, RumorTime: now, ExpiresAt: now + 1000},
	} {
		if _, err := store.EnqueueOutbound(item); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var gaveUp []proofstore.OutboundItem
	go tx.Run(ctx, time.Millisecond, func(item proofstore.OutboundItem) {
		mu.Lock()
		gaveUp = append(gaveUp, item)
		mu.Unlock()
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(gaveUp)
		mu.Unlock()
		if n > 0 {
			mu.Lock()
			defer mu.Unlock()
			if gaveUp[0].DedupeKey != "21902:expired:1" {
				t.Fatalf("wrong item gave up: %+v", gaveUp[0])
			}
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("give-up notification lost: the expired proposal never reached the poisoned-marking callback")
}
