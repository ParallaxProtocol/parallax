package channeld

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestSubmitAsyncSingleFlight: the engine re-returns the ready pair for
// every retransmitted close proposal or withdraw ACK, and each submission
// takes a fresh nonce. While the first submission waits for its block
// (>=10 minutes) a retransmission must not broadcast a second transaction
// that reverts behind the first; once the first finishes, the next request
// runs again.
func TestSubmitAsyncSingleFlight(t *testing.T) {
	h := newHub()
	n := newTestNode(t, h, nil)

	var runs atomic.Int64
	release := make(chan struct{})
	submit := func() error {
		runs.Add(1)
		<-release
		return nil
	}
	n.submitAsync("coopclose", e2eKey, submit)
	n.submitAsync("coopclose", e2eKey, submit) // retransmission: dropped
	other := e2eKey
	other.ChannelID++
	n.submitAsync("coopclose", other, submit) // another channel: runs
	n.submitAsync("withdraw", e2eKey, submit) // another verb: runs

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && runs.Load() < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := runs.Load(); got != 3 {
		t.Fatalf("submissions started = %d, want 3 (duplicate coalesced)", got)
	}
	close(release)

	// The slot frees once the submission returns.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n.inflightMu.Lock()
		busy := len(n.inflight)
		n.inflightMu.Unlock()
		if busy == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	done := make(chan struct{})
	n.submitAsync("coopclose", e2eKey, func() error { close(done); return nil })
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("slot not released after the first submission returned")
	}
}
