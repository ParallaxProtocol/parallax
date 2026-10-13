package channeld

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/nostrmod"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/protocol"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/watcher"
)

// giveUpAfter bounds retransmission for a payment with no invoice expiry
// (Part 2 §7.2: invoice expiry, else 24 h).
const giveUpAfter = 24 * time.Hour

// Pay proposes a payment on the channel and queues the proposal for
// delivery. The proposal is W1-persisted before this returns; completion
// arrives asynchronously via the dispatcher (ACK) and clears the queue
// entry.
func (n *Node) Pay(ctx context.Context, key proofstore.ChannelKey, amountWei *big.Int, invoiceID string) error {
	prop, err := n.Engine.ProposePayment(key, amountWei, invoiceID, n.headBlock(ctx))
	if err != nil {
		return err
	}
	return n.enqueueProposal(key, prop)
}

// AwaitPayment blocks until the payment proposed after `before` completes,
// the wait expires, or ctx is done. It returns the completed seq.
//
// A bare seq advance is NOT completion: in the A-wins tiebreak the seq is
// occupied by the counterparty's payment and our intent is discarded, and a
// NACK leaves the seq advancing later for unrelated reasons. Completion
// means OUR cumulative outbound moved by exactly the paid amount with
// nothing of ours left journaled.
func (n *Node) AwaitPayment(ctx context.Context, key proofstore.ChannelKey, before proofstore.SignedState, amountWei *big.Int, wait time.Duration) (uint64, error) {
	deadline := time.Now().Add(wait)
	for {
		meta, err := n.Store.Meta(key)
		if err != nil {
			return 0, err
		}
		if meta.Poisoned {
			exposure, _ := n.Engine.PoisonedExposure(key)
			return 0, fmt.Errorf("channeld: payment refused (channel poisoned by a NACK); exposure if closed now: %s wei", exposure)
		}
		latest, lerr := n.Store.LatestState(key)
		if lerr == nil && latest.Seq > before.Seq {
			if journal, jerr := n.Store.SelfSigned(key); jerr == nil && len(journal) == 0 {
				delta := new(big.Int).Sub(protocol.OutboundOf(&latest, meta.Role), protocol.OutboundOf(&before, meta.Role))
				if delta.Cmp(amountWei) == 0 {
					return latest.Seq, nil
				}
				return 0, fmt.Errorf("channeld: payment intent discarded at seq %d without paying (tiebreak); re-issue the payment", latest.Seq)
			}
		}
		if !time.Now().Before(deadline) {
			break
		}
		select {
		case <-time.After(200 * time.Millisecond):
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	exposure, _ := n.Engine.PoisonedExposure(key)
	return 0, fmt.Errorf("channeld: no countersignature yet; the proposal keeps retransmitting from the persistent queue. Channel exposure if closed now: %s wei", exposure)
}

// ResolveInvoice resolves a locally stored invoice (received via 21901) to
// the channel and amount that pay it.
func (n *Node) ResolveInvoice(invoiceID string) (proofstore.ChannelKey, *big.Int, error) {
	inv, err := n.Store.Invoice(invoiceID)
	if err != nil {
		return proofstore.ChannelKey{}, nil, fmt.Errorf("channeld: unknown invoice %s (was it received over the relay?)", invoiceID)
	}
	if inv.Paid {
		// Spent by this wallet's own irrevocable proposal (marked at the W1
		// write, released if that proposal is voided); the engine refuses a
		// second one under its lock, this check only names where it went.
		if inv.PaidBy != nil {
			return proofstore.ChannelKey{}, nil, fmt.Errorf("channeld: invoice %s already paid at seq %d on channel %s", invoiceID, inv.PaidSeq, inv.PaidBy.String())
		}
		return proofstore.ChannelKey{}, nil, fmt.Errorf("channeld: invoice %s already paid", invoiceID)
	}
	if time.Now().Unix() > inv.ExpiresAt {
		return proofstore.ChannelKey{}, nil, fmt.Errorf("channeld: invoice expired")
	}
	key, ok := n.channelWithMerchant(inv)
	if !ok {
		return proofstore.ChannelKey{}, nil, fmt.Errorf("channeld: no open channel with the invoice's merchant")
	}
	return key, inv.AmountWei.BigInt(), nil
}

// CureBySupersession queues the no-op supersession that voids outstanding
// proposals on a poisoned channel (Part 2 §7.4 exit b).
func (n *Node) CureBySupersession(ctx context.Context, key proofstore.ChannelKey) error {
	prop, err := n.Engine.ProposeNoOpSupersession(key, n.headBlock(ctx))
	if err != nil {
		return err
	}
	return n.enqueueProposal(key, prop)
}

func (n *Node) enqueueProposal(key proofstore.ChannelKey, prop *protocol.ProposalMsg) error {
	meta, err := n.Store.Meta(key)
	if err != nil {
		return err
	}
	content, err := protocol.EncodePayload(prop)
	if err != nil {
		return err
	}
	seq, err := strconv.ParseUint(prop.State.Seq, 10, 64)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = n.Store.EnqueueOutbound(proofstore.OutboundItem{
		DedupeKey: watcher.DedupeKeyFor(protocol.KindProposal, key, seq),
		ToNpub:    meta.PeerNpub,
		Kind:      protocol.KindProposal,
		Content:   content,
		Tags:      [][]string{{"ch", prop.State.ChannelID}},
		RumorTime: now,
		ExpiresAt: now + int64(giveUpAfter.Seconds()),
	})
	return err
}

// CoopClose signs and queues a cooperative-close proposal; the channel
// freezes immediately (Part 1 §7.4).
func (n *Node) CoopClose(ctx context.Context, key proofstore.ChannelKey) error {
	// Same head requirement as the inbound handler: an online node whose
	// RPC is down would compute expiry = 0 + validity — a block far in the
	// past — and sign itself into a nonsense close whose pending record
	// blocks re-proposals. Fail closed; the caller retries.
	head, err := n.requireHead(ctx)
	if err != nil {
		return fmt.Errorf("channeld: %w; retry the cooperative close when the RPC recovers", err)
	}
	expiry := head + n.Cfg.Channels.CoopCloseValidityBlocks
	prop, err := n.Engine.ProposeCoopClose(key, expiry, head)
	if err != nil {
		return err
	}
	meta, err := n.Store.Meta(key)
	if err != nil {
		return err
	}
	content, err := protocol.EncodePayload(prop)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	// A coop close retransmits until countersigned or its on-chain expiry;
	// block time ~10 min bounds the wall-clock conversion generously.
	_, err = n.Store.EnqueueOutbound(proofstore.OutboundItem{
		DedupeKey: watcher.DedupeKeyFor(protocol.KindCoopCloseProposal, key, 0),
		ToNpub:    meta.PeerNpub,
		Kind:      protocol.KindCoopCloseProposal,
		Content:   content,
		Tags:      [][]string{{"ch", prop.ChannelID}},
		RumorTime: now,
		ExpiresAt: now + int64(n.Cfg.Channels.CoopCloseValidityBlocks)*600,
	})
	return err
}

// Withdraw proposes a cooperative withdraw of amountWei to this wallet and
// queues the 21911 for delivery; on-chain submission happens when the
// countersignature (21912) arrives.
func (n *Node) Withdraw(ctx context.Context, key proofstore.ChannelKey, amountWei *big.Int) error {
	// Same fail-closed rule as CoopClose: expiry is meaningless at head 0.
	head, err := n.requireHead(ctx)
	if err != nil {
		return fmt.Errorf("channeld: %w; retry the withdraw when the RPC recovers", err)
	}
	expiry := head + n.Cfg.Channels.WithdrawValidityBlocks
	prop, err := n.Engine.ProposeWithdraw(key, amountWei, expiry, head)
	if err != nil {
		return err
	}
	meta, err := n.Store.Meta(key)
	if err != nil {
		return err
	}
	content, err := protocol.EncodePayload(prop)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = n.Store.EnqueueOutbound(proofstore.OutboundItem{
		DedupeKey: watcher.DedupeKeyFor(protocol.KindWithdrawProposal, key, 0),
		ToNpub:    meta.PeerNpub,
		Kind:      protocol.KindWithdrawProposal,
		Content:   content,
		Tags:      [][]string{{"ch", prop.ChannelID}},
		RumorTime: now,
		ExpiresAt: now + int64(n.Cfg.Channels.WithdrawValidityBlocks)*600,
	})
	return err
}

// RestoreFromBackups drains the relay pool for wait, collects self-backups,
// and restores the freshest snapshot per channel. The caller MUST run a
// watcher pass before signing anything new (Part 3 §4.3).
func (n *Node) RestoreFromBackups(ctx context.Context, wait time.Duration) (int, error) {
	deadline := time.After(wait)
	var snaps []nostrmod.Snapshot
	for {
		select {
		case wrap := <-n.Pool.Events():
			if snap, err := nostrmod.ParseBackup(wrap, n.NostrPriv); err == nil {
				snaps = append(snaps, snap)
			}
		case <-deadline:
			if len(snaps) == 0 {
				return 0, fmt.Errorf("channeld: no self-backups found on relays")
			}
			return nostrmod.RestoreSnapshots(n.Store, snaps)
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}
