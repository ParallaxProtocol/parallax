package channeld

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"math/big"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/protocol"
)

// DefaultInvoiceTTL bounds an invoice with no explicit TTL.
const DefaultInvoiceTTL = 15 * time.Minute

// CreateInvoice mints and persists an invoice (merchant side, Part 2 §6.1)
// and returns it with its bootstrap payment URI. channelID zero leaves the
// payer free to pick any shared open channel.
func (n *Node) CreateInvoice(amountWei *big.Int, memo string, ttl time.Duration, channelID uint64) (proofstore.Invoice, string, error) {
	if amountWei == nil || amountWei.Sign() <= 0 {
		return proofstore.Invoice{}, "", fmt.Errorf("channeld: non-positive invoice amount")
	}
	if ttl <= 0 {
		ttl = DefaultInvoiceTTL
	}
	var pinned proofstore.ChannelKey
	if channelID != 0 {
		// A pin is a bare id, which coexisting registries both number from 1:
		// resolve it fail-closed now, or the URI gets stamped with an
		// arbitrary registry and the customer's channel filter rejects a
		// perfectly valid pinned invoice.
		key, err := n.ChannelKeyByID(channelID)
		if err != nil {
			return proofstore.Invoice{}, "", err
		}
		meta, err := n.Store.Meta(key)
		if err != nil {
			return proofstore.Invoice{}, "", err
		}
		if meta.Status != proofstore.StatusOpen {
			return proofstore.Invoice{}, "", fmt.Errorf("channeld: pinned channel %d is not open", channelID)
		}
		pinned = key
	}
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return proofstore.Invoice{}, "", err
	}
	inv := proofstore.Invoice{
		ID:        hex.EncodeToString(idBytes[:]),
		AmountWei: proofstore.NewU256(amountWei),
		Memo:      memo,
		ExpiresAt: time.Now().Add(ttl).Unix(),
		ChannelID: channelID,
		Registry:  pinned.Registry,
		ChainID:   pinned.ChainID,
		Merchant:  n.Signer.Address(),
	}
	if err := n.Store.CreateInvoice(inv); err != nil {
		return proofstore.Invoice{}, "", err
	}
	return inv, n.InvoiceURI(inv), nil
}

// InvoiceURI renders the bootstrap URI (Part 2 §6.1):
// parallax:<evmAddress>?amount=<wei>&inv=<id>&npub=<hex>&relays=<r1|r2>&reg=<registry>[&ch=<id>]
func (n *Node) InvoiceURI(inv proofstore.Invoice) string {
	// For unpinned invoices reg= is a bootstrap hint only (which registry a
	// channel-less payer should open on); pick it deterministically rather
	// than by map iteration order.
	var reg string
	for _, label := range slices.Sorted(maps.Keys(n.Cfg.Registries)) {
		if entries := n.Cfg.Registries[label]; len(entries) > 0 {
			reg = strings.ToLower(entries[0].Address)
			break
		}
	}
	q := url.Values{}
	q.Set("amount", inv.AmountWei.BigInt().String())
	q.Set("inv", inv.ID)
	q.Set("npub", n.SelfPub)
	q.Set("relays", strings.Join(n.Cfg.Nostr.Relays, "|"))
	if inv.ChannelID != 0 {
		// A pinned invoice is only payable on that channel: the URI must
		// carry the pin, or a payer with several channels to this merchant
		// proposes on the wrong one and gets NACKed after the irrevocable
		// journal write. The pin also names the authoritative registry.
		q.Set("ch", strconv.FormatUint(inv.ChannelID, 10))
		// The invoice's own qualifier is authoritative; records predating it
		// re-resolve the bare id (CreateInvoice fails closed on ambiguous
		// pins, so it names at most one channel).
		if inv.Registry != (util.Address{}) {
			reg = strings.ToLower(inv.Registry.Hex())
		} else if key, err := n.ChannelKeyByID(inv.ChannelID); err == nil {
			reg = strings.ToLower(key.Registry.Hex())
		}
	}
	q.Set("reg", reg)
	return "parallax:" + strings.ToLower(n.Signer.Address().Hex()) + "?" + q.Encode()
}

// PaymentRequest is a parsed payment URI.
type PaymentRequest struct {
	Merchant  util.Address
	AmountWei *big.Int
	InvoiceID string
	Npub      string
	Relays    []string
	Registry  util.Address
	ChannelID uint64 // nonzero: the invoice is pinned to this channel
}

// ParsePaymentURI parses a parallax: URI.
func ParsePaymentURI(uri string) (PaymentRequest, error) {
	var req PaymentRequest
	rest, ok := strings.CutPrefix(uri, "parallax:")
	if !ok {
		return req, fmt.Errorf("channeld: not a parallax: URI")
	}
	addr, query, _ := strings.Cut(rest, "?")
	if !util.IsHexAddress(addr) {
		return req, fmt.Errorf("channeld: bad merchant address %q", addr)
	}
	req.Merchant = util.HexToAddress(addr)
	q, err := url.ParseQuery(query)
	if err != nil {
		return req, err
	}
	if req.AmountWei, ok = new(big.Int).SetString(q.Get("amount"), 10); !ok || req.AmountWei.Sign() <= 0 {
		return req, fmt.Errorf("channeld: bad amount %q", q.Get("amount"))
	}
	req.InvoiceID = q.Get("inv")
	req.Npub = q.Get("npub")
	if relays := q.Get("relays"); relays != "" {
		req.Relays = strings.Split(relays, "|")
	}
	if reg := q.Get("reg"); reg != "" {
		if !util.IsHexAddress(reg) {
			return req, fmt.Errorf("channeld: bad registry %q", reg)
		}
		req.Registry = util.HexToAddress(reg)
	}
	if ch := q.Get("ch"); ch != "" {
		if req.ChannelID, err = strconv.ParseUint(ch, 10, 64); err != nil {
			return req, fmt.Errorf("channeld: bad channel pin %q", ch)
		}
	}
	return req, nil
}

// ChannelForRequest picks the channel to pay a parsed payment URI on: the
// pinned channel when the URI names one (a pinned invoice is only payable
// there — anything else the merchant NACKs after the payer's irrevocable
// journal write), qualified by the URI's registry since the bare pin is
// ambiguous across coexisting registries; else the first open channel with
// the URI's merchant. For unpinned requests the URI's registry is only a
// bootstrap hint (the merchant accepts any shared open channel), never a
// filter: a multi-registry merchant stamps one registry on the URI, and
// filtering by it would reject a valid channel on the other.
func (n *Node) ChannelForRequest(req PaymentRequest) (proofstore.ChannelKey, error) {
	metas, err := n.Store.ListChannels()
	if err != nil {
		return proofstore.ChannelKey{}, err
	}
	for _, meta := range metas {
		if meta.PeerAddress != req.Merchant || meta.Status != proofstore.StatusOpen {
			continue
		}
		// The URI carries no chain qualifier, so the pin is matched on
		// registry alone here.
		if !proofstore.PinMatches(req.ChannelID, req.Registry, "", meta.Key) {
			continue
		}
		return meta.Key, nil
	}
	if req.ChannelID != 0 {
		return proofstore.ChannelKey{}, fmt.Errorf("channeld: the invoice is pinned to channel %d, which is not an open channel with merchant %s", req.ChannelID, req.Merchant.Hex())
	}
	return proofstore.ChannelKey{}, fmt.Errorf("channeld: no open channel with merchant %s — open one first", req.Merchant.Hex())
}

// SendInvoice queues a 21901 to a channel counterparty (for payers already
// reachable over the relay; the URI covers cold bootstrap).
func (n *Node) SendInvoice(key proofstore.ChannelKey, inv proofstore.Invoice) error {
	meta, err := n.Store.Meta(key)
	if err != nil {
		return err
	}
	msg := protocol.InvoiceMsg{
		V:          1,
		InvoiceID:  inv.ID,
		Amount:     inv.AmountWei.BigInt().String(),
		EVMAddress: strings.ToLower(n.Signer.Address().Hex()),
		Registry:   strings.ToLower(key.Registry.Hex()),
		ChainID:    key.ChainID,
		Memo:       inv.Memo,
		ExpiresAt:  strconv.FormatInt(inv.ExpiresAt, 10),
		Relays:     n.Cfg.Nostr.Relays,
	}
	if inv.ChannelID != 0 {
		msg.ChannelID = strconv.FormatUint(inv.ChannelID, 10)
		// The message's Registry/ChainID must name the PIN's deployment, not
		// the channel the invoice happens to travel over — the payer stores
		// them as the pin qualifier.
		if inv.Registry != (util.Address{}) {
			msg.Registry = strings.ToLower(inv.Registry.Hex())
			msg.ChainID = inv.ChainID
		}
	}
	content, err := protocol.EncodePayload(msg)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = n.Store.EnqueueOutbound(proofstore.OutboundItem{
		DedupeKey: "21901:" + inv.ID,
		ToNpub:    meta.PeerNpub,
		Kind:      protocol.KindInvoice,
		Content:   content,
		Tags:      [][]string{{"inv", inv.ID}},
		RumorTime: now,
		ExpiresAt: inv.ExpiresAt,
	})
	return err
}

// handleInvoice records an inbound 21901 on the payer side (Part 2 §6.1
// payer checks run at pay time) so `channel pay --invoice <id>` can resolve
// amount and channel without retyping.
func (n *Node) handleInvoice(msg protocol.InvoiceMsg, sender string) error {
	amount, ok := new(big.Int).SetString(msg.Amount, 10)
	if !ok || amount.Sign() <= 0 {
		return fmt.Errorf("channeld: bad invoice amount %q", msg.Amount)
	}
	expires, err := strconv.ParseInt(msg.ExpiresAt, 10, 64)
	if err != nil {
		return fmt.Errorf("channeld: bad invoice expiry %q", msg.ExpiresAt)
	}
	if !util.IsHexAddress(msg.EVMAddress) {
		return fmt.Errorf("channeld: bad invoice merchant address")
	}
	merchant := util.HexToAddress(msg.EVMAddress)

	// Only accept invoices from a known channel counterparty whose npub and
	// address both match — anything else is unsolicited spam.
	metas, err := n.Store.ListChannels()
	if err != nil {
		return err
	}
	known := false
	for _, meta := range metas {
		if meta.PeerNpub == sender && meta.PeerAddress == merchant {
			known = true
			break
		}
	}
	if !known {
		return fmt.Errorf("channeld: invoice from unknown counterparty")
	}

	// An absent pin stays absent (PayInvoice picks any open channel with the
	// merchant); a present pin must parse, carry its registry qualifier, and
	// name a channel this wallet holds with the merchant — anything else is
	// unpayable and rejected whole rather than silently re-pinned to an
	// arbitrary first-match channel (the merchant would NACK the payment
	// after the irrevocable journal write, poisoning a healthy channel).
	var channelID uint64
	var pinReg util.Address
	var pinChain string
	if msg.ChannelID != "" {
		channelID, err = strconv.ParseUint(msg.ChannelID, 10, 64)
		if err != nil || channelID == 0 {
			return fmt.Errorf("channeld: bad invoice channel pin %q", msg.ChannelID)
		}
		if msg.Registry != "" {
			if !util.IsHexAddress(msg.Registry) {
				return fmt.Errorf("channeld: bad invoice registry %q", msg.Registry)
			}
			pinReg = util.HexToAddress(msg.Registry)
		}
		pinChain = msg.ChainID
		found := false
		for _, meta := range metas {
			if meta.PeerNpub == sender && meta.PeerAddress == merchant &&
				proofstore.PinMatches(channelID, pinReg, pinChain, meta.Key) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("channeld: invoice pinned to channel %d, which is not a channel with this merchant", channelID)
		}
	}

	inv := proofstore.Invoice{
		ID:        msg.InvoiceID,
		AmountWei: proofstore.NewU256(amount),
		Memo:      msg.Memo,
		ExpiresAt: expires,
		ChannelID: channelID,
		Registry:  pinReg,
		ChainID:   pinChain,
		Merchant:  merchant,
	}
	if err := n.Store.CreateInvoice(inv); err != nil {
		if err == proofstore.ErrExists {
			return nil // retransmission
		}
		return err
	}
	n.log.Info("invoice received", "id", inv.ID, "amountWei", amount, "memo", msg.Memo)
	return nil
}

// PayInvoice resolves a locally stored invoice (received via 21901) and pays
// it on its channel.
func (n *Node) PayInvoice(ctx context.Context, invoiceID string) error {
	key, amount, err := n.ResolveInvoice(invoiceID)
	if err != nil {
		return err
	}
	return n.Pay(ctx, key, amount, invoiceID)
}

// channelWithMerchant resolves the invoice's pin — or, unpinned, any open
// channel — against the store, requiring the counterparty to be the
// invoice's merchant. A pin is matched with its registry/chain qualifier: a
// bare id alone is ambiguous across coexisting registries.
func (n *Node) channelWithMerchant(inv proofstore.Invoice) (proofstore.ChannelKey, bool) {
	metas, err := n.Store.ListChannels()
	if err != nil {
		return proofstore.ChannelKey{}, false
	}
	for _, meta := range metas {
		if meta.PeerAddress == inv.Merchant && meta.Status == proofstore.StatusOpen && inv.PinMatches(meta.Key) {
			return meta.Key, true
		}
	}
	return proofstore.ChannelKey{}, false
}
