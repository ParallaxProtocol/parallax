package merchantd

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/channeld"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/chantest"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/protocol"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/watcher"
)

const testToken = "secret-token"

func api(t *testing.T, ts *httptest.Server, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, ts.URL+path, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out.Bytes()
}

func TestMerchantInvoicePaymentWebhook(t *testing.T) {
	env := chantest.NewPair(t)
	merchant, payer := env.Bob, env.Alice // merchant is B, payer is A

	// Webhook receiver: counts deliveries and checks the HMAC.
	var webhooks atomic.Int32
	var lastBody atomic.Value
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body bytes.Buffer
		if _, err := body.ReadFrom(r.Body); err != nil {
			t.Error(err)
		}
		if r.Header.Get("X-Parallax-Signature") != Sign(testToken, body.Bytes()) {
			t.Error("bad webhook signature")
		}
		webhooks.Add(1)
		lastBody.Store(body.Bytes())
		w.WriteHeader(http.StatusOK)
	}))
	defer hookSrv.Close()
	merchant.Node.Cfg.Merchant.WebhookURL = hookSrv.URL

	server := New(merchant.Node, testToken, nil)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go merchant.Node.Run(ctx, time.Hour)
	go payer.Node.Run(ctx, time.Hour)
	go server.RunWebhookWorker(ctx, 50*time.Millisecond)
	env.WaitConnected(t)

	// Auth is enforced.
	if code, _ := api(t, ts, "GET", "/v1/channels", "wrong", nil); code != http.StatusUnauthorized {
		t.Fatalf("bad token accepted: %d", code)
	}
	if code, _ := api(t, ts, "GET", "/v1/healthz", "", nil); code != http.StatusOK {
		t.Fatal("healthz requires auth")
	}

	// Create an invoice pinned to the channel: it travels to the payer over
	// the relay.
	code, raw := api(t, ts, "POST", "/v1/invoices", testToken,
		map[string]any{"amountWei": "250", "memo": "espresso", "ttlSeconds": 600, "channelId": env.Key.ChannelID})
	if code != http.StatusCreated {
		t.Fatalf("create invoice: %d %s", code, raw)
	}
	var created invoiceResponse
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.URI, "parallax:") {
		t.Fatalf("bad uri: %s", created.URI)
	}

	// Payer receives the 21901 and pays it by id.
	env.WaitUntil(t, "invoice delivered", func() bool {
		_, err := payer.Node.Store.Invoice(created.InvoiceID)
		return err == nil
	})
	if err := payer.Node.PayInvoice(ctx, created.InvoiceID); err != nil {
		t.Fatal(err)
	}

	// The merchant marks it paid and the webhook fires with a valid HMAC.
	env.WaitUntil(t, "invoice paid", func() bool {
		_, raw := api(t, ts, "GET", "/v1/invoices/"+created.InvoiceID, testToken, nil)
		var got invoiceResponse
		return json.Unmarshal(raw, &got) == nil && got.Status == "paid" && got.PaidSeq == 1
	})
	env.WaitUntil(t, "webhook delivered", func() bool { return webhooks.Load() == 1 })

	var payload WebhookPayload
	if err := json.Unmarshal(lastBody.Load().([]byte), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.InvoiceID != created.InvoiceID || payload.AmountWei != "250" || payload.Seq != 1 {
		t.Fatalf("webhook payload: %+v", payload)
	}

	// A duplicate proposal must not double-fire (exactly-once invoice
	// marking); give any stray delivery time to appear.
	time.Sleep(300 * time.Millisecond)
	if webhooks.Load() != 1 {
		t.Fatalf("webhook fired %d times", webhooks.Load())
	}

	// Channel listing reflects the payment.
	_, raw = api(t, ts, "GET", "/v1/channels", testToken, nil)
	var channels []channeld.ChannelSummary
	if err := json.Unmarshal(raw, &channels); err != nil {
		t.Fatal(err)
	}
	// balanceB = bob's 5e9 deposit + the 250 payment.
	if len(channels) != 1 || channels[0].Seq != 1 || channels[0].BalanceB != "5000000250" {
		t.Fatalf("channels: %s", raw)
	}

	// Paying the same invoice again is refused (nack path on the payer).
	if err := payer.Node.PayInvoice(ctx, created.InvoiceID); err == nil {
		// The engine will refuse at proposal time or the merchant nacks;
		// either way the invoice stays paid exactly once. Wait briefly and
		// re-assert the webhook count.
		time.Sleep(300 * time.Millisecond)
		if webhooks.Load() != 1 {
			t.Fatalf("second payment re-fired webhook")
		}
	}
}

func TestMerchantWebhookRetries(t *testing.T) {
	env := chantest.NewPair(t)
	merchant := env.Bob

	var attempts atomic.Int32
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway) // fail twice
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hookSrv.Close()

	// Enqueue a webhook directly with an aggressive schedule.
	body, _ := json.Marshal(WebhookPayload{InvoiceID: "x", AmountWei: "1"})
	now := time.Now().Unix()
	if _, err := merchant.Node.Store.EnqueueWebhook(proofstore.WebhookItem{
		URL: hookSrv.URL, Body: body, ExpiresAt: now + 3600,
	}); err != nil {
		t.Fatal(err)
	}

	server := New(merchant.Node, testToken, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Force retries to be immediate by rescheduling manually between ticks.
	go server.RunWebhookWorker(ctx, 20*time.Millisecond)
	go func() {
		for i := 0; i < 200; i++ {
			due, _, _ := merchant.Node.Store.DueWebhooks(time.Now().Unix()+3600, 16)
			for _, item := range due {
				if item.NextAttempt > time.Now().Unix() {
					_ = merchant.Node.Store.RescheduleWebhook(item.ID, item.Attempts, time.Now().Unix())
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	env.WaitUntil(t, "webhook retried to success", func() bool { return attempts.Load() >= 3 })
	env.WaitUntil(t, "queue drained", func() bool {
		due, _, _ := merchant.Node.Store.DueWebhooks(time.Now().Unix()+7200, 16)
		return len(due) == 0
	})
	final := attempts.Load()
	time.Sleep(200 * time.Millisecond)
	if attempts.Load() != final {
		t.Fatal("delivered webhook kept retrying")
	}
}

// TestCloseRefusesAmbiguousBareChannelID: with coexisting registries both
// holding a channel id, a bare-id close must be refused — first-match
// resolution would freeze or force-close the wrong channel. The qualified
// <chainId>:<registry>:<id> form still works.
func TestCloseRefusesAmbiguousBareChannelID(t *testing.T) {
	env := chantest.NewPair(t)
	merchant := env.Bob

	decoy := env.Key
	decoy.Registry = util.HexToAddress("0x0000000000000000000000000000000000001111")
	err := merchant.Node.Store.CreateChannel(proofstore.ChannelMeta{
		Key:             decoy,
		Role:            proofstore.RoleB,
		Status:          proofstore.StatusOpen,
		PeerNpub:        strings.Repeat("cd", 32),
		PeerAddress:     env.Alice.Node.Signer.Address(),
		ChallengePeriod: 144,
	})
	if err != nil {
		t.Fatal(err)
	}

	server := New(merchant.Node, testToken, nil)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	code, raw := api(t, ts, "POST", "/v1/channels/1/close", testToken, nil)
	if code != http.StatusConflict {
		t.Fatalf("ambiguous bare-id close not refused: %d %s", code, raw)
	}
	for _, key := range []proofstore.ChannelKey{env.Key, decoy} {
		meta, err := merchant.Node.Store.Meta(key)
		if err != nil {
			t.Fatal(err)
		}
		if meta.FrozenUntilBlock != 0 || meta.PendingClose != nil {
			t.Fatalf("channel %s frozen by an ambiguous close", key)
		}
	}

	// The qualified reference disambiguates.
	code, raw = api(t, ts, "POST", "/v1/channels/"+env.Key.String()+"/close", testToken, nil)
	if code != http.StatusAccepted {
		t.Fatalf("qualified close refused: %d %s", code, raw)
	}
	meta, _ := merchant.Node.Store.Meta(env.Key)
	if meta.PendingClose == nil {
		t.Fatal("qualified close did not initiate")
	}
	if decoyMeta, _ := merchant.Node.Store.Meta(decoy); decoyMeta.PendingClose != nil {
		t.Fatal("qualified close hit the decoy channel")
	}
}

// TestZeroValueProposalFiresNoWebhook: the invoice id rides in the unsigned
// envelope, so a payer used to obtain a validly signed "paid" webhook for
// any pending invoice by naming it on a zero-delta supersession, with
// nothing transferred and the invoice still pending.
func TestZeroValueProposalFiresNoWebhook(t *testing.T) {
	env := chantest.NewPair(t)
	merchant, payer := env.Bob, env.Alice

	var webhooks atomic.Int32
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhooks.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer hookSrv.Close()
	merchant.Node.Cfg.Merchant.WebhookURL = hookSrv.URL

	server := New(merchant.Node, testToken, nil)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go merchant.Node.Run(ctx, time.Hour)
	go payer.Node.Run(ctx, time.Hour)
	go server.RunWebhookWorker(ctx, 50*time.Millisecond)
	env.WaitConnected(t)

	code, raw := api(t, ts, "POST", "/v1/invoices", testToken,
		map[string]any{"amountWei": "1000000000", "memo": "laptop", "ttlSeconds": 600})
	if code != http.StatusCreated {
		t.Fatalf("create invoice: %d %s", code, raw)
	}
	var created invoiceResponse
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatal(err)
	}

	// Journal a never-sent payment so a no-op supersession exists, then
	// queue the no-op naming the victim invoice.
	if _, err := payer.Node.Engine.ProposePayment(env.Key, big.NewInt(1), "", 0); err != nil {
		t.Fatal(err)
	}
	noop, err := payer.Node.Engine.ProposeNoOpSupersession(env.Key, 0)
	if err != nil {
		t.Fatal(err)
	}
	noop.InvoiceID = created.InvoiceID
	content, err := protocol.EncodePayload(noop)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := payer.Node.Store.EnqueueOutbound(proofstore.OutboundItem{
		DedupeKey: watcher.DedupeKeyFor(protocol.KindProposal, env.Key, 2),
		ToNpub:    merchant.Node.SelfPub, Kind: protocol.KindProposal, Content: content,
		RumorTime: now, ExpiresAt: now + 600,
	}); err != nil {
		t.Fatal(err)
	}

	env.WaitUntil(t, "no-op countersigned", func() bool {
		latest, err := merchant.Node.Store.LatestState(env.Key)
		return err == nil && latest.Seq == 2
	})
	time.Sleep(300 * time.Millisecond) // give any stray delivery time to appear
	if n := webhooks.Load(); n != 0 {
		t.Fatalf("zero-value proposal fired %d webhook(s)", n)
	}
	_, raw = api(t, ts, "GET", "/v1/invoices/"+created.InvoiceID, testToken, nil)
	var got invoiceResponse
	if err := json.Unmarshal(raw, &got); err != nil || got.Status != "pending" {
		t.Fatalf("invoice status after zero-value proposal: %s", raw)
	}
}
