package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	smtpserver "github.com/emersion/go-smtp"
)

func TestMailRelayRewritesSenderHeadersAndForwardsOneRecipient(t *testing.T) {
	var gotFrom string
	var gotRecipients []string
	var gotMessage []byte
	relay := &mailRelay{
		from: "Holodex <noreply@plumb.capital>", fromAddr: "noreply@plumb.capital", maxDaily: 10,
	}
	relay.send = func(from string, recipients []string, message []byte) error {
		gotFrom = from
		gotRecipients = append([]string(nil), recipients...)
		gotMessage = append([]byte(nil), message...)
		return nil
	}
	session := &mailRelaySession{relay: relay}
	if err := session.Mail("spoof@example.com", &smtpserver.MailOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := session.Rcpt("customer@example.com", &smtpserver.RcptOptions{}); err != nil {
		t.Fatal(err)
	}
	message := "From: Spoof <spoof@example.com>\r\nReply-To: Vehicle Underwriter <noreply@example.com>\r\nTo: customer@example.com\r\nSubject: Confirm\r\n\r\nHello"
	if err := session.Data(strings.NewReader(message)); err != nil {
		t.Fatal(err)
	}
	if gotFrom != "noreply@plumb.capital" || len(gotRecipients) != 1 || gotRecipients[0] != "customer@example.com" {
		t.Fatalf("unexpected envelope: from=%q recipients=%q", gotFrom, gotRecipients)
	}
	if bytes.Contains(gotMessage, []byte("spoof@example.com")) || bytes.Contains(gotMessage, []byte("Vehicle Underwriter")) {
		t.Fatalf("original sender headers were not removed: %s", gotMessage)
	}
	if !bytes.Contains(gotMessage, []byte("From: Holodex <noreply@plumb.capital>")) || !bytes.Contains(gotMessage, []byte("Reply-To: Holodex <noreply@plumb.capital>")) {
		t.Fatalf("sender headers were not rewritten: %s", gotMessage)
	}
}

func TestMailRelayFromEnvAcceptsLegacyVariables(t *testing.T) {
	t.Setenv("HOLODECK_SMTP_ADDRESS", "smtp.example.com")
	t.Setenv("HOLODECK_SMTP_USERNAME", "user")
	t.Setenv("HOLODECK_SMTP_PASSWORD", "pass")
	t.Setenv("HOLODECK_SMTP_FROM", "Holodex <noreply@plumb.capital>")
	relay, err := mailRelayFromEnv()
	if err != nil || relay == nil {
		t.Fatalf("legacy HOLODECK_SMTP_* configuration was rejected: %v", err)
	}
	if relay.upstream != "smtp.example.com:587" || relay.hostname != "holodex" {
		t.Fatalf("unexpected relay config: upstream=%q hostname=%q", relay.upstream, relay.hostname)
	}
	t.Setenv("HOLODEX_SMTP_ADDRESS", "smtp.current.example")
	relay, err = mailRelayFromEnv()
	if err != nil || relay.upstream != "smtp.current.example:587" {
		t.Fatalf("HOLODEX_* must win over HOLODECK_*: upstream=%q err=%v", relay.upstream, err)
	}
}

func TestMailRelayEnforcesDailyQuota(t *testing.T) {
	relay := &mailRelay{from: "Vela <noreply@plumb.capital>", fromAddr: "noreply@plumb.capital", maxDaily: 1}
	relay.send = func(string, []string, []byte) error { return nil }
	message := func() io.Reader { return strings.NewReader("Subject: Test\r\n\r\nHello") }
	for attempt := 0; attempt < 2; attempt++ {
		session := &mailRelaySession{relay: relay, recipients: []string{"customer@example.com"}}
		err := session.Data(message())
		if attempt == 0 && err != nil {
			t.Fatal(err)
		}
		if attempt == 1 && (err == nil || !strings.Contains(err.Error(), "quota")) {
			t.Fatalf("second message should hit quota, got %v", err)
		}
	}
}
