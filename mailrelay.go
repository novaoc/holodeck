package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	stdsmtp "net/smtp"
	"strconv"
	"strings"
	"sync"
	"time"

	smtpserver "github.com/emersion/go-smtp"
)

const maxPreviewMailBytes = 2 << 20

type mailRelay struct {
	listenAddr string
	upstream   string
	username   string
	password   string
	from       string
	fromAddr   string
	hostname   string // internal hostname apps use to reach the relay
	maxDaily   int
	send       func(string, []string, []byte) error

	mu        sync.Mutex
	day       string
	delivered int
}

func mailRelayFromEnv() (*mailRelay, error) {
	address := strings.TrimSpace(setting("SMTP_ADDRESS"))
	username := setting("SMTP_USERNAME")
	password := setting("SMTP_PASSWORD")
	from := strings.TrimSpace(setting("SMTP_FROM"))
	if address == "" && username == "" && password == "" && from == "" {
		return nil, nil
	}
	if address == "" || username == "" || password == "" || from == "" {
		return nil, errors.New("HOLODEX_SMTP_ADDRESS, USERNAME, PASSWORD, and FROM must be set together")
	}
	parsedFrom, err := mail.ParseAddress(from)
	if err != nil || strings.ContainsAny(from, "\r\n") {
		return nil, errors.New("HOLODEX_SMTP_FROM must be a valid single mailbox")
	}
	port := atoiOr(setting("SMTP_PORT"), 587)
	if port < 1 || port > 65535 {
		return nil, errors.New("HOLODEX_SMTP_PORT must be 1-65535")
	}
	relay := &mailRelay{
		listenAddr: settingOr("SMTP_LISTEN", ":2525"),
		upstream:   net.JoinHostPort(address, strconv.Itoa(port)),
		username:   username,
		password:   password,
		from:       from,
		fromAddr:   parsedFrom.Address,
		hostname:   settingOr("SMTP_HOSTNAME", "holodex"),
		maxDaily:   atoiOr(setting("SMTP_MAX_DAILY"), 100),
	}
	if relay.maxDaily < 1 {
		return nil, errors.New("HOLODEX_SMTP_MAX_DAILY must be positive")
	}
	relay.send = relay.sendUpstream
	return relay, nil
}

func (r *mailRelay) serve(listener net.Listener) error {
	server := smtpserver.NewServer(r)
	server.Domain = r.hostname
	server.MaxMessageBytes = maxPreviewMailBytes
	server.MaxRecipients = 1
	server.ReadTimeout = 30 * time.Second
	server.WriteTimeout = 30 * time.Second
	return server.Serve(listener)
}

func (r *mailRelay) NewSession(_ *smtpserver.Conn) (smtpserver.Session, error) {
	return &mailRelaySession{relay: r}, nil
}

func (r *mailRelay) reserve() (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	today := time.Now().UTC().Format(time.DateOnly)
	if r.day != today {
		r.day = today
		r.delivered = 0
	}
	if r.delivered >= r.maxDaily {
		return r.delivered, false
	}
	r.delivered++
	return r.delivered, true
}

func (r *mailRelay) sendUpstream(_ string, recipients []string, message []byte) error {
	host, _, err := net.SplitHostPort(r.upstream)
	if err != nil {
		return err
	}
	connection, err := net.DialTimeout("tcp", r.upstream, 10*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(65 * time.Second)); err != nil {
		return err
	}
	client, err := stdsmtp.NewClient(connection, host)
	if err != nil {
		return err
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); !ok {
		return errors.New("upstream SMTP server did not offer STARTTLS")
	}
	if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
		return err
	}
	auth := stdsmtp.PlainAuth("", r.username, r.password, host)
	if err := client.Auth(auth); err != nil {
		return err
	}
	if err := client.Mail(r.fromAddr); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

type mailRelaySession struct {
	relay      *mailRelay
	recipients []string
}

func (s *mailRelaySession) Reset() {
	s.recipients = nil
}

func (s *mailRelaySession) Logout() error { return nil }

func (s *mailRelaySession) Mail(_ string, _ *smtpserver.MailOptions) error {
	s.Reset()
	return nil
}

func (s *mailRelaySession) Rcpt(to string, _ *smtpserver.RcptOptions) error {
	parsed, err := mail.ParseAddress(to)
	if err != nil || !strings.EqualFold(parsed.Address, to) {
		return errors.New("invalid recipient")
	}
	s.recipients = append(s.recipients, parsed.Address)
	return nil
}

func (s *mailRelaySession) Data(reader io.Reader) error {
	if len(s.recipients) != 1 {
		return errors.New("exactly one recipient is required")
	}
	message, err := io.ReadAll(io.LimitReader(reader, maxPreviewMailBytes+1))
	if err != nil {
		return err
	}
	if len(message) > maxPreviewMailBytes {
		return errors.New("message exceeds preview limit")
	}
	delivered, allowed := s.relay.reserve()
	if !allowed {
		return errors.New("daily preview mail quota reached")
	}
	message = replaceMailHeader(message, "From", s.relay.from)
	if err := s.relay.send(s.relay.fromAddr, s.recipients, message); err != nil {
		return fmt.Errorf("upstream delivery failed: %w", err)
	}
	log.Printf("preview mail accepted by upstream (%d/%d today)", delivered, s.relay.maxDaily)
	return nil
}

func replaceMailHeader(message []byte, name, value string) []byte {
	separator := []byte("\r\n\r\n")
	parts := bytes.SplitN(message, separator, 2)
	lineEnding := "\r\n"
	if len(parts) != 2 {
		separator = []byte("\n\n")
		parts = bytes.SplitN(message, separator, 2)
		lineEnding = "\n"
	}
	if len(parts) != 2 {
		return message
	}
	lines := strings.Split(string(parts[0]), lineEnding)
	wanted := strings.ToLower(name) + ":"
	out := make([]string, 0, len(lines)+1)
	replaced := false
	skippingFold := false
	for _, line := range lines {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if skippingFold {
				continue
			}
			out = append(out, line)
			continue
		}
		skippingFold = strings.HasPrefix(strings.ToLower(line), wanted)
		if skippingFold {
			if !replaced {
				out = append(out, name+": "+value)
				replaced = true
			}
			continue
		}
		out = append(out, line)
	}
	if !replaced {
		out = append(out, name+": "+value)
	}
	return bytes.Join([][]byte{[]byte(strings.Join(out, lineEnding)), parts[1]}, separator)
}
