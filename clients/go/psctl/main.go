// psctl -- a minimal, cross-platform CLI client for the packetsonde agent's
// mTLS TCP IPC listener (the channel/payload protocol, the same one the Unix
// psctl and the UE client speak -- here it runs inside a TLS 1.3 tunnel).
//
// Identity is an Ed25519 keypair stored in the agent keystore's raw format
// (32-byte seed in <name>.sec, 32-byte pubkey in <name>.pub). The client
// presents a self-signed cert carrying that key; the agent authorizes it by
// matching the pubkey fingerprint against its authorized-keys dir. The client
// can pin the agent's fingerprint in turn (--agent-fpr).
//
// Build:
//   go build -o psctl            (host)
//   GOOS=windows GOARCH=amd64 go build -o psctl.exe
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	host := flag.String("host", "127.0.0.1", "agent host")
	port := flag.Int("port", 4701, "agent TCP IPC port")
	keyPath := flag.String("key", defaultKeyPath(), "path to client Ed25519 seed (.sec, 32 raw bytes)")
	agentFpr := flag.String("agent-fpr", "", "pin the agent's fingerprint (sha256:<hex>); empty = no pin")
	timeout := flag.Duration("timeout", 8*time.Second, "overall connect + I/O timeout")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	verb := args[0]

	// gen-key needs no connection.
	if verb == "gen-key" {
		if len(args) < 2 {
			fail("gen-key needs a path prefix, e.g. `psctl gen-key ./client`")
		}
		if err := genKey(args[1]); err != nil {
			fail("gen-key: %v", err)
		}
		return
	}

	ch, payload, wantResp, stream, err := buildRequest(verb, args[1:])
	if err != nil {
		fail("%v", err)
	}

	conn, err := dial(*host, *port, *keyPath, *agentFpr, *timeout)
	if err != nil {
		fail("connect: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))

	if ch != "" {
		if _, err := conn.Write(encodeFrame(ch, payload)); err != nil {
			fail("send %q: %v", ch, err)
		}
	}

	// Read frames. For a query verb, return once the matching response.* arrives
	// (broadcasts like discovery.* that interleave are printed too). For stream
	// verbs / listen, keep printing until the deadline or a terminal frame.
	for {
		rch, rpl, err := readFrame(conn)
		if err != nil {
			if isTimeout(err) && (stream || wantResp == "") {
				return // expected end for listen/stream
			}
			if errors.Is(err, io.EOF) {
				fail("connection closed by agent (rejected? not authorized?)")
			}
			fail("read: %v", err)
		}
		printFrame(rch, rpl)
		if wantResp != "" && rch == wantResp {
			return
		}
		if isTerminal(rch) {
			return
		}
	}
}

// ---- request construction ------------------------------------------------

// Returns (channel, payload, expectedResponseChannel, streaming, err).
func buildRequest(verb string, rest []string) (string, []byte, string, bool, error) {
	job := "psctl-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	switch verb {
	case "hosts":
		return "query.hosts", nil, "response.hosts", false, nil
	case "modules":
		return "query.modules", nil, "response.modules", false, nil
	case "stats":
		return "query.stats", nil, "response.stats", false, nil
	case "flows":
		return "query.flows", nil, "response.flows", false, nil
	case "probe":
		if len(rest) < 1 {
			return "", nil, "", false, errors.New("probe needs <address> [ports] [proto]")
		}
		addr := rest[0]
		ports := "443"
		if len(rest) > 1 {
			ports = rest[1]
		}
		proto := "tcp"
		if len(rest) > 2 {
			proto = rest[2]
		}
		pl := fmt.Sprintf(`{"job_id":"%s","address":"%s","ports":[%s],"proto":"%s"}`,
			job, addr, ports, proto)
		return "probe.request", []byte(pl), "", true, nil
	case "traceroute":
		if len(rest) < 1 {
			return "", nil, "", false, errors.New("traceroute needs <destination> [method]")
		}
		method := "paris"
		if len(rest) > 1 {
			method = rest[1]
		}
		pl := fmt.Sprintf(`{"job_id":"%s","destination":"%s","method":"%s"}`,
			job, rest[0], method)
		return "traceroute.request", []byte(pl), "", true, nil
	case "send":
		if len(rest) < 1 {
			return "", nil, "", false, errors.New("send needs <channel> [payload]")
		}
		var pl []byte
		if len(rest) > 1 {
			pl = []byte(rest[1])
		}
		return rest[0], pl, "", true, nil
	case "listen":
		// No request; just read whatever the agent broadcasts.
		return "", nil, "", true, nil
	default:
		return "", nil, "", false, fmt.Errorf("unknown verb %q (see -h)", verb)
	}
}

func isTerminal(ch string) bool {
	switch ch {
	case "traceroute.complete", "probe.complete":
		return true
	}
	return false
}

// ---- TLS dial + pin -------------------------------------------------------

func dial(host string, port int, keyPath, agentFpr string, timeout time.Duration) (*tls.Conn, error) {
	seed, err := readSeed(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load key %q: %w", keyPath, err)
	}
	cert, err := selfSignedCert(seed)
	if err != nil {
		return nil, err
	}
	want := strings.ToLower(strings.TrimSpace(agentFpr))
	cfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // we pin the agent pubkey ourselves below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if want == "" {
				return nil // no pin requested
			}
			if len(rawCerts) == 0 {
				return errors.New("agent presented no certificate")
			}
			c, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse agent cert: %w", err)
			}
			pub, ok := c.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("agent cert is not Ed25519")
			}
			got := fingerprint(pub)
			if got != want {
				return fmt.Errorf("agent fingerprint mismatch: got %s, want %s", got, want)
			}
			return nil
		},
	}
	td := &tls.Dialer{
		NetDialer: &net.Dialer{Deadline: time.Now().Add(timeout)},
		Config:    cfg,
	}
	conn, err := td.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

// ---- key + cert helpers ---------------------------------------------------

func selfSignedCert(seed []byte) (tls.Certificate, error) {
	priv := ed25519.NewKeyFromSeed(seed)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "packetsonde"},
		NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

func fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub) // SHA-256 of the raw 32-byte pubkey (keystore format)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func readSeed(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < ed25519.SeedSize {
		return nil, fmt.Errorf("seed too short (%d bytes, need %d)", len(b), ed25519.SeedSize)
	}
	return b[:ed25519.SeedSize], nil
}

func genKey(prefix string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(prefix+".sec", priv.Seed(), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(prefix+".pub", pub, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s.sec (0600) and %s.pub (0644)\n", prefix, prefix)
	fmt.Printf("fingerprint: %s\n", fingerprint(pub))
	fmt.Printf("authorize on the agent:  cp %s.pub <PS_KEY_DIR>/authorized/\n", filepath.Base(prefix))
	return nil
}

// ---- frame codec (little-endian, matches ipc_server.c) --------------------

func encodeFrame(channel string, payload []byte) []byte {
	out := make([]byte, 0, 8+len(channel)+len(payload))
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], uint32(len(channel)))
	out = append(out, l[:]...)
	out = append(out, channel...)
	binary.LittleEndian.PutUint32(l[:], uint32(len(payload)))
	out = append(out, l[:]...)
	out = append(out, payload...)
	return out
}

func readFrame(r io.Reader) (string, []byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return "", nil, err
	}
	chLen := binary.LittleEndian.Uint32(l[:])
	if chLen == 0 || chLen >= 128 {
		return "", nil, fmt.Errorf("bad channel length %d", chLen)
	}
	ch := make([]byte, chLen)
	if _, err := io.ReadFull(r, ch); err != nil {
		return "", nil, err
	}
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return "", nil, err
	}
	plLen := binary.LittleEndian.Uint32(l[:])
	if plLen > 256*1024 {
		return "", nil, fmt.Errorf("payload too large %d", plLen)
	}
	pl := make([]byte, plLen)
	if plLen > 0 {
		if _, err := io.ReadFull(r, pl); err != nil {
			return "", nil, err
		}
	}
	return string(ch), pl, nil
}

// ---- output ---------------------------------------------------------------

func printFrame(ch string, pl []byte) {
	if len(pl) == 0 {
		fmt.Printf("[%s]\n", ch)
		return
	}
	var pretty json.RawMessage
	if json.Unmarshal(pl, &pretty) == nil {
		var buf strings.Builder
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if enc.Encode(pretty) == nil {
			fmt.Printf("[%s]\n%s", ch, buf.String())
			return
		}
	}
	fmt.Printf("[%s] %s\n", ch, string(pl))
}

// ---- misc -----------------------------------------------------------------

func defaultKeyPath() string {
	if kd := os.Getenv("PS_KEY_DIR"); kd != "" {
		return filepath.Join(kd, "client.sec")
	}
	return "client.sec"
}

func isTimeout(err error) bool {
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "psctl: "+format+"\n", a...)
	os.Exit(1)
}

func usage() {
	fmt.Fprint(os.Stderr, `psctl -- mTLS TCP client for the packetsonde agent

Usage:
  psctl [flags] <verb> [args]

Verbs:
  hosts                     request the host table (query.hosts)
  modules                   list loaded modules (query.modules)
  stats                     aggregate stats (query.stats)
  flows                     active flow snapshot (query.flows)
  probe <addr> [ports] [proto]    dispatch a probe (default ports=443 proto=tcp)
  traceroute <dst> [method]       dispatch a traceroute (default method=paris)
  send <channel> [payload]  send an arbitrary channel/payload frame
  listen                    print frames the agent pushes (e.g. discovery.*)
  gen-key <prefix>          create <prefix>.sec/.pub (no connection)

Flags:
`)
	flag.PrintDefaults()
}
