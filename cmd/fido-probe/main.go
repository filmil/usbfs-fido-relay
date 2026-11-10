// SPDX-License-Identifier: Apache-2.0

// Command fido-probe checks that this machine can talk to a FIDO key's
// CTAPHID interface, the way a key-side relay would. It changes nothing on
// the key: it sends CTAPHID_INIT and authenticatorGetInfo, which read only.
//
// On Linux, including the ChromeOS Linux container, it uses the key's usbfs
// node (open_linux.go). On macOS it uses IOKit, without seizing the key
// (open_darwin.go).
//
// Usage:
//
//	fido-probe [DEVICE]
//
// With no argument it uses the first Yubico key it finds.
package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/filmil/yubikey-forward/ctaphid"
)

// transport moves 64-byte CTAPHID reports to and from the key.
type transport interface {
	// send writes one report to the key.
	send(report []byte) error
	// recv reads one report. It returns errTimeout when the key sent
	// nothing within the timeout.
	recv(timeout time.Duration) ([]byte, error)
	// close releases the key.
	close() error
}

var errTimeout = errors.New("timeout")

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("PASS: the FIDO interface works from this machine")
}

func run(args []string) error {
	device := ""
	if len(args) > 0 {
		device = args[0]
	}
	t, err := open(device)
	if err != nil {
		return err
	}
	defer func() {
		if err := t.close(); err != nil {
			fmt.Println("warning: release the key:", err)
		}
	}()
	return probe(t)
}

func probe(t transport) error {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	start := time.Now()
	resp, err := call(t, ctaphid.Message{CID: ctaphid.BroadcastCID, Command: ctaphid.CmdInit, Payload: nonce})
	if err != nil {
		return fmt.Errorf("CTAPHID_INIT: %w", err)
	}
	if len(resp.Payload) < 17 || string(resp.Payload[:8]) != string(nonce) {
		return fmt.Errorf("CTAPHID_INIT: bad reply % x", resp.Payload)
	}
	cid := uint32(resp.Payload[8])<<24 | uint32(resp.Payload[9])<<16 | uint32(resp.Payload[10])<<8 | uint32(resp.Payload[11])
	caps := resp.Payload[16]
	fmt.Printf("CTAPHID_INIT: channel %08x, device version %d.%d.%d, capabilities %02x (CBOR %v), %v\n",
		cid, resp.Payload[13], resp.Payload[14], resp.Payload[15], caps, caps&0x04 != 0, time.Since(start).Round(time.Millisecond))
	if caps&0x04 == 0 {
		fmt.Println("the key does not speak CTAP2; U2F only")
		return nil
	}
	start = time.Now()
	resp, err = call(t, ctaphid.Message{CID: cid, Command: ctaphid.CmdCBOR, Payload: []byte{ctaphid.AuthGetInfo}})
	if err != nil {
		return fmt.Errorf("authenticatorGetInfo: %w", err)
	}
	if len(resp.Payload) == 0 || resp.Payload[0] != 0 {
		return fmt.Errorf("authenticatorGetInfo: status % x", resp.Payload[:min(1, len(resp.Payload))])
	}
	fmt.Printf("authenticatorGetInfo: %d bytes of CBOR, %v\n", len(resp.Payload)-1, time.Since(start).Round(time.Millisecond))
	for _, v := range []string{"U2F_V2", "FIDO_2_0", "FIDO_2_1"} {
		if contains(resp.Payload, v) {
			fmt.Println("  version:", v)
		}
	}
	return nil
}

// call sends one message and returns the reply on the same channel. It
// skips KEEPALIVE messages, as a CTAPHID client must.
func call(t transport, m ctaphid.Message) (*ctaphid.Message, error) {
	reports, err := ctaphid.Split(m)
	if err != nil {
		return nil, err
	}
	for _, r := range reports {
		if err := t.send(r); err != nil {
			return nil, fmt.Errorf("send: %w", err)
		}
	}
	var a ctaphid.Assembler
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r, err := t.recv(200 * time.Millisecond)
		if errors.Is(err, errTimeout) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("receive: %w", err)
		}
		if len(r) != ctaphid.ReportSize {
			return nil, fmt.Errorf("receive: %d bytes, want %d", len(r), ctaphid.ReportSize)
		}
		got, err := a.Add(r)
		if err != nil {
			return nil, err
		}
		if got == nil || got.CID != m.CID || got.Command == ctaphid.CmdKeepalive {
			continue
		}
		if got.Command == ctaphid.CmdError {
			return nil, fmt.Errorf("CTAPHID_ERROR % x", got.Payload)
		}
		return got, nil
	}
	return nil, errors.New("no reply in 5 s")
}

func contains(b []byte, s string) bool {
	for i := 0; i+len(s) <= len(b); i++ {
		if string(b[i:i+len(s)]) == s {
			return true
		}
	}
	return false
}
