// SPDX-License-Identifier: Apache-2.0

// Package relay is the key side of fido-forward's wire protocol, version
// 1. It moves CTAPHID reports between a key and fido-forward's sink on
// the far host, and refuses the requests that a ctaphid.Policy does not
// pass.
//
// The wire protocol is from fido-forward's docs/REQUIREMENTS.md, "Wire
// protocol", at commit 2b7b2ac: the sink writes the 5-byte marker
// "FFWD\x01", the key side reads it and writes it back, and then both
// sides send raw 64-byte reports with no framing. Reports from the far
// side are requests; reports to it are responses.
package relay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/filmil/yubikey-forward/ctaphid"
)

// Marker is the 5-byte greeting of fido-forward's wire protocol v1.
var Marker = []byte("FFWD\x01")

// Key is the real key: one FIDO HID interface.
type Key interface {
	// Write sends one 64-byte report.
	Write(r []byte) error
	// Read waits up to timeout for one report. It returns (nil, nil)
	// when none came.
	Read(timeout time.Duration) ([]byte, error)
}

// ErrKey marks an error that came from the key, not from the far side.
var ErrKey = errors.New("key")

// ErrNotReady means the far side did not start with the marker: the
// sink did not start, or a shell startup file wrote to stdout.
var ErrNotReady = errors.New("sink not ready")

// poll is how long one read from the key waits. It bounds how long Run
// takes to notice the end of the session.
const poll = 200 * time.Millisecond

// Run relays between key and conn until conn ends or an error occurs.
// A clean end of conn returns nil. Before it returns, Run sends
// CTAPHID_CANCEL to the key on every channel that the far side used.
// The caller must then close conn and the key.
func Run(key Key, conn io.ReadWriter, p ctaphid.Policy, logf func(string, ...any)) error {
	got := make([]byte, len(Marker))
	if n, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, Marker) {
		return fmt.Errorf("%w: got %q (%v)", ErrNotReady, got[:n], err)
	}
	if _, err := conn.Write(Marker); err != nil {
		return fmt.Errorf("write marker: %w", err)
	}
	logf("relaying")

	r := &run{key: key, conn: conn, f: newFilter(p, logf), done: make(chan struct{})}
	errc := make(chan error, 2)
	fromKeyDone := make(chan struct{})
	go func() { errc <- r.fromFar() }()
	go func() { errc <- r.fromKey(); close(fromKeyDone) }()

	err := <-errc
	if errors.Is(err, io.EOF) {
		err = nil
	}
	close(r.done)
	r.keyMu.Lock()
	r.stopped = true
	r.keyMu.Unlock()
	// The key loop ends within one poll, unless it is blocked writing to
	// conn; the caller's close of conn releases that.
	select {
	case <-fromKeyDone:
	case <-time.After(2 * poll):
	}
	var cerr error
	for _, cid := range r.f.channels() {
		c := make([]byte, ctaphid.ReportSize)
		binary.BigEndian.PutUint32(c, cid)
		c[4] = ctaphid.CmdCancel
		r.keyMu.Lock()
		if werr := key.Write(c); werr != nil {
			cerr = errors.Join(cerr, fmt.Errorf("%w: cancel channel %08x: %v", ErrKey, cid, werr))
		}
		r.keyMu.Unlock()
	}
	return errors.Join(err, cerr)
}

type run struct {
	key  Key
	conn io.ReadWriter
	f    *filter
	done chan struct{}

	keyMu   sync.Mutex
	stopped bool
	connMu  sync.Mutex
}

func (r *run) writeConn(p []byte) error {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	_, err := r.conn.Write(p)
	return err
}

// fromFar reads requests and passes the allowed ones to the key.
func (r *run) fromFar() error {
	p := make([]byte, ctaphid.ReportSize)
	for {
		n, err := io.ReadFull(r.conn, p)
		if err == io.EOF {
			return io.EOF
		}
		if err != nil {
			return fmt.Errorf("read from far side after %d bytes of a report: %w", n, err)
		}
		forward, reply := r.f.request(p)
		for _, q := range reply {
			if err := r.writeConn(q); err != nil {
				return fmt.Errorf("write to far side: %w", err)
			}
		}
		if !forward {
			continue
		}
		r.keyMu.Lock()
		if r.stopped {
			r.keyMu.Unlock()
			return nil
		}
		err = r.key.Write(p)
		r.keyMu.Unlock()
		if err != nil {
			return fmt.Errorf("%w: write: %v", ErrKey, err)
		}
	}
}

// fromKey passes every response from the key to the far side. The relay
// holds the key's FIDO interface alone, so every response belongs to it.
func (r *run) fromKey() error {
	for {
		select {
		case <-r.done:
			return nil
		default:
		}
		p, err := r.key.Read(poll)
		if err != nil {
			return fmt.Errorf("%w: read: %v", ErrKey, err)
		}
		if p == nil {
			continue
		}
		if len(p) != ctaphid.ReportSize {
			return fmt.Errorf("%w: a %d-byte report, want %d", ErrKey, len(p), ctaphid.ReportSize)
		}
		if err := r.writeConn(p); err != nil {
			return fmt.Errorf("write to far side: %w", err)
		}
	}
}

// filter applies the policy to requests, one packet at a time. It needs
// no reassembly: the policy looks only at the command and the first
// payload byte, and both are in the init packet. After it refuses an
// init packet, it drops the continuation packets on that channel.
type filter struct {
	p        ctaphid.Policy
	logf     func(string, ...any)
	mu       sync.Mutex
	dropping map[uint32]bool
	seen     map[uint32]bool
}

func newFilter(p ctaphid.Policy, logf func(string, ...any)) *filter {
	return &filter{p: p, logf: logf, dropping: map[uint32]bool{}, seen: map[uint32]bool{}}
}

// request decides about one request packet. It returns whether to pass
// it to the key, and the reports to send back in its place.
func (f *filter) request(p []byte) (forward bool, reply [][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cid := binary.BigEndian.Uint32(p)
	if cid != ctaphid.BroadcastCID {
		f.seen[cid] = true
	}
	if p[4]&0x80 == 0 {
		return !f.dropping[cid], nil
	}
	n := int(binary.BigEndian.Uint16(p[5:]))
	m := ctaphid.Message{CID: cid, Command: p[4], Payload: p[7 : 7+min(n, ctaphid.ReportSize-7)]}
	if f.p.Allowed(m) {
		f.dropping[cid] = false
		return true, nil
	}
	f.dropping[cid] = true
	var answer ctaphid.Message
	if m.Command == ctaphid.CmdCBOR {
		answer = ctaphid.Message{CID: cid, Command: ctaphid.CmdCBOR, Payload: []byte{ctaphid.StatusOperationDenied}}
		f.logf("refused CTAP2 command 0x%02x on channel %08x", m.Payload[0], cid)
	} else {
		answer = ctaphid.Message{CID: cid, Command: ctaphid.CmdError, Payload: []byte{ctaphid.ErrInvalidCmd}}
		f.logf("refused CTAPHID command 0x%02x on channel %08x", m.Command, cid)
	}
	reply, _ = ctaphid.Split(answer)
	return false, reply
}

// channels returns the channels the far side used, for teardown.
func (f *filter) channels() []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []uint32
	for c := range f.seen {
		out = append(out, c)
	}
	return out
}
