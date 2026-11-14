// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/filmil/usbfs-fido-relay/ctaphid"
)

// fakeKey records what the relay writes and answers from a queue.
type fakeKey struct {
	mu      sync.Mutex
	written [][]byte
	replies chan []byte
	readErr error
}

func newFakeKey() *fakeKey { return &fakeKey{replies: make(chan []byte, 16)} }

func (k *fakeKey) Write(r []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.written = append(k.written, append([]byte(nil), r...))
	return nil
}

func (k *fakeKey) Read(timeout time.Duration) ([]byte, error) {
	if k.readErr != nil {
		return nil, k.readErr
	}
	select {
	case r := <-k.replies:
		return r, nil
	case <-time.After(timeout):
		return nil, nil
	}
}

func (k *fakeKey) got() [][]byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([][]byte(nil), k.written...)
}

func packets(t *testing.T, cid uint32, cmd byte, payload []byte) [][]byte {
	t.Helper()
	r, err := ctaphid.Split(ctaphid.Message{CID: cid, Command: cmd, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// start runs the relay on one end of a pipe, does the marker exchange on
// the other end, and returns that end and the relay's result.
func start(t *testing.T, key Key, p ctaphid.Policy) (net.Conn, <-chan error) {
	t.Helper()
	far, near := net.Pipe()
	res := make(chan error, 1)
	go func() {
		err := Run(key, near, p, t.Logf)
		near.Close()
		res <- err
	}()
	if _, err := far.Write(Marker); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(Marker))
	if _, err := io.ReadFull(far, back); err != nil || !bytes.Equal(back, Marker) {
		t.Fatalf("marker back: %q, %v", back, err)
	}
	return far, res
}

func readReport(t *testing.T, c net.Conn) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	r := make([]byte, ctaphid.ReportSize)
	if _, err := io.ReadFull(c, r); err != nil {
		t.Fatalf("read report: %v", err)
	}
	return r
}

func finish(t *testing.T, far net.Conn, res <-chan error) {
	t.Helper()
	far.Close()
	select {
	case err := <-res:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not end after the far side closed")
	}
}

func isCancel(r []byte, cid uint32) bool {
	return binary.BigEndian.Uint32(r) == cid && r[4] == ctaphid.CmdCancel
}

func TestBadMarker(t *testing.T) {
	far, near := net.Pipe()
	res := make(chan error, 1)
	go func() { res <- Run(newFakeKey(), near, ctaphid.Policy{}, t.Logf) }()
	far.Write([]byte("Last "))
	if err := <-res; !errors.Is(err, ErrNotReady) {
		t.Fatalf("got %v, want ErrNotReady", err)
	}
}

func TestAllowedRequestReachesKey(t *testing.T) {
	key := newFakeKey()
	far, res := start(t, key, ctaphid.Policy{})
	const cid = 0x01020304
	req := packets(t, cid, ctaphid.CmdCBOR, []byte{ctaphid.AuthGetInfo})[0]
	far.Write(req)
	resp := packets(t, cid, ctaphid.CmdCBOR, []byte{0x00, 0xa1})[0]
	key.replies <- resp
	if got := readReport(t, far); !bytes.Equal(got, resp) {
		t.Fatalf("far side got %x, want the key's response", got)
	}
	finish(t, far, res)
	w := key.got()
	if len(w) != 2 || !bytes.Equal(w[0], req) || !isCancel(w[1], cid) {
		t.Fatalf("key got %x, want the request and then CANCEL", w)
	}
}

func TestResetIsRefused(t *testing.T) {
	key := newFakeKey()
	far, res := start(t, key, ctaphid.Policy{})
	const cid = 0x0a0b0c0d
	// A refused request of three packets: none may reach the key.
	payload := append([]byte{ctaphid.AuthReset}, make([]byte, 130)...)
	reqs := packets(t, cid, ctaphid.CmdCBOR, payload)
	if len(reqs) != 3 {
		t.Fatalf("test setup: %d packets", len(reqs))
	}
	go func() {
		for _, r := range reqs {
			far.Write(r)
		}
	}()
	got := readReport(t, far)
	want := packets(t, cid, ctaphid.CmdCBOR, []byte{ctaphid.StatusOperationDenied})[0]
	if !bytes.Equal(got, want) {
		t.Fatalf("far side got %x, want CTAP2_ERR_OPERATION_DENIED", got)
	}
	// The next request on the same channel passes again.
	time.Sleep(50 * time.Millisecond)
	ok := packets(t, cid, ctaphid.CmdCBOR, []byte{ctaphid.AuthGetInfo})[0]
	far.Write(ok)
	time.Sleep(50 * time.Millisecond)
	finish(t, far, res)
	w := key.got()
	if len(w) != 2 || !bytes.Equal(w[0], ok) || !isCancel(w[1], cid) {
		t.Fatalf("key got %x, want only getInfo and then CANCEL", w)
	}
}

func TestVendorCommandIsRefused(t *testing.T) {
	key := newFakeKey()
	far, res := start(t, key, ctaphid.Policy{})
	const cid = 0x11223344
	far.Write(packets(t, cid, 0xC2, []byte{1, 2, 3})[0])
	got := readReport(t, far)
	want := packets(t, cid, ctaphid.CmdError, []byte{ctaphid.ErrInvalidCmd})[0]
	if !bytes.Equal(got, want) {
		t.Fatalf("far side got %x, want CTAPHID_ERROR invalid command", got)
	}
	finish(t, far, res)
	if w := key.got(); len(w) != 1 || !isCancel(w[0], cid) {
		t.Fatalf("key got %x, want only CANCEL", w)
	}
}

func TestAllowManagementPassesReset(t *testing.T) {
	key := newFakeKey()
	far, res := start(t, key, ctaphid.Policy{AllowManagement: true})
	req := packets(t, 7, ctaphid.CmdCBOR, []byte{ctaphid.AuthReset})[0]
	far.Write(req)
	time.Sleep(50 * time.Millisecond)
	finish(t, far, res)
	if w := key.got(); len(w) == 0 || !bytes.Equal(w[0], req) {
		t.Fatalf("key got %x, want the reset request", w)
	}
}

func TestKeyErrorIsMarked(t *testing.T) {
	key := newFakeKey()
	key.readErr = errors.New("no such device")
	far, near := net.Pipe()
	res := make(chan error, 1)
	go func() { res <- Run(key, near, ctaphid.Policy{}, t.Logf) }()
	far.Write(Marker)
	io.ReadFull(far, make([]byte, len(Marker)))
	select {
	case err := <-res:
		if !errors.Is(err, ErrKey) {
			t.Fatalf("got %v, want an ErrKey error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not end after a key error")
	}
}
