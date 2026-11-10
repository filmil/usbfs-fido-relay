// SPDX-License-Identifier: Apache-2.0

// Command fido-probe checks, on the real Chromebook, whether a process in
// the Crostini container can reach a FIDO key's CTAPHID interface through
// the key's usbfs node. It changes nothing on the key: it sends
// CTAPHID_INIT and authenticatorGetInfo, which read only.
//
// Usage:
//
//	fido-probe [/dev/bus/usb/BBB/DDD]
//
// With no argument it looks for the first Yubico device (vendor 0x1050).
// While it runs, the kernel's HID driver is detached from the FIDO
// interface; it is attached again at the end.
package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/filmil/yubikey-forward/ctaphid"
	"github.com/filmil/yubikey-forward/usbfs"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("PASS: the FIDO interface works through usbfs")
}

func find() (string, error) {
	nodes, err := filepath.Glob("/dev/bus/usb/*/*")
	if err != nil {
		return "", err
	}
	for _, n := range nodes {
		h, err := usbfs.Open(n)
		if err != nil {
			continue
		}
		d, err := h.Descriptors()
		h.Close()
		if err == nil && d.VendorID == 0x1050 {
			return n, nil
		}
	}
	return "", fmt.Errorf("no Yubico device among %d usbfs nodes; is the key shared with Linux?", len(nodes))
}

func run(args []string) error {
	path := ""
	if len(args) > 0 {
		path = args[0]
	} else {
		p, err := find()
		if err != nil {
			return err
		}
		path = p
	}
	fmt.Println("device:", path)
	h, err := usbfs.Open(path)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer h.Close()
	d, err := h.Descriptors()
	if err != nil {
		return err
	}
	fmt.Printf("id: %04x:%04x, %d interfaces\n", d.VendorID, d.ProductID, len(d.Interfaces))
	for _, it := range d.Interfaces {
		fmt.Printf("  interface %d: class %02x, %d endpoints\n", it.Number, it.Class, len(it.Endpoints))
	}
	for _, it := range d.HIDInterfaces() {
		in, out, ok := it.InterruptPair()
		if !ok || it.ReportDescLn == 0 {
			continue
		}
		if err := h.Detach(it.Number); err != nil {
			return fmt.Errorf("detach the kernel driver from interface %d: %w", it.Number, err)
		}
		fmt.Printf("interface %d: kernel driver detached\n", it.Number)
		err := probe(h, it, in, out)
		if rerr := h.Reattach(it.Number); rerr != nil {
			fmt.Printf("interface %d: reattach failed: %v (unplug and share the key again)\n", it.Number, rerr)
		}
		if errors.Is(err, errNotFIDO) {
			continue
		}
		return err
	}
	return errors.New("no FIDO HID interface found")
}

var errNotFIDO = errors.New("not a FIDO interface")

func probe(h *usbfs.Handle, it usbfs.Interface, in, out byte) error {
	if err := h.Claim(it.Number); err != nil {
		return fmt.Errorf("claim interface %d: %w", it.Number, err)
	}
	defer h.Release(it.Number)
	rd, err := h.ReportDescriptor(it.Number, it.ReportDescLn)
	if err != nil {
		return err
	}
	if !usbfs.IsFIDOReport(rd) {
		return errNotFIDO
	}
	fmt.Printf("interface %d: FIDO usage page 0xF1D0, endpoints in %02x out %02x\n", it.Number, in, out)

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	start := time.Now()
	resp, err := call(h, in, out, ctaphid.Message{CID: ctaphid.BroadcastCID, Command: ctaphid.CmdInit, Payload: nonce})
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
	resp, err = call(h, in, out, ctaphid.Message{CID: cid, Command: ctaphid.CmdCBOR, Payload: []byte{ctaphid.AuthGetInfo}})
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
func call(h *usbfs.Handle, in, out byte, m ctaphid.Message) (*ctaphid.Message, error) {
	reports, err := ctaphid.Split(m)
	if err != nil {
		return nil, err
	}
	for _, r := range reports {
		if _, err := h.Interrupt(out, r, time.Second); err != nil {
			return nil, fmt.Errorf("interrupt OUT: %w", err)
		}
	}
	var a ctaphid.Assembler
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, ctaphid.ReportSize)
	for time.Now().Before(deadline) {
		n, err := h.Interrupt(in, buf, 200*time.Millisecond)
		if errors.Is(err, usbfs.ErrTimeout) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("interrupt IN: %w", err)
		}
		if n != ctaphid.ReportSize {
			return nil, fmt.Errorf("interrupt IN: %d bytes, want %d", n, ctaphid.ReportSize)
		}
		got, err := a.Add(append([]byte(nil), buf...))
		if err != nil {
			return nil, err
		}
		if got == nil || got.CID != m.CID {
			continue
		}
		if got.Command == ctaphid.CmdKeepalive {
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
