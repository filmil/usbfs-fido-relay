// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/filmil/yubikey-forward/usbfs"
)

// usbfsTransport talks to the FIDO interface through the key's usbfs node.
// The ChromeOS Linux container has no hidraw node, so this is the path
// that works there; it also works on any Linux host.
type usbfsTransport struct {
	h       *usbfs.Handle
	iface   byte
	in, out byte
}

func (t *usbfsTransport) send(r []byte) error {
	_, err := t.h.Interrupt(t.out, r, time.Second)
	return err
}

func (t *usbfsTransport) recv(timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 64)
	n, err := t.h.Interrupt(t.in, buf, timeout)
	if errors.Is(err, usbfs.ErrTimeout) {
		return nil, errTimeout
	}
	return buf[:n], err
}

func (t *usbfsTransport) close() error {
	rerr := t.h.Release(t.iface)
	if err := t.h.Reattach(t.iface); err != nil {
		fmt.Printf("interface %d: reattach failed: %v (unplug and share the key again)\n", t.iface, err)
	}
	cerr := t.h.Close()
	return errors.Join(rerr, cerr)
}

func findYubico() (string, error) {
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
	return "", fmt.Errorf("no Yubico device among %d usbfs nodes; on ChromeOS, is the key shared with Linux?", len(nodes))
}

func open(path string) (transport, error) {
	if path == "" {
		p, err := findYubico()
		if err != nil {
			return nil, err
		}
		path = p
	}
	fmt.Println("device:", path)
	h, err := usbfs.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	d, err := h.Descriptors()
	if err != nil {
		h.Close()
		return nil, err
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
			h.Close()
			return nil, fmt.Errorf("detach the kernel driver from interface %d: %w", it.Number, err)
		}
		fmt.Printf("interface %d: kernel driver detached\n", it.Number)
		if err := h.Claim(it.Number); err != nil {
			h.Reattach(it.Number)
			h.Close()
			return nil, fmt.Errorf("claim interface %d: %w", it.Number, err)
		}
		rd, err := h.ReportDescriptor(it.Number, it.ReportDescLn)
		if err == nil && usbfs.IsFIDOReport(rd) {
			fmt.Printf("interface %d: FIDO usage page 0xF1D0, endpoints in %02x out %02x\n", it.Number, in, out)
			return &usbfsTransport{h: h, iface: it.Number, in: in, out: out}, nil
		}
		h.Release(it.Number)
		h.Reattach(it.Number)
	}
	h.Close()
	return nil, errors.New("no FIDO HID interface found")
}
