// SPDX-License-Identifier: Apache-2.0

package usbfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// YubicoVendorID is the USB vendor ID of Yubico.
const YubicoVendorID = 0x1050

// FIDOKey is the FIDO HID interface of a key, claimed through usbfs.
// The kernel driver is detached from that interface while the FIDOKey is
// open. Other interfaces of the key (OTP, CCID) are not touched.
type FIDOKey struct {
	h       *Handle
	iface   byte
	in, out byte
}

// Write sends one 64-byte report to the key.
func (k *FIDOKey) Write(r []byte) error {
	_, err := k.h.Interrupt(k.out, r, time.Second)
	return err
}

// Read waits up to timeout for one report from the key. It returns
// ErrTimeout when none came.
func (k *FIDOKey) Read(timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 64)
	n, err := k.h.Interrupt(k.in, buf, timeout)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// Close releases the interface and attaches the kernel driver again, so
// that ChromeOS or the host can use the key.
func (k *FIDOKey) Close() error {
	rerr := k.h.Release(k.iface)
	aerr := k.h.Reattach(k.iface)
	if aerr != nil {
		aerr = fmt.Errorf("attach the kernel driver to interface %d again (unplug the key to recover): %w", k.iface, aerr)
	}
	return errors.Join(rerr, aerr, k.h.Close())
}

// FindYubico returns the usbfs node of the first Yubico device.
func FindYubico() (string, error) {
	nodes, err := filepath.Glob("/dev/bus/usb/*/*")
	if err != nil {
		return "", err
	}
	var denied []string
	for _, n := range nodes {
		h, err := Open(n)
		if errors.Is(err, os.ErrPermission) {
			// On ChromeOS the shared node is 0664 root:root.
			denied = append(denied, n)
			continue
		}
		if err != nil {
			continue
		}
		d, err := h.Descriptors()
		h.Close()
		if err == nil && d.VendorID == YubicoVendorID {
			return n, nil
		}
	}
	if len(denied) > 0 {
		return "", fmt.Errorf("no Yubico device found, and no permission to open %v; run with sudo, or name the device", denied)
	}
	return "", fmt.Errorf("no Yubico device among %d usbfs nodes; on ChromeOS, is the key shared with Linux?", len(nodes))
}

// OpenFIDO opens the usbfs node at path and claims the key's FIDO HID
// interface: the HID interface whose report descriptor has usage page
// 0xF1D0. It reports each step through logf.
func OpenFIDO(path string, logf func(string, ...any)) (*FIDOKey, error) {
	h, err := Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	d, err := h.Descriptors()
	if err != nil {
		h.Close()
		return nil, err
	}
	logf("id: %04x:%04x, %d interfaces", d.VendorID, d.ProductID, len(d.Interfaces))
	for _, it := range d.Interfaces {
		logf("  interface %d: class %02x, %d endpoints", it.Number, it.Class, len(it.Endpoints))
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
		logf("interface %d: kernel driver detached", it.Number)
		if err := h.Claim(it.Number); err != nil {
			h.Reattach(it.Number)
			h.Close()
			return nil, fmt.Errorf("claim interface %d: %w", it.Number, err)
		}
		rd, err := h.ReportDescriptor(it.Number, it.ReportDescLn)
		if err == nil && IsFIDOReport(rd) {
			logf("interface %d: FIDO usage page 0xF1D0, endpoints in %02x out %02x", it.Number, in, out)
			return &FIDOKey{h: h, iface: it.Number, in: in, out: out}, nil
		}
		h.Release(it.Number)
		h.Reattach(it.Number)
	}
	h.Close()
	return nil, errors.New("no FIDO HID interface found")
}
