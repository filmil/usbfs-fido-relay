// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"time"

	"rafaelmartins.com/p/usbhid"
)

// iokitTransport talks to the FIDO interface through IOKit. It opens the
// device without seizing it, so the Mac's own browser can keep using the
// key. rafaelmartins/usbhid calls IOKit through purego, so no cgo is needed.
type iokitTransport struct {
	d       *usbhid.Device
	reports chan []byte
	errs    chan error
}

func (t *iokitTransport) send(r []byte) error {
	// The FIDO report descriptor has no report ID, so the ID is 0.
	return t.d.SetOutputReport(0, r)
}

func (t *iokitTransport) recv(timeout time.Duration) ([]byte, error) {
	select {
	case r := <-t.reports:
		return r, nil
	case err := <-t.errs:
		return nil, err
	case <-time.After(timeout):
		return nil, errTimeout
	}
}

func (t *iokitTransport) close() error { return t.d.Close() }

func open(path string) (transport, error) {
	isFIDO := func(d *usbhid.Device) bool {
		return d.UsagePage() == 0xF1D0 && (path == "" || d.Path() == path)
	}
	devs, err := usbhid.Enumerate(isFIDO)
	if err != nil {
		return nil, fmt.Errorf("enumerate HID devices: %w", err)
	}
	if len(devs) == 0 {
		return nil, errors.New("no FIDO HID device (usage page 0xF1D0) found")
	}
	d := devs[0]
	for _, c := range devs {
		if c.VendorId() == 0x1050 {
			d = c
			break
		}
	}
	fmt.Printf("device: %s (%04x:%04x, %s)\n", d.Path(), d.VendorId(), d.ProductId(), d.Product())
	if err := d.Open(false); err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	t := &iokitTransport{d: d, reports: make(chan []byte, 16), errs: make(chan error, 1)}
	// GetInputReport blocks until a report arrives, so one goroutine reads
	// and recv waits on the channel with a timeout. The goroutine ends when
	// close makes GetInputReport fail.
	go func() {
		for {
			_, r, err := d.GetInputReport()
			if err != nil {
				t.errs <- err
				return
			}
			t.reports <- r
		}
	}()
	return t, nil
}
