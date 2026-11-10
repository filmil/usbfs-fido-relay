// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/filmil/yubikey-forward/usbfs"
)

// usbfsTransport talks to the FIDO interface through the key's usbfs node.
// The ChromeOS Linux container has no hidraw node, so this is the path
// that works there; it also works on any Linux host.
type usbfsTransport struct{ k *usbfs.FIDOKey }

func (t usbfsTransport) send(r []byte) error { return t.k.Write(r) }

func (t usbfsTransport) recv(timeout time.Duration) ([]byte, error) {
	r, err := t.k.Read(timeout)
	if errors.Is(err, usbfs.ErrTimeout) {
		return nil, errTimeout
	}
	return r, err
}

func (t usbfsTransport) close() error { return t.k.Close() }

func open(path string) (transport, error) {
	if path == "" {
		p, err := usbfs.FindYubico()
		if err != nil {
			return nil, err
		}
		path = p
	}
	fmt.Println("device:", path)
	k, err := usbfs.OpenFIDO(path, func(f string, a ...any) { fmt.Printf(f+"\n", a...) })
	if err != nil {
		return nil, err
	}
	return usbfsTransport{k}, nil
}
