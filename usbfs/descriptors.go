// SPDX-License-Identifier: Apache-2.0

// Package usbfs talks to a USB device through its usbfs node,
// /dev/bus/usb/BBB/DDD, with no libusb and no cgo.
//
// Crostini's container gets a shared USB device only as its usbfs node.
// It gets no /dev/hidraw node, so a FIDO key must be reached here.
package usbfs

import (
	"encoding/binary"
	"fmt"
)

// Endpoint is one endpoint of an interface.
type Endpoint struct {
	Address      byte // bit 7 set means IN
	Attributes   byte // bits 0..1: 0 control, 1 isochronous, 2 bulk, 3 interrupt
	MaxPacket    uint16
	IntervalMsec byte
}

// In reports whether data flows from the device to the host.
func (e Endpoint) In() bool { return e.Address&0x80 != 0 }

// Interrupt reports whether the endpoint is an interrupt endpoint.
func (e Endpoint) Interrupt() bool { return e.Attributes&0x03 == 3 }

// Interface is one interface (alternate setting 0) of the active
// configuration.
type Interface struct {
	Number       byte
	Class        byte // 3 is HID, 0x0B is CCID (smart card)
	SubClass     byte
	Protocol     byte
	ReportDescLn uint16 // HID only: length of the report descriptor
	Endpoints    []Endpoint
}

// Device is what the usbfs node's descriptors say about the device.
type Device struct {
	VendorID   uint16
	ProductID  uint16
	Interfaces []Interface
}

const (
	descDevice    = 1
	descConfig    = 2
	descInterface = 4
	descEndpoint  = 5
	descHID       = 0x21
	descReport    = 0x22
)

// ParseDescriptors parses the bytes that a read of a usbfs node returns:
// the device descriptor, then the configuration descriptors.
// Only the first configuration is read.
func ParseDescriptors(b []byte) (*Device, error) {
	if len(b) < 18 || b[1] != descDevice {
		return nil, fmt.Errorf("no device descriptor in %d bytes", len(b))
	}
	d := &Device{
		VendorID:  binary.LittleEndian.Uint16(b[8:]),
		ProductID: binary.LittleEndian.Uint16(b[10:]),
	}
	var cur *Interface
	configs := 0
	for i := int(b[0]); i+2 <= len(b); {
		n, t := int(b[i]), b[i+1]
		if n < 2 || i+n > len(b) {
			return nil, fmt.Errorf("bad descriptor length %d at offset %d", n, i)
		}
		p := b[i : i+n]
		switch t {
		case descConfig:
			configs++
			if configs > 1 {
				return d, nil
			}
		case descInterface:
			if n < 9 {
				return nil, fmt.Errorf("short interface descriptor at offset %d", i)
			}
			cur = nil
			if p[3] == 0 { // alternate setting 0 only
				d.Interfaces = append(d.Interfaces, Interface{Number: p[2], Class: p[5], SubClass: p[6], Protocol: p[7]})
				cur = &d.Interfaces[len(d.Interfaces)-1]
			}
		case descHID:
			if cur != nil && n >= 9 && p[6] == descReport {
				cur.ReportDescLn = binary.LittleEndian.Uint16(p[7:])
			}
		case descEndpoint:
			if cur != nil && n >= 7 {
				cur.Endpoints = append(cur.Endpoints, Endpoint{
					Address: p[2], Attributes: p[3],
					MaxPacket:    binary.LittleEndian.Uint16(p[4:]),
					IntervalMsec: p[6],
				})
			}
		}
		i += n
	}
	return d, nil
}

// IsFIDOReport reports whether a HID report descriptor declares the FIDO
// usage page 0xF1D0 (CTAP 2.1, section 11.2.8.1).
func IsFIDOReport(r []byte) bool {
	for i := 0; i < len(r); {
		prefix := r[i]
		if prefix == 0xFE { // long item: data size in the next byte
			if i+1 >= len(r) {
				return false
			}
			i += 3 + int(r[i+1])
			continue
		}
		size := int(prefix & 0x03)
		if size == 3 {
			size = 4
		}
		if i+1+size > len(r) {
			return false
		}
		// Global item "Usage Page" is tag 0, type 1: prefix 0b0000_01ss.
		if prefix&0xFC == 0x04 && size == 2 && binary.LittleEndian.Uint16(r[i+1:]) == 0xF1D0 {
			return true
		}
		i += 1 + size
	}
	return false
}

// HIDInterfaces returns the HID interfaces. A FIDO interface among them
// has one interrupt IN and one interrupt OUT endpoint.
// The caller still checks the report descriptor with IsFIDOReport.
func (d *Device) HIDInterfaces() []Interface {
	var out []Interface
	for _, it := range d.Interfaces {
		if it.Class == 3 {
			out = append(out, it)
		}
	}
	return out
}

// InterruptPair returns the interrupt IN and OUT endpoint addresses.
func (it Interface) InterruptPair() (in, out byte, ok bool) {
	var hasIn, hasOut bool
	for _, e := range it.Endpoints {
		if !e.Interrupt() {
			continue
		}
		if e.In() && !hasIn {
			in, hasIn = e.Address, true
		} else if !e.In() && !hasOut {
			out, hasOut = e.Address, true
		}
	}
	return in, out, hasIn && hasOut
}
