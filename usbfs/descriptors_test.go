// SPDX-License-Identifier: Apache-2.0

package usbfs

import "testing"

// yubikey5 is the start of a YubiKey 5 NFC (1050:0407) as usbfs returns
// it: the device descriptor, then one configuration with an OTP keyboard
// interface (0), a FIDO interface (1) and a CCID interface (2).
// The bytes are built by hand from the descriptor layout in the USB 2.0
// specification, chapter 9, and the HID 1.11 specification, section 6.2.1.
var yubikey5 = []byte{
	// device: bLength 18, type 1, bcdUSB 2.0, class 0, maxpacket 64, VID 1050, PID 0407
	18, 1, 0x00, 0x02, 0, 0, 0, 64, 0x50, 0x10, 0x07, 0x04, 0x26, 0x05, 1, 2, 0, 1,
	// configuration: 3 interfaces
	9, 2, 0x5d, 0x00, 3, 1, 0, 0x80, 15,
	// interface 0: HID keyboard (OTP)
	9, 4, 0, 0, 1, 3, 1, 1, 0,
	9, 0x21, 0x11, 0x01, 0, 1, 0x22, 71, 0,
	7, 5, 0x81, 3, 8, 0, 10,
	// interface 1: HID, FIDO
	9, 4, 1, 0, 2, 3, 0, 0, 0,
	9, 0x21, 0x11, 0x01, 0, 1, 0x22, 34, 0,
	7, 5, 0x04, 3, 64, 0, 2,
	7, 5, 0x84, 3, 64, 0, 2,
	// interface 2: CCID
	9, 4, 2, 0, 3, 0x0B, 0, 0, 0,
	7, 5, 0x02, 2, 64, 0, 0,
	7, 5, 0x82, 2, 64, 0, 0,
	7, 5, 0x83, 3, 8, 0, 32,
}

func TestParseYubiKey(t *testing.T) {
	d, err := ParseDescriptors(yubikey5)
	if err != nil {
		t.Fatal(err)
	}
	if d.VendorID != 0x1050 || d.ProductID != 0x0407 {
		t.Fatalf("got %04x:%04x", d.VendorID, d.ProductID)
	}
	if len(d.Interfaces) != 3 {
		t.Fatalf("got %d interfaces", len(d.Interfaces))
	}
	hid := d.HIDInterfaces()
	if len(hid) != 2 || hid[1].Number != 1 || hid[1].ReportDescLn != 34 {
		t.Fatalf("HID interfaces: %+v", hid)
	}
	in, out, ok := hid[1].InterruptPair()
	if !ok || in != 0x84 || out != 0x04 {
		t.Fatalf("interrupt pair: in %02x out %02x ok %v", in, out, ok)
	}
	if _, _, ok := hid[0].InterruptPair(); ok {
		t.Fatal("the OTP keyboard has no interrupt OUT endpoint")
	}
	if d.Interfaces[2].Class != 0x0B {
		t.Fatalf("interface 2 class %02x, want CCID", d.Interfaces[2].Class)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := ParseDescriptors([]byte{1, 2, 3}); err == nil {
		t.Fatal("parsed a 3-byte buffer")
	}
	bad := append([]byte{}, yubikey5[:18]...)
	bad = append(bad, 0, 2) // a zero-length descriptor
	if _, err := ParseDescriptors(bad); err == nil {
		t.Fatal("parsed a zero-length descriptor")
	}
}

func TestIsFIDOReport(t *testing.T) {
	// The example report descriptor from CTAP 2.1, section 11.2.8.1.
	fido := []byte{
		0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
		0x09, 0x01, // Usage (U2F Authenticator Device)
		0xA1, 0x01, // Collection (Application)
		0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
		0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02,
		0xC0,
	}
	if !IsFIDOReport(fido) {
		t.Fatal("FIDO report descriptor not recognised")
	}
	keyboard := []byte{0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0xC0}
	if IsFIDOReport(keyboard) {
		t.Fatal("keyboard report descriptor recognised as FIDO")
	}
	if IsFIDOReport([]byte{0x06, 0xD0}) {
		t.Fatal("truncated item recognised")
	}
}

func TestIoctlNumbers(t *testing.T) {
	// The values that <linux/usbdevice_fs.h> gives on 64-bit Linux.
	for name, c := range map[string][2]uintptr{
		"CONTROL":          {ioControl, 0xC0185500},
		"BULK":             {ioBulk, 0xC0185502},
		"CLAIMINTERFACE":   {ioClaimInterface, 0x8004550F},
		"RELEASEINTERFACE": {ioReleaseInterface, 0x80045510},
		"IOCTL":            {ioIoctl, 0xC0105512},
		"DISCONNECT":       {ioDisconnect, 0x5516},
		"CONNECT":          {ioConnect, 0x5517},
	} {
		if c[0] != c[1] {
			t.Errorf("USBDEVFS_%s = %#x, want %#x", name, c[0], c[1])
		}
	}
}
