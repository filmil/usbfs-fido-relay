// SPDX-License-Identifier: Apache-2.0

package ctaphid

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, initData, initData + 1, initData + contData, 1000, MaxMessage} {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i * 7)
		}
		in := Message{CID: 0x01020304, Command: CmdCBOR, Payload: payload}
		reports, err := Split(in)
		if err != nil {
			t.Fatalf("Split(%d bytes): %v", n, err)
		}
		var a Assembler
		var out *Message
		for i, r := range reports {
			if len(r) != ReportSize {
				t.Fatalf("report %d has %d bytes", i, len(r))
			}
			m, err := a.Add(r)
			if err != nil {
				t.Fatalf("Add report %d of %d: %v", i, len(reports), err)
			}
			if m != nil && i != len(reports)-1 {
				t.Fatalf("message complete after report %d of %d", i, len(reports))
			}
			out = m
		}
		if out == nil || out.CID != in.CID || out.Command != in.Command || !bytes.Equal(out.Payload, payload) {
			t.Fatalf("%d bytes: round trip mismatch", n)
		}
	}
}

func TestTooLarge(t *testing.T) {
	if _, err := Split(Message{CID: 1, Command: CmdCBOR, Payload: make([]byte, MaxMessage+1)}); err == nil {
		t.Fatal("Split accepted an oversized payload")
	}
}

func TestOutOfSequence(t *testing.T) {
	reports, err := Split(Message{CID: 9, Command: CmdMsg, Payload: make([]byte, 200)})
	if err != nil {
		t.Fatal(err)
	}
	var a Assembler
	if _, err := a.Add(reports[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add(reports[2]); err != ErrSequence {
		t.Fatalf("got %v, want ErrSequence", err)
	}
}

func TestPolicy(t *testing.T) {
	cbor := func(cmd byte) Message { return Message{Command: CmdCBOR, Payload: []byte{cmd}} }
	strict := Policy{}
	for _, c := range []byte{AuthMakeCredential, AuthGetAssertion, AuthGetInfo, AuthClientPIN, AuthGetNextAssertion, AuthSelection} {
		if !strict.Allowed(cbor(c)) {
			t.Errorf("command 0x%02x refused", c)
		}
	}
	for _, c := range []byte{AuthReset, AuthCredentialManagement, AuthBioEnrollment, AuthConfig, AuthLargeBlobs, 0x55} {
		if strict.Allowed(cbor(c)) {
			t.Errorf("command 0x%02x passed", c)
		}
	}
	if !(Policy{AllowManagement: true}).Allowed(cbor(AuthReset)) {
		t.Error("AllowManagement did not pass reset")
	}
	if !strict.Allowed(Message{Command: CmdInit, Payload: make([]byte, 8)}) {
		t.Error("INIT refused")
	}
}
