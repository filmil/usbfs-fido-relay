// SPDX-License-Identifier: Apache-2.0

// Package ctaphid splits CTAPHID messages into 64-byte HID reports and
// joins them again. It also classifies the CTAP2 command in a CBOR
// message, so that a relay can refuse dangerous commands.
//
// The packet layout is from the FIDO CTAP 2.1 specification, section
// 11.2.4 "Message and packet structure":
//
//	init packet:         CID(4) CMD(1, bit 7 set) BCNTH(1) BCNTL(1) DATA(57)
//	continuation packet: CID(4) SEQ(1, 0..0x7f)                      DATA(59)
package ctaphid

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ReportSize is the size of one HID report on a full-speed FIDO device.
const ReportSize = 64

const (
	initData = ReportSize - 7
	contData = ReportSize - 5
	// MaxMessage is the largest payload: one init packet and 128
	// continuation packets.
	MaxMessage = initData + 128*contData
)

// CTAPHID commands (CTAP 2.1, section 11.2.9).
const (
	CmdPing      byte = 0x81
	CmdMsg       byte = 0x83
	CmdLock      byte = 0x84
	CmdInit      byte = 0x86
	CmdWink      byte = 0x88
	CmdCBOR      byte = 0x90
	CmdCancel    byte = 0x91
	CmdKeepalive byte = 0xBB
	CmdError     byte = 0xBF
)

// BroadcastCID is the channel that CTAPHID_INIT uses to allocate a channel.
const BroadcastCID uint32 = 0xFFFFFFFF

// Message is one CTAPHID message on one channel.
type Message struct {
	CID     uint32
	Command byte
	Payload []byte
}

// Split returns the HID reports that carry m, each ReportSize bytes,
// padded with zeros.
func Split(m Message) ([][]byte, error) {
	if m.Command&0x80 == 0 {
		return nil, fmt.Errorf("command 0x%02x has bit 7 clear", m.Command)
	}
	if len(m.Payload) > MaxMessage {
		return nil, fmt.Errorf("payload of %d bytes is larger than %d", len(m.Payload), MaxMessage)
	}
	first := make([]byte, ReportSize)
	binary.BigEndian.PutUint32(first, m.CID)
	first[4] = m.Command
	binary.BigEndian.PutUint16(first[5:], uint16(len(m.Payload)))
	rest := m.Payload[copy(first[7:], m.Payload):]
	reports := [][]byte{first}
	for seq := byte(0); len(rest) > 0; seq++ {
		r := make([]byte, ReportSize)
		binary.BigEndian.PutUint32(r, m.CID)
		r[4] = seq
		rest = rest[copy(r[5:], rest):]
		reports = append(reports, r)
	}
	return reports, nil
}

// Assembler joins HID reports into messages. It follows one message at
// a time, as a CTAPHID device does.
type Assembler struct {
	msg     *Message
	want    int
	nextSeq byte
}

// ErrSequence means a continuation packet came out of order, or with no
// message in progress.
var ErrSequence = errors.New("ctaphid: continuation packet out of sequence")

// Add takes one report. It returns the message when the report completes
// it, and nil when more reports are needed.
func (a *Assembler) Add(report []byte) (*Message, error) {
	if len(report) != ReportSize {
		return nil, fmt.Errorf("report of %d bytes, want %d", len(report), ReportSize)
	}
	cid := binary.BigEndian.Uint32(report)
	if report[4]&0x80 != 0 {
		n := int(binary.BigEndian.Uint16(report[5:]))
		if n > MaxMessage {
			a.msg = nil
			return nil, fmt.Errorf("message of %d bytes is larger than %d", n, MaxMessage)
		}
		m := &Message{CID: cid, Command: report[4], Payload: make([]byte, 0, n)}
		m.Payload = append(m.Payload, report[7:7+min(n, initData)]...)
		if len(m.Payload) == n {
			a.msg = nil
			return m, nil
		}
		a.msg, a.want, a.nextSeq = m, n, 0
		return nil, nil
	}
	if a.msg == nil || cid != a.msg.CID || report[4] != a.nextSeq {
		a.msg = nil
		return nil, ErrSequence
	}
	take := min(a.want-len(a.msg.Payload), contData)
	a.msg.Payload = append(a.msg.Payload, report[5:5+take]...)
	a.nextSeq++
	if len(a.msg.Payload) == a.want {
		m := a.msg
		a.msg = nil
		return m, nil
	}
	return nil, nil
}

// CTAP2 authenticator commands, the first byte of a CTAPHID_CBOR payload
// (CTAP 2.1, section 6 "Authenticator API").
const (
	AuthMakeCredential       byte = 0x01
	AuthGetAssertion         byte = 0x02
	AuthGetInfo              byte = 0x04
	AuthClientPIN            byte = 0x06
	AuthReset                byte = 0x07
	AuthGetNextAssertion     byte = 0x08
	AuthBioEnrollment        byte = 0x09
	AuthCredentialManagement byte = 0x0A
	AuthSelection            byte = 0x0B
	AuthLargeBlobs           byte = 0x0C
	AuthConfig               byte = 0x0D
	AuthCredMgmtPreview      byte = 0x41
	AuthBioEnrollPreview     byte = 0x40
)

// Policy says which CTAP2 commands a relay passes to the real key.
type Policy struct {
	// AllowManagement passes commands that change or erase the key:
	// reset, credential management, bio enrollment, config, large blobs.
	AllowManagement bool
}

// Allowed reports whether the policy passes the message to the key.
// Only CTAPHID_CBOR messages are classified; all others pass, because
// they are framing (INIT, PING, CANCEL) or U2F (MSG), which cannot
// erase or list credentials.
func (p Policy) Allowed(m Message) bool {
	if m.Command != CmdCBOR || len(m.Payload) == 0 {
		return true
	}
	switch m.Payload[0] {
	case AuthMakeCredential, AuthGetAssertion, AuthGetInfo, AuthClientPIN,
		AuthGetNextAssertion, AuthSelection:
		return true
	case AuthReset, AuthCredentialManagement, AuthBioEnrollment, AuthConfig,
		AuthLargeBlobs, AuthCredMgmtPreview, AuthBioEnrollPreview:
		return p.AllowManagement
	default:
		// Unknown commands are refused: a newer key may define a
		// command this relay cannot judge.
		return false
	}
}
