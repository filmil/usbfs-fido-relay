// SPDX-License-Identifier: Apache-2.0

package usbfs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The usbfs ioctls, from <linux/usbdevice_fs.h>. The structures match the
// kernel's layout on 64-bit Linux (amd64 and arm64).
type ctrlTransfer struct {
	RequestType byte
	Request     byte
	Value       uint16
	Index       uint16
	Length      uint16
	Timeout     uint32 // milliseconds
	_           uint32
	Data        uintptr
}

type bulkTransfer struct {
	Endpoint uint32
	Length   uint32
	Timeout  uint32 // milliseconds
	_        uint32
	Data     uintptr
}

type ioctlArg struct {
	Interface int32
	Code      int32
	Data      uintptr
}

func ioc(dir, nr, size uintptr) uintptr { return dir<<30 | size<<16 | 'U'<<8 | nr }

var (
	ioControl          = ioc(3, 0, unsafe.Sizeof(ctrlTransfer{}))
	ioBulk             = ioc(3, 2, unsafe.Sizeof(bulkTransfer{}))
	ioClaimInterface   = ioc(2, 15, 4)
	ioReleaseInterface = ioc(2, 16, 4)
	ioIoctl            = ioc(3, 18, unsafe.Sizeof(ioctlArg{}))
	ioDisconnect       = ioc(0, 22, 0)
	ioConnect          = ioc(0, 23, 0)
)

// ErrTimeout means a transfer did not finish in time. On an interrupt IN
// endpoint it only means the device had nothing to send.
var ErrTimeout = errors.New("usbfs: transfer timed out")

// Handle is an open usbfs node.
type Handle struct {
	f *os.File
}

// Open opens a usbfs node, such as /dev/bus/usb/001/004.
func Open(path string) (*Handle, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &Handle{f: f}, nil
}

// Close closes the node. The kernel releases claimed interfaces.
func (h *Handle) Close() error { return h.f.Close() }

// Descriptors returns the device and configuration descriptors.
func (h *Handle) Descriptors() (*Device, error) {
	if _, err := h.f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(h.f, 4096))
	if err != nil {
		return nil, fmt.Errorf("read descriptors: %w", err)
	}
	return ParseDescriptors(b)
}

func (h *Handle) ioctl(code uintptr, arg unsafe.Pointer) (int, error) {
	r, _, e := unix.Syscall(unix.SYS_IOCTL, h.f.Fd(), code, uintptr(arg))
	if e != 0 {
		return int(r), e
	}
	return int(r), nil
}

// Detach unbinds the kernel driver (usbhid) from an interface. It
// returns nil when no driver was bound.
func (h *Handle) Detach(iface byte) error {
	a := ioctlArg{Interface: int32(iface), Code: int32(ioDisconnect)}
	_, err := h.ioctl(ioIoctl, unsafe.Pointer(&a))
	if errors.Is(err, unix.ENODATA) {
		return nil
	}
	return err
}

// Reattach binds the kernel driver to an interface again.
func (h *Handle) Reattach(iface byte) error {
	a := ioctlArg{Interface: int32(iface), Code: int32(ioConnect)}
	_, err := h.ioctl(ioIoctl, unsafe.Pointer(&a))
	return err
}

// Claim claims an interface for this process.
func (h *Handle) Claim(iface byte) error {
	n := uint32(iface)
	_, err := h.ioctl(ioClaimInterface, unsafe.Pointer(&n))
	return err
}

// Release releases a claimed interface.
func (h *Handle) Release(iface byte) error {
	n := uint32(iface)
	_, err := h.ioctl(ioReleaseInterface, unsafe.Pointer(&n))
	return err
}

// ReportDescriptor reads the HID report descriptor of an interface.
func (h *Handle) ReportDescriptor(iface byte, length uint16) ([]byte, error) {
	buf := make([]byte, length)
	c := ctrlTransfer{
		RequestType: 0x81, // IN, standard, interface
		Request:     6,    // GET_DESCRIPTOR
		Value:       descReport << 8,
		Index:       uint16(iface),
		Length:      length,
		Timeout:     1000,
		Data:        uintptr(unsafe.Pointer(&buf[0])),
	}
	n, err := h.ioctl(ioControl, unsafe.Pointer(&c))
	if err != nil {
		return nil, fmt.Errorf("GET_DESCRIPTOR(report): %w", err)
	}
	return buf[:n], nil
}

// Interrupt runs one transfer on an interrupt endpoint. For an OUT
// endpoint it sends buf; for an IN endpoint it fills buf. The usbfs bulk
// ioctl also serves interrupt endpoints.
func (h *Handle) Interrupt(ep byte, buf []byte, timeout time.Duration) (int, error) {
	b := bulkTransfer{
		Endpoint: uint32(ep),
		Length:   uint32(len(buf)),
		Timeout:  uint32(timeout.Milliseconds()),
		Data:     uintptr(unsafe.Pointer(&buf[0])),
	}
	n, err := h.ioctl(ioBulk, unsafe.Pointer(&b))
	if errors.Is(err, unix.ETIMEDOUT) {
		return 0, ErrTimeout
	}
	return n, err
}
