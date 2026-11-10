// SPDX-License-Identifier: Apache-2.0

// Command ffwd-usbfs forwards the FIDO interface of a key to a remote
// Linux host over SSH. It is the key side of fido-forward
// (github.com/txomon/fido-forward) for a machine where the key has a
// usbfs node and no hidraw node, such as the ChromeOS Linux container.
// The remote host runs fido-forward's sink, unchanged.
//
//	ffwd-usbfs [-d /dev/bus/usb/BBB/DDD] [--allow-management] HOST
//
// Exit codes, as fido-forward: 0 clean end, 1 relay or transport
// failure, 2 usage, 3 key or permission error.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/filmil/yubikey-forward/ctaphid"
	"github.com/filmil/yubikey-forward/relay"
	"github.com/filmil/yubikey-forward/usbfs"
)

// keyIO adapts the usbfs key to relay.Key: a read that times out
// returns no report and no error.
type keyIO struct{ k *usbfs.FIDOKey }

func (k keyIO) Write(r []byte) error { return k.k.Write(r) }

func (k keyIO) Read(timeout time.Duration) ([]byte, error) {
	r, err := k.k.Read(timeout)
	if errors.Is(err, usbfs.ErrTimeout) {
		return nil, nil
	}
	return r, err
}

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, "local: "+format+"\n", a...) }

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("ffwd-usbfs", flag.ContinueOnError)
	device := fs.String("d", "", "usbfs node of the key (default: the first Yubico key)")
	manage := fs.Bool("allow-management", false, "also pass commands that change or erase the key (reset, credential management, config, vendor commands)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ffwd-usbfs [-d /dev/bus/usb/BBB/DDD] [--allow-management] HOST")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		if err == nil {
			fs.Usage()
		}
		return 2
	}
	host := fs.Arg(0)

	path := *device
	if path == "" {
		p, err := usbfs.FindYubico()
		if err != nil {
			logf("%v", err)
			return 3
		}
		path = p
	}
	logf("device: %s", path)
	key, err := usbfs.OpenFIDO(path, logf)
	if err != nil {
		logf("%v", err)
		return 3
	}
	defer func() {
		if err := key.Close(); err != nil {
			logf("%v", err)
		} else {
			logf("key given back to the system")
		}
	}()

	// Under sudo, keep the open key and give up root before ssh starts,
	// so that ssh uses the user's keys and nothing from the network is
	// handled as root.
	if err := dropPrivileges(); err != nil {
		logf("drop privileges: %v", err)
		return 3
	}

	remote := "fido-forward"
	if r := os.Getenv("FIDO_FORWARD_REMOTE"); r != "" {
		remote = r
	}
	sshBin := "ssh"
	if s := os.Getenv("FIDO_FORWARD_SSH"); s != "" {
		sshBin = s
	}
	// ClearAllForwardings: the relay's connection must not take the
	// port forwards that ~/.ssh/config sets for HOST. Otherwise a second
	// ssh to HOST cannot bind them while the relay runs, and with
	// ExitOnForwardFailure it fails.
	ssh := exec.Command(sshBin, "-T", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3", "-o", "ClearAllForwardings=yes", "--", host, remote+" --sink")
	ssh.Stderr = os.Stderr
	in, err := ssh.StdinPipe()
	if err != nil {
		logf("%v", err)
		return 1
	}
	out, err := ssh.StdoutPipe()
	if err != nil {
		logf("%v", err)
		return 1
	}

	// Ctrl-C goes to ssh too and ends the session; the relay then
	// cancels and gives the key back. SIGTERM reaches only this process,
	// so it stops ssh.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	if err := ssh.Start(); err != nil {
		logf("start ssh: %v", err)
		return 1
	}
	go func() {
		s := <-sigs
		if s != os.Interrupt {
			ssh.Process.Signal(syscall.SIGTERM)
		}
	}()

	conn := struct {
		io.Reader
		io.Writer
	}{out, in}
	policy := ctaphid.Policy{AllowManagement: *manage}
	if *manage {
		logf("warning: --allow-management passes commands that can erase the key")
	}
	rerr := relay.Run(keyIO{key}, conn, policy, logf)
	in.Close()
	waited := make(chan error, 1)
	go func() { waited <- ssh.Wait() }()
	var serr error
	select {
	case serr = <-waited:
	case <-time.After(5 * time.Second):
		ssh.Process.Kill()
		serr = <-waited
	}

	switch {
	case errors.Is(rerr, relay.ErrKey):
		logf("%v", rerr)
		return 3
	case rerr != nil:
		logf("%v", rerr)
		return 1
	case serr != nil:
		// The relay ended cleanly but ssh failed: a dropped connection
		// or a sink that could not start.
		logf("ssh: %v", serr)
		return 1
	}
	return 0
}
