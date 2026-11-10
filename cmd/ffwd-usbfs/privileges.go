// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// dropPrivileges switches to the user who ran sudo, when this process is
// root and SUDO_UID is set. The open key stays usable: usbfs checks
// access when the node is opened. Go sets the IDs of every thread.
func dropPrivileges() error {
	if os.Geteuid() != 0 {
		return nil
	}
	s := os.Getenv("SUDO_UID")
	if s == "" {
		logf("warning: running as root; ssh uses root's keys and known_hosts")
		return nil
	}
	uid, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("SUDO_UID %q: %w", s, err)
	}
	u, err := user.LookupId(s)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("gid %q: %w", u.Gid, err)
	}
	var groups []int
	if ids, err := u.GroupIds(); err == nil {
		for _, g := range ids {
			if n, err := strconv.Atoi(g); err == nil {
				groups = append(groups, n)
			}
		}
	}
	if err := syscall.Setgroups(groups); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("still root after setuid(%d)", uid)
	}
	os.Setenv("HOME", u.HomeDir)
	os.Setenv("USER", u.Username)
	os.Setenv("LOGNAME", u.Username)
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		logf("note: no ssh-agent (sudo removes SSH_AUTH_SOCK); use sudo --preserve-env=SSH_AUTH_SOCK to keep it")
	}
	logf("running as %s from now on", u.Username)
	return nil
}
