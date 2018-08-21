// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package sophie
Sophie - Golang Sophie protocol implementation
*/
package sophie

import (
	"go/build"
	"net"
	"os"
	"path"
	"testing"
	"time"
)

func TestBasics(t *testing.T) {
	// Test Non existent socket
	_, e := NewClient("unix", "/tmp/.dumx.sock")
	if e == nil {
		t.Errorf("An error should be returned as sock does not exist")
	} else {
		expected := "The unix socket: /tmp/.dumx.sock does not exist"
		if e.Error() != expected {
			t.Errorf("Expected %q want %q", expected, e)
		}
	}
	// Test defaults
	_, e = NewClient("", "")
	if e == nil {
		t.Errorf("An error should be returned as sock does not exist")
	} else {
		expected := "The unix socket: /var/lib/savdid/savdid.sock does not exist"
		if e.Error() != expected {
			t.Errorf("Got %q want %q", expected, e)
		}
	}
	// Test udp
	_, e = NewClient("udp", "127.1.1.1:4010")
	if e == nil {
		t.Errorf("Expected an error got nil")
	} else {
		expected := "Protocol: udp is not supported"
		if e.Error() != expected {
			t.Errorf("Got %q want %q", expected, e)
		}
	}
	// Test tcp
	network := "tcp"
	address := "127.1.1.1:4010"
	c, e := NewClient(network, address)
	if e != nil {
		t.Errorf("An error should not be returned")
	} else {
		if c.network != network {
			t.Errorf("Got %q want %q", c.network, network)
		}
		if c.address != address {
			t.Errorf("Got %q want %q", c.address, address)
		}
	}
}

func TestSettings(t *testing.T) {
	var e error
	var c *Client
	network := "tcp"
	address := "127.1.1.1:4010"
	if c, e = NewClient(network, address); e != nil {
		t.Errorf("An error should not be returned")
	}
	if c.connTimeout != defaultTimeout {
		t.Errorf("The default conn timeout should be set")
	}
	if c.connSleep != defaultSleep {
		t.Errorf("The default conn sleep should be set")
	}
	if c.connRetries != 0 {
		t.Errorf("The default conn retries should be set")
	}
	expected := 2 * time.Second
	c.SetConnTimeout(expected)
	if c.connTimeout != expected {
		t.Errorf("Calling c.SetConnTimeout(%q) failed", expected)
	}
	c.SetCmdTimeout(expected)
	if c.cmdTimeout != expected {
		t.Errorf("Calling c.SetCmdTimeout(%q) failed", expected)
	}
	c.SetConnSleep(expected)
	if c.connSleep != expected {
		t.Errorf("Calling c.SetConnSleep(%q) failed", expected)
	}
	c.SetConnRetries(2)
	if c.connRetries != 2 {
		t.Errorf("Calling c.SetConnRetries(%q) failed", 2)
	}
	c.SetConnRetries(-2)
	if c.connRetries != 0 {
		t.Errorf("Preventing negative values in c.SetConnRetries(%q) failed", -2)
	}
}

func TestMethodsErrors(t *testing.T) {
	var e error
	var c *Client
	network := "tcp"
	address := "127.1.1.1:4010"
	if c, e = NewClient(network, address); e != nil {
		t.Errorf("An error should not be returned")
	}
	c.SetConnTimeout(500 * time.Microsecond)
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}
	fn := path.Join(gopath, "src/github.com/baruwa-enterprise/sophie/examples/data/eicar.txt")
	if _, e = c.Scan(fn); e == nil {
		t.Errorf("An error should be returned")
	} else {
		if _, ok := e.(*net.OpError); !ok {
			t.Errorf("Expected *net.OpError want %q", e)
		}
	}
}
