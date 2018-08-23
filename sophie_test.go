// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package sophie implements the sophie protocol
Sophie - Golang Sophie protocol implementation
*/
package sophie

import (
	"bytes"
	"go/build"
	"net"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

const (
	localSock = "/Users/andrew/sophie.sock"
)

func TestBasics(t *testing.T) {
	var expected string
	// Test Non existent socket
	_, e := NewClient("unix", "/tmp/.dumx.sock")
	if e == nil {
		t.Fatalf("An error should be returned as sock does not exist")
	}
	expected = "The unix socket: /tmp/.dumx.sock does not exist"
	if e.Error() != expected {
		t.Errorf("Expected %q want %q", expected, e)
	}
	// Test defaults
	_, e = NewClient("", "")
	if e == nil {
		t.Fatalf("An error should be returned as sock does not exist")
	}
	expected = "The unix socket: /var/lib/savdid/savdid.sock does not exist"
	if e.Error() != expected {
		t.Errorf("Got %q want %q", expected, e)
	}
	// Test udp
	_, e = NewClient("udp", "127.1.1.1:4010")
	if e == nil {
		t.Fatalf("Expected an error got nil")
	}
	expected = "Protocol: udp is not supported"
	if e.Error() != expected {
		t.Errorf("Got %q want %q", expected, e)
	}
	// Test tcp
	network := "tcp"
	address := "127.1.1.1:4010"
	c, e := NewClient(network, address)
	if e != nil {
		t.Fatalf("An error should not be returned")
	}
	if c.network != network {
		t.Errorf("Got %q want %q", c.network, network)
	}
	if c.address != address {
		t.Errorf("Got %q want %q", c.address, address)
	}
}

func TestSettings(t *testing.T) {
	var e error
	var c *Client
	network := "tcp"
	address := "127.1.1.1:4010"
	if c, e = NewClient(network, address); e != nil {
		t.Fatalf("An error should not be returned")
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
		t.Fatalf("An error should be returned")
	}
	if _, ok := e.(*net.OpError); !ok {
		t.Errorf("Expected *net.OpError want %q", e)
	}

}

func TestUnixScan(t *testing.T) {
	address := os.Getenv("SOPHIE_UNIX_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient("unix", address)
		if e != nil {
			t.Errorf("An error should not be returned")
		}
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			gopath = build.Default.GOPATH
		}
		fn := path.Join(gopath, "src/github.com/baruwa-enterprise/sophie/examples/data/eicar.txt")
		s, e := c.Scan(fn)
		if e == nil {
			t.Errorf("An error should be returned: %s", e)
		}
		if s.Filename != fn {
			t.Errorf("c.Scan(%q) = %q, want %q", fn, s.Filename, fn)
		}
		if s.Infected {
			t.Errorf("c.Scan(%q).Infected = %t, want %t", fn, s.Infected, false)
		}
		fn = "/tmp/eicar.tar.bz2"
		s, e = c.Scan(fn)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		if s.Filename != fn {
			t.Errorf("c.Scan(%q) = %q, want %q", fn, s.Filename, fn)
		}
		if !s.Infected {
			t.Errorf("c.Scan(%q).Infected = %t, want %t", fn, s.Infected, true)
		}
		if s.Signature != "EICAR-AV-Test" {
			t.Errorf("c.Scan(%q).Signature = %s, want %s", fn, s.Signature, "EICAR-AV-Test")
		}
	}
}

func TestTCPScan(t *testing.T) {
	var e error
	var c *Client
	var s *Response

	address := os.Getenv("SOPHIE_TCP_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e = os.Stat(address); !os.IsNotExist(e) {
		if address == localSock {
			c, e = NewClient("tcp4", "192.168.1.126:4010")
		} else {
			c, e = NewClient("tcp", address)
		}
		if e != nil {
			t.Errorf("An error should not be returned")
		}
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			gopath = build.Default.GOPATH
		}
		fn := path.Join(gopath, "src/github.com/baruwa-enterprise/sophie/examples/data/eicar.txt")
		s, e = c.Scan(fn)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		if s.Filename != "stream" {
			t.Errorf("c.Scan(%q) = %q, want %q", fn, s.Filename, "stream")
		}
		if !s.Infected {
			t.Errorf("c.Scan(%q).Infected = %t, want %t", fn, s.Infected, true)
		}
		if s.Signature != "EICAR-AV-Test" {
			t.Errorf("c.Scan(%q).Signature = %s, want %s", fn, s.Signature, "EICAR-AV-Test")
		}
		fn = path.Join(gopath, "src/github.com/baruwa-enterprise/sophie/examples/data")
		s, e = c.Scan(fn)
		if e == nil {
			t.Errorf("An error should be returned: %s", e)
		}
		es := "Scanning directories not supported on a TCP connection"
		if e.Error() != es {
			t.Errorf("c.Scan(%q) returned error '%s' want '%s'", fn, e, es)
		}
	}
}

func TestTCPScanFileStream(t *testing.T) {
	var e error
	var c *Client
	var s *Response

	address := os.Getenv("SOPHIE_TCP_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e = os.Stat(address); !os.IsNotExist(e) {
		if address == localSock {
			c, e = NewClient("tcp4", "192.168.1.126:4010")
		} else {
			c, e = NewClient("tcp", address)
		}
		if e != nil {
			t.Errorf("An error should not be returned")
		}
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			gopath = build.Default.GOPATH
		}
		fn := path.Join(gopath, "src/github.com/baruwa-enterprise/sophie/examples/data/eicar.txt")
		f, e := os.Open(fn)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		defer f.Close()
		s, e = c.ScanReader(f)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		if s.Filename != "stream" {
			t.Errorf("c.Scan(%q) = %q, want %q", fn, s.Filename, "stream")
		}
		if !s.Infected {
			t.Errorf("c.Scan(%q).Infected = %t, want %t", fn, s.Infected, true)
		}
		if s.Signature != "EICAR-AV-Test" {
			t.Errorf("c.Scan(%q).Signature = %s, want %s", fn, s.Signature, "EICAR-AV-Test")
		}

	}
}

func TestTCPScanBytesStream(t *testing.T) {
	var e error
	var c *Client
	var s *Response

	address := os.Getenv("SOPHIE_TCP_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e = os.Stat(address); !os.IsNotExist(e) {
		if address == localSock {
			c, e = NewClient("tcp4", "192.168.1.126:4010")
		} else {
			c, e = NewClient("tcp", address)
		}
		if e != nil {
			t.Errorf("An error should not be returned")
		}
		fn := "stream"
		m := []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
		f := bytes.NewReader(m)
		s, e = c.ScanReader(f)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		if s.Filename != fn {
			t.Errorf("c.Scan(%q) = %q, want %q", fn, s.Filename, fn)
		}
		if !s.Infected {
			t.Errorf("c.Scan(%q).Infected = %t, want %t", fn, s.Infected, true)
		}
		if s.Signature != "EICAR-AV-Test" {
			t.Errorf("c.Scan(%q).Signature = %s, want %s", fn, s.Signature, "EICAR-AV-Test")
		}
	}
}

func TestTCPScanBufferStream(t *testing.T) {
	var e error
	var c *Client
	var s *Response

	address := os.Getenv("SOPHIE_TCP_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e = os.Stat(address); !os.IsNotExist(e) {
		if address == localSock {
			c, e = NewClient("tcp4", "192.168.1.126:4010")
		} else {
			c, e = NewClient("tcp", address)
		}
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		fn := "stream"
		f := bytes.NewBufferString(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
		s, e = c.ScanReader(f)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		if s.Filename != fn {
			t.Errorf("c.Scan(%q) = %q, want %q", fn, s.Filename, fn)
		}
		if !s.Infected {
			t.Errorf("c.Scan(%q).Infected = %t, want %t", fn, s.Infected, true)
		}
		if s.Signature != "EICAR-AV-Test" {
			t.Errorf("c.Scan(%q).Signature = %s, want %s", fn, s.Signature, "EICAR-AV-Test")
		}
	}
}

func TestTCPScanStringStream(t *testing.T) {
	var e error
	var c *Client
	var s *Response

	address := os.Getenv("SOPHIE_TCP_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e = os.Stat(address); !os.IsNotExist(e) {
		if address == localSock {
			c, e = NewClient("tcp4", "192.168.1.126:4010")
		} else {
			c, e = NewClient("tcp", address)
		}
		if e != nil {
			t.Errorf("An error should not be returned")
		}
		fn := "stream"
		f := strings.NewReader(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
		s, e = c.ScanReader(f)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		if s.Filename != fn {
			t.Errorf("c.Scan(%q) = %q, want %q", fn, s.Filename, fn)
		}
		if !s.Infected {
			t.Errorf("c.Scan(%q).Infected = %t, want %t", fn, s.Infected, true)
		}
		if s.Signature != "EICAR-AV-Test" {
			t.Errorf("c.Scan(%q).Signature = %s, want %s", fn, s.Signature, "EICAR-AV-Test")
		}
	}
}
