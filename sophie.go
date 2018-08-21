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
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"strings"
	"time"
)

const (
	defaultTimeout = 15 * time.Second
	defaultSleep   = 1 * time.Second
)

// Response is the response from the server
type Response struct {
	Filename  string
	Signature string
	Infected  bool
	Raw       string
}

// A Client represents a Sophie client.
type Client struct {
	network     string
	address     string
	connTimeout time.Duration
	connRetries int
	connSleep   time.Duration
	cmdTimeout  time.Duration
}

// SetConnTimeout sets the connection timeout
func (c *Client) SetConnTimeout(t time.Duration) {
	c.connTimeout = t
}

// SetCmdTimeout sets the cmd timeout
func (c *Client) SetCmdTimeout(t time.Duration) {
	c.cmdTimeout = t
}

// SetConnRetries sets the number of times
// connection is retried
func (c *Client) SetConnRetries(s int) {
	if s < 0 {
		s = 0
	}
	c.connRetries = s
}

// SetConnSleep sets the connection retry sleep
// duration in seconds
func (c *Client) SetConnSleep(s time.Duration) {
	c.connSleep = s
}

// Scan a file or directory
func (c *Client) Scan(p string) (r *Response, err error) {
	r, err = c.fileCmd(p)
	return
}

// ScanStream submits a stream for scanning
// func (c *Client) ScanStream(i io.Reader) (r *Response, err error) {
// 	r, err = c.readerCmd(i)
// 	return
// }

// ScanReader scans an io.reader
func (c *Client) ScanReader(i io.Reader) (r *Response, err error) {
	r, err = c.readerCmd(i)
	return
}

func (c *Client) dial() (conn net.Conn, err error) {
	d := &net.Dialer{}

	if c.connTimeout > 0 {
		d.Timeout = c.connTimeout
	}

	for i := 0; i <= c.connRetries; i++ {
		conn, err = d.Dial(c.network, c.address)
		if e, ok := err.(net.Error); ok && e.Timeout() {
			time.Sleep(c.connSleep)
			continue
		}
		break
	}
	return
}

func (c *Client) fileCmd(p string) (r *Response, err error) {
	var id uint
	var isTCP bool
	var f *os.File
	var conn net.Conn
	var stat os.FileInfo
	var tc *textproto.Conn

	if stat, err = os.Stat(p); os.IsNotExist(err) {
		return
	}

	if c.network != "unix" && c.network != "unixpacket" {
		isTCP = true
		if stat.IsDir() {
			err = fmt.Errorf("Scanning directories not supported on a TCP connection")
			return
		}
	}

	if isTCP {
		if f, err = os.Open(p); err != nil {
			return
		}
		defer f.Close()

		r, err = c.readerCmd(f)
	} else {
		conn, err = c.dial()
		if err != nil {
			return
		}

		if c.cmdTimeout > 0 {
			conn.SetDeadline(time.Now().Add(c.cmdTimeout))
		}

		tc = textproto.NewConn(conn)
		defer tc.Close()

		id = tc.Next()
		tc.StartRequest(id)

		if err = tc.PrintfLine("%s", p); err != nil {
			tc.EndRequest(id)
			return
		}

		tc.EndRequest(id)
		tc.StartResponse(id)
		defer tc.EndResponse(id)

		r, err = c.processResponse(tc, p)
	}

	return
}

func (c *Client) readerCmd(i io.Reader) (r *Response, err error) {
	var id uint
	var l string
	var clen int64
	var conn net.Conn
	var stat os.FileInfo
	var tc *textproto.Conn

	conn, err = c.dial()
	if err != nil {
		return
	}

	if c.cmdTimeout > 0 {
		conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	}

	tc = textproto.NewConn(conn)
	defer tc.Close()

	switch v := i.(type) {
	case *bytes.Buffer:
		clen = int64(v.Len())
	case *bytes.Reader:
		clen = int64(v.Len())
	case *strings.Reader:
		clen = int64(v.Len())
	case *os.File:
		stat, err = v.Stat()
		if err != nil {
			return
		}
		clen = stat.Size()
	default:
		err = fmt.Errorf("The content length could not be determined")
		return
	}

	id = tc.Next()
	tc.StartRequest(id)

	if err = tc.PrintfLine("stream/%d", clen); err != nil {
		tc.EndRequest(id)
		return
	}

	if l, err = tc.ReadLine(); err != nil {
		tc.EndRequest(id)
		return
	}

	if l != "OK" {
		err = fmt.Errorf("Invalid Server Response: %s", l)
		tc.EndRequest(id)
		return
	}

	if _, err = io.Copy(tc.Writer.W, i); err != nil {
		tc.EndRequest(id)
		return
	}
	tc.W.Flush()

	tc.EndRequest(id)
	tc.StartResponse(id)
	defer tc.EndResponse(id)

	r, err = c.processResponse(tc, "")

	return
}

func (c *Client) processResponse(tc *textproto.Conn, p string) (r *Response, err error) {
	var l string

	if l, err = tc.ReadLine(); err != nil {
		return
	}

	r = &Response{}
	if p == "" {
		r.Filename = "stream"
	} else {
		r.Filename = p
	}

	if strings.HasPrefix(l, "-1") {
		err = fmt.Errorf("Unknown status")
	} else if strings.HasPrefix(l, "1") || strings.HasPrefix(l, "0") {
		r.Raw = l
		if strings.HasPrefix(l, "1") {
			r.Signature = l[2:]
			r.Infected = true
		}
	}

	return
}

// NewClient returns a new Sophie client.
func NewClient(network, address string) (c *Client, err error) {
	if network == "" && address == "" {
		network = "unix"
		address = "/var/lib/savdid/savdid.sock"
	}

	if network == "unix" || network == "unixpacket" {
		if _, err = os.Stat(address); os.IsNotExist(err) {
			err = fmt.Errorf("The unix socket: %s does not exist", address)
			return
		}
	}

	if network != "unix" && network != "unixpacket" && network != "tcp" && network != "tcp4" && network != "tcp6" {
		err = fmt.Errorf("Protocol: %s is not supported", network)
		return
	}

	c = &Client{
		network:     network,
		address:     address,
		connTimeout: defaultTimeout,
		connSleep:   defaultSleep,
	}
	return
}
