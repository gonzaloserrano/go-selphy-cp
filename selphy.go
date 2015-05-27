/*********************************************************************\
*                                                                     *
*  selphy.go                                                          *
*  Client implementation of the Canon Selphy CP900 network protocol   *
*                                                                     *
*  Copyright 2013 Wilmer van der Gaast <wilmer@gaast.net>             *
*                                                                     *
*  This program is free software; you can redistribute it and/or      *
*  modify it under the terms of version 2 of the GNU General Public   *
*  License as published by the Free Software Foundation.              *
*                                                                     *
*  This program is distributed in the hope that it will be useful,    *
*  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      *
*  GNU General Public License for more details.                       *
*                                                                     *
*  You should have received a copy of the GNU General Public License  *
*  along with this program; if not, write to the Free Software        *
*  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA      *
*  02110-1301, USA.                                                   *
*                                                                     *
\*********************************************************************/

/* Maybe needless to say, this is my first time using Go. Apologies for
   not being bothered to split this into multiple files. */

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"image"
	_ "image/jpeg"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	CPNP_ADDR = "255.255.255.255"
	CPNP_PORT = 8609

	CPNP_MSG_DISCOVER = 0x101
	CPNP_MSG_STARTTCP = 0x110
	CPNP_MSG_ID       = 0x130
	CPNP_MSG_STATUS   = 0x120
	CPNP_MSG_DATA     = 0x121
)

type cmd_handler func(head []byte, body []byte)

func cpnp_packet(command int, payload []byte) []byte {
	ret := make([]byte, 16, 10240)

	copy(ret[0:], []byte("CPNP"))
	binary.BigEndian.PutUint16(ret[4:], uint16(command))
	binary.BigEndian.PutUint16(ret[14:], uint16(len(payload)))
	ret = ret[:len(ret)+len(payload)]
	copy(ret[16:], payload)

	return ret
}

type device struct {
	mac []byte

	udps *net.UDPConn
	dest *net.UDPAddr

	tcps   *net.TCPConn
	tcpd   *net.TCPAddr
	tcpbuf []byte

	cmdseq   uint16
	jobseq   uint16
	handlers map[uint16]cmd_handler
	props    map[string]string

	last_status []byte
	chunk       []byte

	job *imgreader

	cb func()
}

func new_device(printer_mac, printer_ip *string) *device {
	var err error

	c := new(device)

	if *printer_mac != "" {
		c.mac, err = hex.DecodeString(strings.Replace(*printer_mac, ":", "", -1))
		checkError(err)
	}

	c.dest, err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *printer_ip, CPNP_PORT))
	checkError(err)

	c.udps, err = net.ListenUDP("udp", nil)
	checkError(err)

	c.handlers = make(map[uint16]cmd_handler)
	c.props = make(map[string]string)

	return c
}

func (c *device) send(msg []byte, h cmd_handler) {
	var err error

	c.cmdseq++
	binary.BigEndian.PutUint16(msg[8:], c.cmdseq)
	c.handlers[c.cmdseq] = h

	if c.tcps != nil {
		/* Job number is sent in the TCP start response, and is (I
		   suppose) used to track state instead of just the TCP
		   port number. */
		binary.BigEndian.PutUint16(msg[10:], c.jobseq)

		_, err = c.tcps.Write(msg)
	} else {
		_, err = c.udps.WriteTo(msg, c.dest)
	}

	checkError(err)
}

func (c *device) wait() {
	for {
		if c.tcps != nil {
			c.wait_tcp()
		} else {
			c.wait_udp()
		}
	}
}

func (c *device) wait_udp() {
	buf := make([]byte, 5120, 5120)
	n, err := c.udps.Read(buf[0:])
	checkError(err)
	if bytes.Compare(buf[0:4], []byte("CPNP")) != 0 {
		fmt.Println("UDP protocol error!")
	} else {
		c.handle_message(buf[0:n])
	}
}

func (c *device) wait_tcp() {
	buf := make([]byte, 5120, 5120)
	n, err := c.tcps.Read(buf[0:])
	checkError(err)
	c.tcpbuf = c.tcpbuf[0 : len(c.tcpbuf)+n]
	copy(c.tcpbuf[len(c.tcpbuf)-n:], buf[0:n])

	if len(c.tcpbuf) < 16 {
		return
	}

	if bytes.Compare(c.tcpbuf[0:4], []byte("CPNP")) != 0 {
		fmt.Println("TCP protocol error!")
		return
	}

	msglen := 16 + binary.BigEndian.Uint32(c.tcpbuf[12:])

	if len(c.tcpbuf) < int(msglen) {
		return
	}

	c.handle_message(c.tcpbuf[0:msglen])
	buf = make([]byte, 0, 5120)
	copy(buf[0:], c.tcpbuf[msglen:])
	c.tcpbuf = buf
}

func (c *device) handle_message(buf []byte) {
	cmdseq := binary.BigEndian.Uint16(buf[8:])
	c.handlers[cmdseq](buf[0:16], buf[16:])
	delete(c.handlers, cmdseq)
}

func (c *device) discover(cb func()) {
	c.cb = cb
	p := cpnp_packet(CPNP_MSG_DISCOVER, []byte{})
	c.send(p, c.discover_reply)
}

func (c *device) discover_reply(head []byte, body []byte) {
	if body[4] == 6 {
		mac := ""
		for i := 0; i < 6; i++ {
			mac += fmt.Sprintf(":%02x", body[6+i])
		}
		mac = mac[1:]
		fmt.Println("Found printer with MAC address", mac)
	} /* else meh? */

	if c.mac != nil && bytes.Compare(c.mac, body[6:12]) != 0 {
		fmt.Println("Not the MAC address we're looking for, " +
			"waiting for more responses")
		return
	}

	var ip net.IP = body[6+body[4] : 6+body[4]+body[5]]
	fmt.Println("Switching to IP address", ip.String())
	c.dest.IP = ip

	p := cpnp_packet(CPNP_MSG_ID, []byte{0, 0, 0, 0})
	c.send(p, c.id_reply)
}

func (c *device) id_reply(head []byte, body []byte) {
	props := string(body[2:])
	for _, bit := range strings.Split(props, ";") {
		if len(bit) > 0 {
			kv := strings.Split(bit, ":")
			c.props[kv[0]] = kv[1]
		}
	}

	p := cpnp_packet(CPNP_MSG_STATUS, []byte{})
	c.send(p, c.status_reply)
}

func (c *device) status_reply(head []byte, body []byte) {
	/* Might tell us stuff like "go away I'm busy!"? */
	c.cb()
}

func (c *device) start_job(job *imgreader) {
	c.job = job

	u, _ := user.Current()

	_, fn := filepath.Split(job.fn)

	b := make([]byte, 0x188)
	utf16_write(b[0x008:0x048], "selphy.go")
	utf16_write(b[0x048:0x088], u.Username)
	utf16_write(b[0x088:0x188], fn)
	p := cpnp_packet(CPNP_MSG_STARTTCP, b)

	c.send(p, c.start_tcp)
}

func (c *device) start_tcp(head []byte, body []byte) {
	c.jobseq = binary.BigEndian.Uint16(head[10:])

	port := binary.BigEndian.Uint16(body[4:])
	if port == 0 {
		/* TODO: Throw a big fat error. */
		fmt.Println("Help! No TCP port to connect to..")
		return
	}

	fmt.Printf("Should connect to TCP %s:%d ... ", c.dest.IP, port)
	c.tcpd = new(net.TCPAddr)
	c.tcpd.IP = c.dest.IP
	c.tcpd.Port = int(port)

	var e error
	c.tcps, e = net.DialTCP("tcp", nil, c.tcpd)
	checkError(e)
	fmt.Println("Done")
	c.tcpbuf = make([]byte, 0, 51200)

	c.print_poll()
}

func (c *device) print_poll() {
	p := cpnp_packet(CPNP_MSG_STATUS, []byte{})
	c.send(p, c.print_data_request)
}

func (c *device) send_flags() {
	b := make([]byte, 0x40)
	binary.LittleEndian.PutUint32(b[0x04:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[0x0c:], 1) // ?
	if c.job.border {
		binary.LittleEndian.PutUint32(b[0x12:], 3)
	} else {
		binary.LittleEndian.PutUint32(b[0x12:], 2)
	}

	p := cpnp_packet(CPNP_MSG_DATA, b)
	c.send(p, c.send_flags_cb)
}

func (c *device) send_flags_cb(head []byte, body []byte) {
	c.print_poll()
}

func (c *device) send_chunk() {
	len := len(c.chunk)
	if len > 4096 {
		len = 4096
	}

	p := cpnp_packet(CPNP_MSG_DATA, c.chunk[0:len])
	c.send(p, c.send_chunk_cb)

	c.chunk = c.chunk[len:]
}

func (c *device) send_chunk_cb(head []byte, body []byte) {
	if len(c.chunk) > 0 {
		c.send_chunk()
	} else {
		c.print_poll()
	}
}

func (c *device) job_done(head []byte, body []byte) {
	c.tcps.Close()
	c.tcpd = nil
	c.tcps = nil

	c.cb()
}

func (c *device) print_data_request(head []byte, body []byte) {
	state := int(body[0x12])
	fmt.Println("state", state)

	/* It frequently seems to repeat the last status response, I suppose
	   that means it's still processing. Give it half a second. */
	if bytes.Compare(c.last_status, body) == 0 {
		time.Sleep(200 * time.Millisecond)
		c.print_poll()
		return
	}
	c.last_status = body

	switch state {
	case 0x00:
		/* Wait */
		time.Sleep(500 * time.Millisecond)
		c.print_poll()
	case 0x01:
		/* Job flags */
		fmt.Println("Sending flags")
		c.send_flags()
	case 0x02:
		/* File data request */
		offset := binary.LittleEndian.Uint32(body[0x18:])
		length := binary.LittleEndian.Uint32(body[0x1c:])
		fmt.Println("Will send", length, "bytes starting from", offset)

		/* Save the whole chunk and have it sent in 4KB steps. */
		c.chunk = c.job.get_chunk(offset, length)
		c.send_chunk()
	case 0x03:
		/* DONE! */
		fmt.Println("Job done, closing connection.")

		b := make([]byte, 0x40)
		binary.LittleEndian.PutUint32(b[0x04:], uint32(len(b)))
		b[2] = 0x03 // Echo status code? No clue..
		p := cpnp_packet(CPNP_MSG_DATA, b)
		c.send(p, c.job_done)
	}
}

func utf16_write(buf []byte, val string) {
	enc := utf16.Encode([]rune(val))
	for i, c := range enc {
		binary.BigEndian.PutUint16(buf[2*i:], uint16(c))
	}
}

type imgreader struct {
	fn     string
	fp     *os.File
	w, h   int
	fsize  int64
	border bool
}

func new_imgreader(fn string) *imgreader {
	r := new(imgreader)

	r.fn = fn
	r.fp, _ = os.Open(r.fn)

	fi, _ := r.fp.Stat()
	r.fsize = fi.Size()

	cfg, f, e := image.DecodeConfig(r.fp)
	checkError(e)
	fmt.Printf("File %s, %s file, %d bytes, %d×%d\n", fn, f, r.fsize, cfg.Width, cfg.Height)

	r.w = cfg.Width
	r.h = cfg.Height

	return r
}

func (r *imgreader) file_header(offset uint32, length uint32) []byte {
	buf := make([]byte, 0x68)

	buf[0x02] = 1
	binary.LittleEndian.PutUint32(buf[0x04:], length+uint32(len(buf)))
	buf[0x0c] = 1

	binary.LittleEndian.PutUint32(buf[0x14:], uint32(r.fsize))
	binary.LittleEndian.PutUint32(buf[0x18:], uint32(r.w))
	binary.LittleEndian.PutUint32(buf[0x1c:], uint32(r.h))

	binary.LittleEndian.PutUint32(buf[0x60:], offset)
	binary.LittleEndian.PutUint32(buf[0x64:], length)

	return buf
}

func (r *imgreader) get_chunk(offset uint32, length uint32) []byte {
	head := r.file_header(offset, length)
	buf := make([]byte, len(head)+int(length))
	copy(buf[0:], head)

	r.fp.Seek(int64(offset), 0)
	_, err := r.fp.Read(buf[len(head):])
	checkError(err)

	/* Read might have read less than the number of bytes requested, but
	   that's okay, IIRC the original implementation has 0/junk-padded
	   chunk as well after EOF.

	   Note that the printer does parse the JPEG as it comes in, and
	   will stop asking for more chunks when it doesn't need more
	   (skipping thumbnail info at the end or whatever it was?). */

	return buf
}

type printer struct {
	dev  *device
	jobs []*imgreader
}

func new_printer() *printer {
	p := new(printer)
	p.jobs = make([]*imgreader, 0, 10)
	return p
}

func (p *printer) add_job(job *imgreader) {
	p.jobs = append(p.jobs, job)
}

func (p *printer) start() {
	p.dev.discover(p.start_job)
	p.dev.wait()
}

func (p *printer) start_job() {
	fmt.Println("It's a", p.dev.props["DES"])

	if len(p.jobs) == 0 {
		fmt.Println("Ran out of stuff to do, exiting")
		os.Exit(0)
	}

	job := p.jobs[0]
	fmt.Println("Will send", job.fn)
	p.dev.start_job(job)
	p.jobs = p.jobs[1:]
}

func main() {
	printer_mac := flag.String("printer_mac", "", "MAC address of printer")
	printer_ip := flag.String("printer_ip", CPNP_ADDR, "IP addres of printer")
	border := flag.Bool("border", false, "Allow white borders, don't crop")
	flag.Parse()

	p := new_printer()
	for _, fn := range flag.Args() {
		job := new_imgreader(fn)
		job.border = *border
		p.add_job(job)
	}

	p.dev = new_device(printer_mac, printer_ip)
	p.start()

	os.Exit(0)
}

func checkError(err error) {
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		fmt.Fprintln(os.Stderr, "Fatal error at ", file, "line", line, err.Error())
		os.Exit(1)
	}
}
