// Package dcc is a clean-room Go implementation of a DCC (Distributed Checksum
// Clearinghouse) protocol client: it computes the message checksums DCC uses
// and (later) queries/reports them to DCC servers. It is not DCC itself.
//
// This file defines the checksum value type and the byte-exact text form that
// matches the C reference (clntlib/ck2str.c).
package dcc

import "fmt"

// CkType is a DCC checksum type, numbered as in include/dcc_proto.h.
type CkType uint8

const (
	CkInvalid   CkType = 0
	CkIP        CkType = 1 // MD5 of the binary source IPv6 address
	CkEnvFrom   CkType = 2 // envelope Mail From value
	CkFrom      CkType = 3 // From: header
	CkEnvTo     CkType = 4 // envelope Rcpt To value
	CkMessageID CkType = 5 // Message-ID: header
	CkReceived  CkType = 6 // last Received: header
	CkBody      CkType = 7 // whitespace-stripped body
	CkFuz1      CkType = 8 // fuzzy body checksum 1
	CkFuz2      CkType = 9 // fuzzy body checksum 2
	CkSub       CkType = 10
)

// label is the type name as dccproc -C prints it (clntlib/type2str.c via the
// DCC_XHDR_TYPE_* macros). Used both for output and for parity comparison.
func (t CkType) label() string {
	switch t {
	case CkIP:
		return "IP"
	case CkEnvFrom:
		return "env_From"
	case CkFrom:
		return "From"
	case CkEnvTo:
		return "env_To"
	case CkMessageID:
		return "Message-ID"
	case CkReceived:
		return "Received"
	case CkBody:
		return "Body"
	case CkFuz1:
		return "Fuz1"
	case CkFuz2:
		return "Fuz2"
	case CkSub:
		return "substitute"
	}
	return fmt.Sprintf("%d?", uint8(t))
}

// Sum is a 16-byte DCC checksum (an MD5 digest).
type Sum [16]byte

// String renders the checksum exactly as ck2str() does for non-server-ID types:
// four big-endian 32-bit words in lower-case hex, space separated.
func (s Sum) String() string {
	return fmt.Sprintf("%08x %08x %08x %08x",
		be32(s[0:4]), be32(s[4:8]), be32(s[8:12]), be32(s[12:16]))
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Checksum is one computed checksum: its type, the printable label, and value.
// Report mirrors the C rpt2srvr flag: whether this checksum is sent to a DCC
// server in a query/report. (A synthesised empty Message-ID is emitted for
// debug parity but not reported.)
type Checksum struct {
	Type   CkType
	Label  string
	Sum    Sum
	Report bool
}
