package dcc

// cks is the shared checksum context — the Go analogue of GOT_CKS. It owns the
// body/Fuz1/Fuz2 sub-states, the shared URL extractor, and the MIME container
// state (multipart boundaries, quoted-printable / base64 decoders, the current
// content-type / charset / transfer-encoding). The body driver ck_body and the
// header parser parse_mime_hdr live here; they feed decoded bytes to all three
// checksummers via decodeSum.

// MIME boundary limits (clntlib/dcc_ck.h).
const (
	ckBndMax   = 94           // CK_BND_MAX
	ckBndDim   = ckBndMax + 2 // CK_BND_DIM, including the leading "--"
	ckBndMiss  = ckBndDim + 1 // CK_BND_MISS sentinel for cmp_len
	mimeBndNum = 3            // mime_bnd[3]
)

// content transfer encoding (DCC_CK_CE_*)
const (
	ceASCII = iota
	ceQP
	ceB64
)

// multipart parser state (CK_MP_ST_*)
const (
	mpPreamble = iota
	mpBnd
	mpHdrs
	mpText
	mpEpilogue
)

// MIME-header parser state (enum CK_MHDR_ST_*), in declaration order.
const (
	mhdrIdle = iota
	mhdrCeCt
	mhdrCe
	mhdrCeWS
	mhdrCt
	mhdrCtWS
	mhdrQP
	mhdrB64
	mhdrText
	mhdrHTML
	mhdrCsetSkipParam
	mhdrCsetSpanWS
	mhdrCset
	mhdrCsetISO8859
	mhdrCsetISOX
	mhdrMultipart
	mhdrBndSkipParam
	mhdrBndSpanWS
	mhdrBnd
	mhdrBndValue
)

// cks flags
const (
	cksMimeBOL    = 0x01
	cksMimeQuoted = 0x02
)

// ckBnd mirrors CK_BND: a "--"-prefixed boundary plus its compare progress.
type ckBnd struct {
	bndLen int
	cmpLen int
	bnd    [ckBndDim]byte
}

// qpState / b64State mirror the GOT_CKS quoted-printable and base64 decoders.
type qpState struct {
	x, y  byte
	n     byte
	state int
}

type b64State struct {
	quantum    uint32
	quantumCnt int
}

// quoted-printable decoder states (CK_QP_*)
const (
	qpIdle = iota
	qpEq
	qp1
	qpFail1
	qpFail2
	qpFail3
)

type cks struct {
	body *bodyState
	fz1  *fuz1State
	fz2  *fuz2State
	url  ckURL

	// MIME container state
	mimeNest       int
	mimeBnd        [mimeBndNum]ckBnd
	mimeBndMatches int
	mpSt           int
	mhdrSt         int
	mhdrPos        int
	qp             qpState
	b64            b64State
	mimeCt         int        // CK_CT_*
	mimeCset       *[256]byte // folding table (default c8859_1)
	mimeCe         int        // DCC_CK_CE_*
	flags          uint
}

// newCks builds and initialises a context (cks_init): all three checksummers
// fresh, decoders idle, text/ASCII/8859-1 defaults.
func newCks() *cks {
	c := &cks{}
	c.body = newBodyState()
	c.fz1 = newFuz1State()
	c.fz2 = newFuz2State()
	c.fz1.c = c
	c.fz2.c = c
	c.url.st = urlIdle
	c.url.cref.st = crefIdle
	c.url.start, c.url.tld, c.url.sld = -1, -1, -1
	c.mhdrSt = mhdrIdle
	c.mpSt = mpText
	c.decodersInit()
	return c
}

// decodersInit ports ckbody.c:decoders_init — reset per-entity decoder state.
func (c *cks) decodersInit() {
	c.mimeBndMatches = 0
	c.flags |= cksMimeBOL
	c.mimeCt = ckCtText
	c.mimeCset = &cset8859_1
	c.mimeCe = ceASCII
	c.qp.state = qpIdle
	c.b64.quantumCnt = 0
}

// computeBody runs the full body pipeline over a raw message body and returns
// the three body checksums. Multipart/quoted-printable/base64/charset are all
// handled by ckBody/decodeSum.
func (c *cks) computeBody(body []byte) (bodySum Sum, bodyOK bool, f1 Sum, f1OK bool, f2 Sum, f2OK bool) {
	c.ckBody(body)
	// cks_fin: flush the URL/line decoders with a trailing newline.
	c.fz1.fuz1([]byte("\n"))
	c.fz2.fuz2([]byte("\n"))

	bodySum, bodyOK = c.body.final()
	f1, f1OK = c.fz1.final()
	f2, f2OK = c.fz2.final(&c.url)
	return
}

// fz2WordCount reports the English (lang 0) word total — read by the Fuz1 URL
// code to decide host-name buffer management.
func (c *cks) fz2WordCount() int { return c.fz2.lang[0].wtotal }
