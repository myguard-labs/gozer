package dcc

import "bytes"

// ckBodyMultipart ports the multipart branch of clntlib/ckbody.c:ck_body. It
// walks the body line by line, matches the active MIME boundaries, parses entity
// headers after each boundary, and feeds the text between boundaries to
// decodeSum (which applies the per-entity transfer-encoding and charset).
func (c *cks) ckBodyMultipart(bp []byte) {
	n := len(bp)
	sum := 0
	cmp := 0
	bpLen := n // bytes remaining starting at cmp

	for bpLen != 0 {
		if c.mimeNest == 0 {
			c.decodeSum(bp[sum:])
			return
		}

		if c.mimeBndMatches == 0 {
			// start of the next line: parse an entity header and reset boundaries
			rel := indexByteFromTo(bp, '\n', cmp, n)
			var cp int
			if rel < 0 {
				cp = cmp + bpLen
			} else {
				cp = rel + 1
			}
			i := cp - cmp
			if c.mpSt == mpHdrs {
				if c.parseMimeHdr(bp[cmp:cp], false) {
					if j := cp - sum; j != 0 {
						c.decodeSum(bp[sum:cp])
						sum = cp
					}
					c.mpSt = mpText
				}
			}
			if bp[cp-1] == '\n' {
				c.flags |= cksMimeBOL
				c.mimeBndMatches = c.mimeNest
				for k := 0; k < mimeBndNum; k++ {
					c.mimeBnd[k].cmpLen = 0
				}
			}
			cmp = cp
			bpLen -= i
			if bpLen == 0 {
				break
			}
		}

		matchedLen := 0
		for bi := 0; bi < c.mimeNest; bi++ {
			bndp := &c.mimeBnd[bi]
			if bndp.cmpLen == ckBndMiss {
				continue
			}
			j := bndp.bndLen - bndp.cmpLen
			length := bpLen
			if j > length {
				j = length
			}
			cp := cmp
			if j > 0 {
				if !bytes.Equal(bp[cp:cp+j], bndp.bnd[bndp.cmpLen:bndp.cmpLen+j]) {
					bndp.cmpLen = ckBndMiss
					c.mimeBndMatches--
					continue
				}
				bndp.cmpLen += j
				cp += j
				length -= j
				if length <= 0 {
					matchedLen = bpLen
					continue
				}
				j = 0
			}

			// trailing "--" of a final boundary
			if j == 0 && bp[cp] == '-' {
				bndp.cmpLen++
				length--
				if length <= 0 {
					matchedLen = bpLen
					continue
				}
				cp++
				j = -1
			}
			if j == -1 {
				if bp[cp] == '-' {
					bndp.cmpLen++
					length--
					if length <= 0 {
						matchedLen = bpLen
						continue
					}
					cp++
				} else {
					bndp.cmpLen = ckBndMiss
					c.mimeBndMatches--
					continue
				}
			}

			// trailing whitespace then the required '\n'
			if ch := bp[cp]; ch == ' ' || ch == '\t' || ch == '\r' {
				for {
					cp++
					length--
					if length <= 0 {
						break
					}
					ch = bp[cp]
					if ch != ' ' && ch != '\t' && ch != '\r' {
						break
					}
				}
				if length <= 0 {
					matchedLen = bpLen
					continue
				}
			}
			if bp[cp] != '\n' {
				bndp.cmpLen = ckBndMiss
				c.mimeBndMatches--
				continue
			}

			// found a MIME boundary: flush the text before it
			if j := cmp - sum; j != 0 {
				c.decodeSum(bp[sum:cmp])
			}
			matchedLen = cp + 1 - cmp
			cmp = cp + 1
			sum = cmp

			// checksum the boundary itself
			c.mpSt = mpBnd
			c.decodeSum(bndp.bnd[:bndp.bndLen])
			if bndp.cmpLen != bndp.bndLen {
				c.decodeSum([]byte("--"))
				c.mpSt = mpEpilogue
			} else {
				c.mpSt = mpHdrs
				bi++
			}
			c.mimeNest = bi
			c.decodersInit()
			break
		}
		bpLen -= matchedLen
	}

	if j := cmp - sum; j != 0 {
		c.decodeSum(bp[sum:cmp])
	}
}
