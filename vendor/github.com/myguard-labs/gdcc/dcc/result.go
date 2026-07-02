package dcc

// CkCount is a server's answer for one queried checksum: the total count
// including this transaction (Cur) and before it (Prev). Sentinel values like
// "many" (DCC_TGTS_TOO_MANY) and the whitelist markers live in Cur.
type CkCount struct {
	Type  CkType
	Label string
	Cur   uint32
	Prev  uint32
}

// IsMany reports the DCC "many" sentinel — a checksum so widely reported the
// server stopped counting (>= 16,777,200).
func (c CkCount) IsMany() bool { return c.Cur >= dccTgtsTooMany && c.Cur <= dccTgtsMask }

// IsWhite reports the server whitelisting this checksum as certified not spam.
func (c CkCount) IsWhite() bool { return c.Cur == dccTgtsOK || c.Cur == dccTgtsOK2 }

// Result is a DCC server's response to a Check: the per-checksum counts.
type Result struct {
	Counts []CkCount
}

func isBodyType(t CkType) bool { return t >= CkBody && t <= CkFuz2 }

// BodyCount returns the largest body-checksum (Body/Fuz1/Fuz2) current count
// and whether any body checksum was present. This is the number DCC's spam
// decision rides on. "Many" reads as the sentinel value.
func (r Result) BodyCount() (uint32, bool) {
	var max uint32
	var have bool
	for _, c := range r.Counts {
		if isBodyType(c.Type) {
			have = true
			if c.Cur > max {
				max = c.Cur
			}
		}
	}
	return max, have
}

// Whitelisted reports whether the server certified any body checksum not spam.
func (r Result) Whitelisted() bool {
	for _, c := range r.Counts {
		if isBodyType(c.Type) && c.IsWhite() {
			return true
		}
	}
	return false
}

// Action is the coarse verdict for the gozer shim.
type Action int

const (
	ActionUnknown Action = iota // no opinion
	ActionAccept                // server whitelisted the body
	ActionReject                // a body checksum is "many"/bulk
)

func (a Action) String() string {
	switch a {
	case ActionAccept:
		return "accept"
	case ActionReject:
		return "reject"
	}
	return "unknown"
}

// Verdict is the DCCResult the gozer backend consumes. Bulk is the
// representative body count when the message is bulk, else nil.
type Verdict struct {
	Action Action
	Bulk   *int
}

// Verdict applies the standard rule: a server whitelist → accept; a body
// checksum at "many" → reject with the bulk count; otherwise unknown. Pass a
// custom bulk threshold via VerdictThreshold; this uses the "many" sentinel.
func (r Result) Verdict() Verdict { return r.VerdictThreshold(dccTgtsTooMany) }

// VerdictThreshold lets the caller reject at a lower body count than "many"
// (e.g. rspamd-style numeric thresholds). A whitelist still wins.
func (r Result) VerdictThreshold(threshold uint32) Verdict {
	if r.Whitelisted() {
		return Verdict{Action: ActionAccept}
	}
	count, have := r.BodyCount()
	if have && count >= threshold {
		b := int(count)
		return Verdict{Action: ActionReject, Bulk: &b}
	}
	return Verdict{Action: ActionUnknown}
}
