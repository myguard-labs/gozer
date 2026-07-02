package razor

// drand48 reimplements Perl's internal drand48 (Config randfunc=Perl_drand48),
// which the Ephemeral signature relies on via srand(seed)/rand(). Perl ships its
// own deterministic drand48 since 5.20, so srand(42); rand() is reproducible
// across platforms — verified bit-exact (17 significant digits) against perl.
type drand48 struct{ s [3]uint16 }

func newDrand48(seed uint32) *drand48 {
	// #nosec G115 -- drand48 state is three 16-bit limbs; the truncation is the algorithm.
	return &drand48{s: [3]uint16{0x330e, uint16(seed), uint16(seed >> 16)}}
}

// f returns the next value in [0,1), matching Perl's rand() (== drand48()).
func (d *drand48) f() float64 {
	const m0, m1, m2, add = 0xe66d, 0xdeec, 0x0005, 0x000b
	var accu uint32
	var t [2]uint16
	accu = uint32(m0)*uint32(d.s[0]) + uint32(add)
	t[0] = uint16(accu) // #nosec G115 -- 16-bit limb, intentional truncation
	accu >>= 16
	accu += uint32(m0)*uint32(d.s[1]) + uint32(m1)*uint32(d.s[0])
	t[1] = uint16(accu) // #nosec G115 -- 16-bit limb, intentional truncation
	accu >>= 16
	accu += m0*uint32(d.s[2]) + m1*uint32(d.s[1]) + m2*uint32(d.s[0])
	d.s[0], d.s[1], d.s[2] = t[0], t[1], uint16(accu) // #nosec G115 -- 16-bit limb, intentional truncation
	x := uint64(d.s[2])<<32 | uint64(d.s[1])<<16 | uint64(d.s[0])
	return float64(x) / float64(uint64(1)<<48)
}

// randf mimics Perl rand($n) = drand48()*n.
func (d *drand48) randf(n float64) float64 { return d.f() * n }
