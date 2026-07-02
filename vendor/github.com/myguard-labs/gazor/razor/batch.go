package razor

import (
	"sort"
	"strings"
)

// findsimilar ports Razor2::String::findsimilar. status: 0 = different keys
// (perl returns ()), 1 = identical keys+values (perl returns (1)), 2 = same keys
// but some differing values (perl returns \%same,\@diff). On status 2, both holds
// shared values with "?" for differing keys, and diff lists the differing keys.
func findsimilar(a, b map[string]string) (both map[string]string, diff []string, status int) {
	if len(a) != len(b) {
		return nil, nil, 0
	}
	both = map[string]string{}
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		bv, ok := b[k]
		if !ok {
			return nil, nil, 0
		}
		if bv == a[k] {
			both[k] = a[k]
		} else {
			both[k] = "?"
			diff = append(diff, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			return nil, nil, 0
		}
	}
	if len(diff) == 0 {
		return nil, nil, 1
	}
	return both, diff, 2
}

// toBatchedQuery ports Razor2::String::to_batched_query. queries is the ordered
// list of query maps; bql/bqs cap each batch by line count / KB (0 = no limit);
// novar disables variable batching (our only caller, obj2queries, passes true).
func toBatchedQuery(queries []map[string]string, bql, bqs int, novar bool) []string {
	if len(queries) == 0 {
		return nil
	}
	var out []string
	var last map[string]string
	var line strings.Builder
	linecnt := 0
	batchmode := 0

	for _, cur := range queries {
		// message blob (report/revoke): emit as its own batch immediately
		if msg, ok := cur["message"]; ok {
			tmp := map[string]string{}
			for k, v := range cur {
				if k != "message" {
					tmp[k] = v
				}
			}
			l := "-" + makesis(tmp)
			l = strings.TrimSuffix(l, "\r\n")
			l += "&message=*\r\n" + msg + "\r\n.\r\n"
			out = append(out, l)
			continue
		}

		if last == nil {
			last = cur
			continue
		}
		if batchmode == 0 {
			both, diff, status := findsimilar(last, cur)
			if status == 2 && !novar {
				batchmode = 2
				line.Reset()
				line.WriteString("-" + makesisNue(both))
				line.WriteString(joinDiff(last, diff) + "\r\n")
				line.WriteString(joinDiff(cur, diff) + "\r\n")
				last = both
				linecnt = 2
			} else {
				batchmode = 1
				line.Reset()
				line.WriteString("-" + makesis(last))
				line.WriteString(makesisNue(cur))
				linecnt = 2
			}
			continue
		}
		// in batchmode
		var diff []string
		var status int
		if batchmode == 2 {
			_, diff, status = findsimilar(last, cur)
		}
		if (bqs > 0 && line.Len() > bqs*1024) ||
			(bql > 0 && linecnt >= bql) ||
			(batchmode == 2 && status != 2) {
			batchmode = 0
			line.WriteString(".\r\n")
			out = append(out, line.String())
			last = cur
		} else {
			if batchmode == 2 {
				line.WriteString(joinDiff(cur, diff) + "\r\n")
			} else {
				line.WriteString(makesisNue(cur))
			}
			linecnt++
		}
	}

	if batchmode != 0 {
		line.WriteString(".\r\n")
		out = append(out, line.String())
	} else if last != nil {
		out = append(out, makesis(last))
	}
	return out
}

func joinDiff(q map[string]string, diff []string) string {
	vals := make([]string, len(diff))
	for i, k := range diff {
		vals[i] = q[k]
	}
	return strings.Join(vals, ",")
}

// fromBatchedQuery ports Razor2::String::from_batched_query: expand a batched
// response back into individual query maps. Handles the leading-"-" template
// form ("?"-valued variable keys), the "*" message form, and plain sis lines.
func fromBatchedQuery(s string) []map[string]string {
	fq, rq := s, ""
	if strings.HasPrefix(s, "-") {
		if i := strings.Index(s, "\r\n"); i >= 0 {
			fq = s[1:i]
			rq = s[i+2:]
		}
	}

	var out []map[string]string
	switch {
	case strings.Contains(fq, "?"):
		template := map[string]string{}
		var seq []string
		for _, pair := range strings.Split(fq, "&") {
			k, v, _ := strings.Cut(pair, "=")
			if v == "?" {
				seq = append(seq, k)
			} else {
				template[k] = uriUnescape(v)
			}
		}
		for _, ln := range splitCRLF(rq) {
			vals := strings.Split(ln, ",")
			m := map[string]string{}
			for k, v := range template {
				m[k] = v
			}
			for i, k := range seq {
				if i < len(vals) {
					m[k] = vals[i]
				}
			}
			out = append(out, m)
		}
	case strings.Contains(fq, "*"):
		q := parsesis(fq)
		for k, v := range q {
			if v == "*" {
				q[k] = rq
				break
			}
		}
		out = append(out, q)
	default:
		out = append(out, parsesis(fq))
		for _, ln := range splitCRLF(rq) {
			out = append(out, parsesis(ln))
		}
	}
	return out
}

// splitCRLF mimics perl `split /\r\n/`: trailing empty fields removed.
func splitCRLF(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "\r\n")
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}
