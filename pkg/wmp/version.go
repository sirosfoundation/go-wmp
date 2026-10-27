package wmp

import (
	"strconv"
	"strings"
)

// parseVersion parses a "MAJOR.MINOR" protocol version (core section 2.2).
// Both parts must be plain decimal digits: signs, spaces, empty parts and
// extra components are rejected.
func parseVersion(v string) (major, minor int, ok bool) {
	maj, min, found := strings.Cut(v, ".")
	if !found {
		return 0, 0, false
	}
	var err error
	if major, err = parseVersionPart(maj); err != nil {
		return 0, 0, false
	}
	if minor, err = parseVersionPart(min); err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func parseVersionPart(s string) (int, error) {
	if s == "" || len(s) > 6 {
		return 0, strconv.ErrSyntax
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, strconv.ErrSyntax
		}
	}
	return strconv.Atoi(s)
}

// NegotiateVersion implements core section 2.2.2: it returns the highest
// version in supported that has the same MAJOR as offered and a MINOR that
// is not greater than offered's. The returned string is the entry from
// supported, unmodified. ok is false when offered is not a valid
// "MAJOR.MINOR" version or no supported version is compatible; the caller
// then rejects the request with ErrVersionNotSupported. Unparseable entries
// in supported are ignored.
func NegotiateVersion(offered string, supported []string) (selected string, ok bool) {
	offMajor, offMinor, valid := parseVersion(offered)
	if !valid {
		return "", false
	}
	best := -1
	for _, s := range supported {
		major, minor, valid := parseVersion(s)
		if !valid || major != offMajor || minor > offMinor || minor <= best {
			continue
		}
		best, selected = minor, s
	}
	return selected, best >= 0
}
