package protocol

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// AllowList is a relay's own list of what it may reach: host:port, *.suffix:port, or a network as CIDR:port (an
// address is a /32 or /128); a port of * is any. The relay refuses everything else; byke reads a relay's list (it says
// it at every hello) to know which targets the relay covers.
type AllowList []rule

type rule struct {
	host   string     // a name (lower case), or ""
	suffix string     // ".suffix" of *.suffix, or ""
	nw     *net.IPNet // a network, or nil
	port   int        // 0: any
}

// ParseAllow reads a relay's allow list.
func ParseAllow(entries []string) (AllowList, error) {
	var out AllowList
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		i := strings.LastIndex(e, ":")
		if i <= 0 || i == len(e)-1 {
			return nil, fmt.Errorf("allow %q: write host:port, *.suffix:port or CIDR:port (a port of * is any)", e)
		}
		host, portText := strings.Trim(e[:i], "[]"), e[i+1:]
		var rl rule
		if portText != "*" {
			p, err := strconv.Atoi(portText)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("allow %q: its port is 1-65535 or *", e)
			}
			rl.port = p
		}
		switch {
		case strings.HasPrefix(host, "*."):
			rl.suffix = strings.ToLower(host[1:])
		case strings.Contains(host, "/"):
			_, nw, err := net.ParseCIDR(host)
			if err != nil {
				return nil, fmt.Errorf("allow %q: %v", e, err)
			}
			rl.nw = nw
		case net.ParseIP(host) != nil:
			ip := net.ParseIP(host)
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			rl.nw = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		default:
			rl.host = strings.ToLower(host)
		}
		out = append(out, rl)
	}
	return out, nil
}

// Names says whether a name rule allows host:port (dialled by name).
func (l AllowList) Names(host string, port int) bool {
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, rl := range l {
		if rl.port != 0 && rl.port != port {
			continue
		}
		if rl.host != "" && rl.host == name || rl.suffix != "" && strings.HasSuffix(name, rl.suffix) {
			return true
		}
	}
	return false
}

// Holds says whether a network rule allows ip:port.
func (l AllowList) Holds(ip net.IP, port int) bool {
	for _, rl := range l {
		if rl.nw != nil && (rl.port == 0 || rl.port == port) && rl.nw.Contains(ip) {
			return true
		}
	}
	return false
}

// Covers says whether the list may allow host:port, as seen from outside the relay's network: a name a network rule
// would have to resolve first counts as covered when a network rule has its port (the relay decides).
func (l AllowList) Covers(host string, port int) bool {
	if l.Names(host, port) {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return l.Holds(ip, port)
	}
	for _, rl := range l {
		if rl.nw != nil && (rl.port == 0 || rl.port == port) {
			return true
		}
	}
	return false
}
