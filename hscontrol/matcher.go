package hscontrol

import (
	"fmt"
	"net/netip"
	"strings"

	"go4.org/netipx"
	"tailscale.com/tailcfg"
)

// This is borrowed from, and updated to use IPSet
// https://github.com/tailscale/tailscale/blob/71029cea2ddf82007b80f465b256d027eab0f02d/wgengine/filter/tailcfg.go#L97-L162
// TODO(kradalby): contribute upstream and make public.
var (
	zeroIP4 = netip.AddrFrom4([4]byte{})
	zeroIP6 = netip.AddrFrom16([16]byte{})
)

// parseIPSet parses arg as one:
//
//   - an IP address (IPv4 or IPv6)
//   - the string "*" to match everything (both IPv4 & IPv6)
//   - a CIDR (e.g. "192.168.0.0/16")
//   - a range of two IPs, inclusive, separated by hyphen ("2eff::1-2eff::0800")
//
// bits, if non-nil, is the legacy SrcBits CIDR length to make a IP
// address (without a slash) treated as a CIDR of *bits length.
// nolint
func parseIPSet(arg string, bits *int) (*netipx.IPSet, error) {
	var ipSet netipx.IPSetBuilder
	if arg == "*" {
		ipSet.AddPrefix(netip.PrefixFrom(zeroIP4, 0))
		ipSet.AddPrefix(netip.PrefixFrom(zeroIP6, 0))

		return ipSet.IPSet()
	}
	if strings.Contains(arg, "/") {
		pfx, err := netip.ParsePrefix(arg)
		if err != nil {
			return nil, err
		}
		if pfx != pfx.Masked() {
			return nil, fmt.Errorf("%v contains non-network bits set", pfx)
		}

		ipSet.AddPrefix(pfx)

		return ipSet.IPSet()
	}
	if strings.Count(arg, "-") == 1 {
		ip1s, ip2s, _ := strings.Cut(arg, "-")

		ip1, err := netip.ParseAddr(ip1s)
		if err != nil {
			return nil, err
		}

		ip2, err := netip.ParseAddr(ip2s)
		if err != nil {
			return nil, err
		}

		r := netipx.IPRangeFrom(ip1, ip2)
		if !r.IsValid() {
			return nil, fmt.Errorf("invalid IP range %q", arg)
		}

		for _, prefix := range r.Prefixes() {
			ipSet.AddPrefix(prefix)
		}

		return ipSet.IPSet()
	}
	ip, err := netip.ParseAddr(arg)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address %q", arg)
	}
	bits8 := uint8(ip.BitLen())
	if bits != nil {
		if *bits < 0 || *bits > int(bits8) {
			return nil, fmt.Errorf("invalid CIDR size %d for IP %q", *bits, arg)
		}
		bits8 = uint8(*bits)
	}

	ipSet.AddPrefix(netip.PrefixFrom(ip, int(bits8)))

	return ipSet.IPSet()
}

type Match struct {
	Srcs  *netipx.IPSet
	Dests *netipx.IPSet
}

func MatchFromFilterRule(rule tailcfg.FilterRule) Match {
	srcs := new(netipx.IPSetBuilder)
	dests := new(netipx.IPSetBuilder)

	for _, srcIP := range rule.SrcIPs {
		set, _ := parseIPSet(srcIP, nil)

		srcs.AddSet(set)
	}

	for _, dest := range rule.DstPorts {
		set, _ := parseIPSet(dest.IP, nil)

		dests.AddSet(set)
	}

	srcsSet, _ := srcs.IPSet()
	destsSet, _ := dests.IPSet()

	match := Match{
		Srcs:  srcsSet,
		Dests: destsSet,
	}

	return match
}

func (m *Match) SrcsContainsIPs(ips []netip.Addr) bool {
	for _, ip := range ips {
		if m.Srcs.Contains(ip) {
			return true
		}
	}

	return false
}

func (m *Match) DestsContainsIP(ips []netip.Addr) bool {
	for _, ip := range ips {
		if m.Dests.Contains(ip) {
			return true
		}
	}

	return false
}

// filterRule is a FilterRule with its addresses parsed. The ACL filter is
// compiled once per rebuild so that map responses, which check every rule for
// every peer of every machine, do not parse the policy again each time.
type filterRule struct {
	tailcfg.FilterRule
	match Match
	// srcs and dsts hold the parsed SrcIPs and DstPorts[].IP, in order.
	srcs []*netipx.IPSet
	dsts []*netipx.IPSet
}

func compileFilterRules(rules []tailcfg.FilterRule) []filterRule {
	compiled := make([]filterRule, len(rules))
	for i, rule := range rules {
		srcs := make([]*netipx.IPSet, len(rule.SrcIPs))
		for j, src := range rule.SrcIPs {
			srcs[j] = parseIPSetOrEmpty(src)
		}
		dsts := make([]*netipx.IPSet, len(rule.DstPorts))
		for j, dest := range rule.DstPorts {
			dsts[j] = parseIPSetOrEmpty(dest.IP)
		}
		compiled[i] = filterRule{
			FilterRule: rule,
			match:      MatchFromFilterRule(rule),
			srcs:       srcs,
			dsts:       dsts,
		}
	}

	return compiled
}

// parseIPSetOrEmpty fails closed: an address we cannot parse matches nothing.
func parseIPSetOrEmpty(arg string) *netipx.IPSet {
	set, err := parseIPSet(arg, nil)
	if err != nil {
		return &netipx.IPSet{}
	}

	return set
}

// denyAllFilter is sent to a machine that no rule applies to. An empty
// PacketFilter is dropped by omitempty, which tells the client to keep the
// filter it already has; a rule without sources matches nothing.
var denyAllFilter = []tailcfg.FilterRule{{SrcIPs: []string{}}}

// reduceFilterRules returns the part of the ACL filter that machine can ever
// apply. Tailscale clients only check the filter for packets arriving at them,
// and WireGuard only accepts a packet from a peer whose AllowedIPs contain its
// source. So a rule matters only if a destination is the machine or a subnet
// it advertises, and only the sources inside the machine's own addresses or
// its peers' AllowedIPs can ever match. Everything else is dropped, so the
// filter reveals nothing beyond the peer list; sending the whole filter
// disclosed every other user's addresses and subnets to each client.
//
// The destination check follows ReduceFilterRules in upstream headscale v0.23.
// The source check is needed here because peers are limited to the machine's
// own user while the policy has rules across users.
func reduceFilterRules(machine *Machine, peers []*tailcfg.Node, rules []filterRule) []tailcfg.FilterRule {
	addrs := []netip.Addr(machine.IPAddresses)
	routes := machine.HostInfo.RoutableIPs

	var sourcesBuilder netipx.IPSetBuilder
	for _, addr := range addrs {
		sourcesBuilder.Add(addr)
	}
	for _, peer := range peers {
		for _, prefix := range peer.Addresses {
			sourcesBuilder.AddPrefix(prefix)
		}
		for _, prefix := range peer.AllowedIPs {
			sourcesBuilder.AddPrefix(prefix)
		}
	}
	sources, _ := sourcesBuilder.IPSet()

	reduced := []tailcfg.FilterRule{}
	for _, rule := range rules {
		if !rule.match.Srcs.Overlaps(sources) || !setMatchesMachine(rule.match.Dests, addrs, routes) {
			continue
		}

		kept := rule.FilterRule
		// SrcBits pairs with SrcIPs by index; headscale never sets it, but
		// leave such a rule's sources alone rather than misalign them.
		if len(rule.SrcBits) == 0 {
			kept.SrcIPs = []string{}
			for i, src := range rule.srcs {
				if src.Overlaps(sources) {
					kept.SrcIPs = append(kept.SrcIPs, rule.SrcIPs[i])
				}
			}
		}
		kept.DstPorts = []tailcfg.NetPortRange{}
		for i, dst := range rule.dsts {
			if setMatchesMachine(dst, addrs, routes) {
				kept.DstPorts = append(kept.DstPorts, rule.DstPorts[i])
			}
		}
		reduced = append(reduced, kept)
	}

	if len(reduced) == 0 {
		return denyAllFilter
	}

	return reduced
}

func setMatchesMachine(set *netipx.IPSet, addrs []netip.Addr, routes []netip.Prefix) bool {
	for _, addr := range addrs {
		if set.Contains(addr) {
			return true
		}
	}
	for _, route := range routes {
		if set.OverlapsPrefix(route) {
			return true
		}
	}

	return false
}
