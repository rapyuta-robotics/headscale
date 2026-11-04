package hscontrol

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

func Test_reduceFilterRules(t *testing.T) {
	allPorts := tailcfg.PortRange{First: 0, Last: 65535}
	dst := func(ip string) tailcfg.NetPortRange {
		return tailcfg.NetPortRange{IP: ip, Ports: allPorts}
	}
	machine := func(addr string, routes ...string) *Machine {
		m := &Machine{IPAddresses: MachineAddresses{netip.MustParseAddr(addr)}}
		for _, r := range routes {
			m.HostInfo.RoutableIPs = append(m.HostInfo.RoutableIPs, netip.MustParsePrefix(r))
		}

		return m
	}
	peer := func(addr string, routes ...string) *tailcfg.Node {
		self := netip.MustParsePrefix(addr + "/32")
		n := &tailcfg.Node{
			Addresses:  []netip.Prefix{self},
			AllowedIPs: []netip.Prefix{self},
		}
		for _, r := range routes {
			n.AllowedIPs = append(n.AllowedIPs, netip.MustParsePrefix(r))
		}

		return n
	}

	// Rules as a per-user policy generates them: each user may reach its own
	// machines and its site subnet. User B reuses user A's site subnet and
	// user C lists a tailnet range as one of its subnets.
	userA := tailcfg.FilterRule{
		SrcIPs:   []string{"100.64.0.1/32", "100.64.0.2/32"},
		DstPorts: []tailcfg.NetPortRange{dst("100.64.0.1/32"), dst("100.64.0.2/32"), dst("10.0.4.0/24")},
	}
	userB := tailcfg.FilterRule{
		SrcIPs:   []string{"100.64.0.3/32"},
		DstPorts: []tailcfg.NetPortRange{dst("100.64.0.3/32"), dst("10.0.4.0/24")},
	}
	userC := tailcfg.FilterRule{
		SrcIPs:   []string{"100.64.0.4/32"},
		DstPorts: []tailcfg.NetPortRange{dst("100.64.0.4/32"), dst("100.64.0.0/16")},
	}
	// A user with no machines yet: no sources.
	empty := tailcfg.FilterRule{SrcIPs: []string{}, DstPorts: []tailcfg.NetPortRange{dst("100.64.0.1/32")}}
	all := []tailcfg.FilterRule{userA, userB, userC, empty}

	tests := []struct {
		name    string
		machine *Machine
		peers   []*tailcfg.Node
		rules   []tailcfg.FilterRule
		want    []tailcfg.FilterRule
	}{
		{
			name:    "machine gets only its own user's rule, trimmed to itself",
			machine: machine("100.64.0.1"),
			peers:   []*tailcfg.Node{peer("100.64.0.2")},
			rules:   all,
			want: []tailcfg.FilterRule{{
				SrcIPs:   userA.SrcIPs,
				DstPorts: []tailcfg.NetPortRange{dst("100.64.0.1/32")},
			}},
		},
		{
			name:    "subnet router drops other users' rules for the same subnet",
			machine: machine("100.64.0.2", "10.0.4.0/24"),
			peers:   []*tailcfg.Node{peer("100.64.0.1")},
			rules:   all,
			want: []tailcfg.FilterRule{{
				SrcIPs:   userA.SrcIPs,
				DstPorts: []tailcfg.NetPortRange{dst("100.64.0.2/32"), dst("10.0.4.0/24")},
			}},
		},
		{
			name:    "sources are trimmed to the machine and its peers",
			machine: machine("100.64.0.1"),
			peers:   nil,
			rules:   []tailcfg.FilterRule{userA},
			want: []tailcfg.FilterRule{{
				SrcIPs:   []string{"100.64.0.1/32"},
				DstPorts: []tailcfg.NetPortRange{dst("100.64.0.1/32")},
			}},
		},
		{
			name:    "source behind a peer's subnet route is kept",
			machine: machine("100.64.0.1"),
			peers:   []*tailcfg.Node{peer("100.64.0.2", "10.0.4.0/24")},
			rules: []tailcfg.FilterRule{{
				SrcIPs:   []string{"10.0.4.0/24", "10.99.0.0/16"},
				DstPorts: []tailcfg.NetPortRange{dst("100.64.0.1/32")},
			}},
			want: []tailcfg.FilterRule{{
				SrcIPs:   []string{"10.0.4.0/24"},
				DstPorts: []tailcfg.NetPortRange{dst("100.64.0.1/32")},
			}},
		},
		{
			name:    "route overlapping part of a destination keeps it",
			machine: machine("100.64.0.9", "10.0.4.128/25"),
			peers:   []*tailcfg.Node{peer("100.64.0.1")},
			rules:   []tailcfg.FilterRule{userA},
			want: []tailcfg.FilterRule{{
				SrcIPs:   []string{"100.64.0.1/32"},
				DstPorts: []tailcfg.NetPortRange{dst("10.0.4.0/24")},
			}},
		},
		{
			name:    "exit node keeps every rule its peers can match",
			machine: machine("100.64.0.9", "0.0.0.0/0", "::/0"),
			peers:   []*tailcfg.Node{peer("100.64.0.1"), peer("100.64.0.3")},
			rules:   all,
			want: []tailcfg.FilterRule{
				{SrcIPs: []string{"100.64.0.1/32"}, DstPorts: userA.DstPorts},
				{SrcIPs: userB.SrcIPs, DstPorts: userB.DstPorts},
			},
		},
		{
			name:    "wildcard applies to everyone",
			machine: machine("100.64.0.3"),
			peers:   []*tailcfg.Node{peer("100.64.0.1")},
			rules:   tailcfg.FilterAllowAll,
			want:    tailcfg.FilterAllowAll,
		},
		{
			name:    "machine no rule applies to gets deny all, not an empty filter",
			machine: machine("100.64.0.7"),
			peers:   []*tailcfg.Node{peer("100.64.0.1")},
			rules:   all,
			want:    denyAllFilter,
		},
		{
			name:    "unparsable destination matches nothing",
			machine: machine("100.64.0.1"),
			peers:   []*tailcfg.Node{peer("100.64.0.2")},
			rules: []tailcfg.FilterRule{{
				SrcIPs:   []string{"100.64.0.2/32"},
				DstPorts: []tailcfg.NetPortRange{dst("not-an-ip"), dst("100.64.0.1/32")},
			}},
			want: []tailcfg.FilterRule{{
				SrcIPs:   []string{"100.64.0.2/32"},
				DstPorts: []tailcfg.NetPortRange{dst("100.64.0.1/32")},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reduceFilterRules(tt.machine, tt.peers, compileFilterRules(tt.rules))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("reduceFilterRules() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// The deny-all filter must survive JSON encoding (an empty PacketFilter is
// omitted and the client keeps its previous rules) and must block everything
// in the tailscale client's own filter.
func Test_denyAllFilter(t *testing.T) {
	body, err := json.Marshal(tailcfg.MapResponse{PacketFilter: denyAllFilter})
	if err != nil {
		t.Fatal(err)
	}
	var resp tailcfg.MapResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.PacketFilter == nil {
		t.Fatalf("PacketFilter dropped from %s", body)
	}

	matches, err := filter.MatchesFromFilterRules(resp.PacketFilter)
	if err != nil {
		t.Fatal(err)
	}
	self := netip.MustParseAddr("100.64.0.1")
	local, err := parseIPSet("100.64.0.1/32", nil)
	if err != nil {
		t.Fatal(err)
	}
	f := filter.New(matches, local, local, nil, t.Logf)
	if got := f.CheckTCP(netip.MustParseAddr("100.64.0.2"), self, 22); got != filter.Drop {
		t.Errorf("CheckTCP() = %v, want Drop", got)
	}
}
