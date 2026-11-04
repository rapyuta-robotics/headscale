// Command filtercheck compares two sets of map responses dumped by
// hack/loadgen -verify -dump, one from a server sending the full packet filter
// and one from a server reducing it per machine. It checks, with the tailscale
// client's own filter code, that every machine accepts and drops exactly the
// same inbound packets with either filter, and that peer lists did not change.
//
// A packet can only reach a machine from itself or from a peer whose
// AllowedIPs contain its source (WireGuard drops anything else), so decisions
// must match for those sources. Differences for other sources are counted
// separately: the reduced filter drops rules no peer can match.
//
//	go run ./hack/filtercheck -base out/base.dump -fix out/fix.dump
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

func main() {
	var (
		baseDir = flag.String("base", "", "dump directory from the server sending the full filter")
		fixDir  = flag.String("fix", "", "dump directory from the server reducing the filter")
		ports   = flag.String("ports", "22,443", "TCP destination ports to check")
	)
	flag.Parse()

	var dstPorts []uint16
	for _, p := range strings.Split(*ports, ",") {
		var n uint16
		if _, err := fmt.Sscan(p, &n); err != nil {
			log.Fatalf("port %q: %v", p, err)
		}
		dstPorts = append(dstPorts, n)
	}

	names, err := filepath.Glob(filepath.Join(*baseDir, "*.json"))
	if err != nil || len(names) == 0 {
		log.Fatalf("no dumps in %s: %v", *baseDir, err)
	}

	base := map[string]*tailcfg.MapResponse{}
	var srcCandidates []netip.Addr
	for _, name := range names {
		resp := mustLoad(name)
		base[filepath.Base(name)] = resp
		for _, p := range resp.Node.Addresses {
			srcCandidates = append(srcCandidates, p.Addr())
		}
		// Packets forwarded by a peer subnet router carry addresses from
		// its routes.
		for _, p := range resp.Node.AllowedIPs {
			if !p.IsSingleIP() {
				srcCandidates = append(srcCandidates, samples(p)...)
			}
		}
	}
	srcCandidates = append(srcCandidates, netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("192.0.2.1"))
	srcCandidates = dedup(srcCandidates)

	var machines, checks, regressions, widenings, peerDiffs, missing, unreachable int
	for file, b := range base {
		f, err := load(filepath.Join(*fixDir, file))
		if err != nil {
			missing++
			continue
		}
		machines++

		if got, want := peerSet(f), peerSet(b); got != want {
			peerDiffs++
			log.Printf("PEERS DIFFER %s: base %q fix %q", b.Node.Name, want, got)
		}

		// The machine receives packets for its own addresses and for every
		// route peers send to it.
		var local netipx.IPSetBuilder
		var dsts []netip.Addr
		for _, p := range b.Node.AllowedIPs {
			local.AddPrefix(p)
			if p.IsSingleIP() {
				dsts = append(dsts, p.Addr())
			} else {
				dsts = append(dsts, samples(p)...)
				// A route covering tailnet addresses also receives
				// packets for the machines inside it.
				for _, a := range srcCandidates {
					if p.Contains(a) {
						dsts = append(dsts, a)
					}
				}
			}
		}
		localNets, _ := local.IPSet()
		dsts = dedup(dsts)

		// Sources that can reach the machine at all.
		var reach netipx.IPSetBuilder
		for _, p := range b.Node.Addresses {
			reach.AddPrefix(p)
		}
		for _, peer := range b.Peers {
			for _, p := range peer.AllowedIPs {
				reach.AddPrefix(p)
			}
		}
		reachable, _ := reach.IPSet()

		full := newFilter(b.PacketFilter, localNets)
		reduced := newFilter(f.PacketFilter, localNets)
		for _, src := range srcCandidates {
			for _, dst := range dsts {
				for _, port := range dstPorts {
					checks++
					want := full.CheckTCP(src, dst, port)
					got := reduced.CheckTCP(src, dst, port)
					if got == want {
						continue
					}
					if !reachable.Contains(src) {
						unreachable++
						continue
					}
					if want == filter.Accept {
						regressions++
						if regressions <= 20 {
							log.Printf("REGRESSION %s: %s -> %s:%d accepted with the full filter, %v with the reduced one", b.Node.Name, src, dst, port, got)
						}
					} else {
						widenings++
						if widenings <= 20 {
							log.Printf("WIDENING %s: %s -> %s:%d %v with the full filter, accepted with the reduced one", b.Node.Name, src, dst, port, want)
						}
					}
				}
			}
		}
	}

	fmt.Printf("machines=%d missing_in_fix=%d checks=%d regressions=%d widenings=%d peer_list_diffs=%d differ_only_for_non_peer_sources=%d\n",
		machines, missing, checks, regressions, widenings, peerDiffs, unreachable)
	if regressions+widenings+peerDiffs+missing > 0 {
		os.Exit(1)
	}
}

func newFilter(rules []tailcfg.FilterRule, localNets *netipx.IPSet) *filter.Filter {
	matches, err := filter.MatchesFromFilterRules(rules)
	if err != nil {
		log.Fatalf("parsing filter: %v", err)
	}

	return filter.New(matches, localNets, localNets, nil, logger.Discard)
}

// samples returns a few addresses spread over a prefix.
func samples(p netip.Prefix) []netip.Addr {
	r := netipx.RangeOfPrefix(p)
	first, last := r.From(), r.To()

	return []netip.Addr{first, first.Next(), last.Prev(), last}
}

func peerSet(resp *tailcfg.MapResponse) string {
	var peers []string
	for _, p := range resp.Peers {
		peers = append(peers, fmt.Sprintf("%s=%v", p.Key.ShortString(), p.AllowedIPs))
	}
	sort.Strings(peers)

	return strings.Join(peers, " ")
}

func dedup(addrs []netip.Addr) []netip.Addr {
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	out := addrs[:0]
	for i, a := range addrs {
		if i == 0 || a != addrs[i-1] {
			out = append(out, a)
		}
	}

	return out
}

func load(path string) (*tailcfg.MapResponse, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var resp tailcfg.MapResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if resp.Node == nil {
		return nil, fmt.Errorf("%s: no Node", path)
	}

	return &resp, nil
}

func mustLoad(path string) *tailcfg.MapResponse {
	resp, err := load(path)
	if err != nil {
		log.Fatal(err)
	}

	return resp
}
