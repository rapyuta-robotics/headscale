// Command loadgen simulates a fleet of Tailscale clients against a headscale
// server over the real ts2021 control protocol (Noise handshake + HTTP/2).
//
// Machine identities are read from a headscale database: the public node key
// and the stored Hostinfo of each machine are replayed verbatim, so the server
// evaluates exactly the same machines, users and tags as it does in
// production. headscale 0.22 resolves a MapRequest by node key alone, so a
// fresh random machine key per simulated client is sufficient.
//
// Each simulated client keeps one streaming MapRequest open (the long poll)
// and periodically sends endpoint-only updates, matching what a real client
// does when its STUN-discovered endpoints change. Optionally it drops and
// re-opens the stream on a fixed cadence to reproduce a reconnect storm.
//
// Example:
//
//	go run ./hack/loadgen -n 800 -endpoint-rate 11.8
//	go run ./hack/loadgen -n 800 -endpoint-rate 6.4 -reconnect-every 22s
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"tailscale.com/control/controlclient"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func main() {
	var (
		serverURL      = flag.String("server", "http://127.0.0.1:8080", "headscale server URL")
		dbDSN          = flag.String("db", "postgres://postgres:headscale@127.0.0.1:15432/headscale?sslmode=disable", "headscale database DSN (machines are read from here)")
		n              = flag.Int("n", 800, "number of machines to simulate (most recently seen first)")
		endpointRate   = flag.Float64("endpoint-rate", 11.8, "fleet-wide endpoint-update requests per second (0 disables)")
		reconnectEvery = flag.Duration("reconnect-every", 0, "drop and re-open the map stream this often per client (0 = keep streams open)")
		ramp           = flag.Duration("ramp", 30*time.Second, "spread initial connections over this duration")
		statsEvery     = flag.Duration("stats", 5*time.Second, "print stats this often")
		duration       = flag.Duration("duration", 0, "stop after this long (0 = until interrupted)")
	)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *duration > 0 {
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}

	machines, err := loadMachines(ctx, *dbDSN, *n)
	if err != nil {
		log.Fatalf("loading machines: %v", err)
	}
	serverKey, err := fetchServerKey(ctx, *serverURL)
	if err != nil {
		log.Fatalf("fetching server key: %v", err)
	}
	log.Printf("loaded %d machines from db; server noise key %s", len(machines), serverKey.ShortString())

	var perClientInterval time.Duration
	if *endpointRate > 0 {
		perClientInterval = time.Duration(float64(len(machines)) / *endpointRate * float64(time.Second))
		log.Printf("endpoint updates: %.2f/s fleet-wide -> one per client every %s", *endpointRate, perClientInterval.Round(time.Millisecond))
	}
	if *reconnectEvery > 0 {
		log.Printf("reconnect storm: each client re-opens its stream every %s", *reconnectEvery)
	}

	st := &stats{}
	var wg sync.WaitGroup
	for i, m := range machines {
		c := newClient(i, m, *serverURL, serverKey)
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Stagger connections over the ramp window.
			delay := time.Duration(rand.Int63n(int64(*ramp) + 1))
			if !sleepCtx(ctx, delay) {
				return
			}
			var cwg sync.WaitGroup
			cwg.Add(1)
			go func() { defer cwg.Done(); c.runStream(ctx, *reconnectEvery, st) }()
			if perClientInterval > 0 {
				cwg.Add(1)
				go func() { defer cwg.Done(); c.runEndpointUpdates(ctx, perClientInterval, st) }()
			}
			cwg.Wait()
			c.nc.Close()
		}()
	}

	go st.printLoop(ctx, *statsEvery)
	wg.Wait()
	st.print("final")
}

type machineRow struct {
	Hostname string
	NodeKey  key.NodePublic
	Hostinfo tailcfg.Hostinfo
}

func loadMachines(ctx context.Context, dsn string, n int) ([]machineRow, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, `
		SELECT hostname, node_key, host_info
		FROM machines
		WHERE node_key <> ''
		  AND (expiry IS NULL OR expiry < '1970-01-01' OR expiry > now())
		ORDER BY last_seen DESC NULLS LAST
		LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []machineRow
	for rows.Next() {
		var (
			m        machineRow
			nodeKey  string
			hostInfo []byte
		)
		if err := rows.Scan(&m.Hostname, &nodeKey, &hostInfo); err != nil {
			return nil, err
		}
		if err := m.NodeKey.UnmarshalText([]byte("nodekey:" + nodeKey)); err != nil {
			log.Printf("skipping %s: bad node key: %v", m.Hostname, err)
			continue
		}
		if len(hostInfo) > 0 {
			if err := json.Unmarshal(hostInfo, &m.Hostinfo); err != nil {
				log.Printf("skipping %s: bad host_info: %v", m.Hostname, err)
				continue
			}
		}
		if m.Hostinfo.Hostname == "" {
			m.Hostinfo.Hostname = m.Hostname
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func fetchServerKey(ctx context.Context, serverURL string) (key.MachinePublic, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/key?v=%d", serverURL, tailcfg.CurrentCapabilityVersion), nil)
	if err != nil {
		return key.MachinePublic{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return key.MachinePublic{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return key.MachinePublic{}, fmt.Errorf("/key returned %s", resp.Status)
	}
	var keys tailcfg.OverTLSPublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return key.MachinePublic{}, err
	}
	return keys.PublicKey, nil
}

type client struct {
	id        int
	m         machineRow
	serverURL string
	nc        *controlclient.NoiseClient
	disco     key.DiscoPublic
	epSeq     uint64
}

func newClient(id int, m machineRow, serverURL string, serverKey key.MachinePublic) *client {
	nc, err := controlclient.NewNoiseClient(key.NewMachine(), serverKey, serverURL,
		&tsdial.Dialer{Logf: logger.Discard}, nil)
	if err != nil {
		log.Fatalf("creating noise client for %s: %v", m.Hostname, err)
	}
	return &client{
		id:        id,
		m:         m,
		serverURL: serverURL,
		nc:        nc,
		disco:     key.NewDisco().Public(),
	}
}

// endpoints returns one stable LAN endpoint plus a public endpoint whose port
// changes on every call, mimicking STUN-discovered endpoints flapping behind
// a load balancer.
func (c *client) endpoints() []string {
	c.epSeq++
	return []string{
		fmt.Sprintf("10.%d.%d.%d:41641", (c.id>>16)&0xff, (c.id>>8)&0xff, c.id&0xff),
		fmt.Sprintf("203.0.113.%d:%d", c.id%250+1, 10000+int(c.epSeq%50000)),
	}
}

func (c *client) mapRequest(stream, omitPeers bool) *tailcfg.MapRequest {
	hi := c.m.Hostinfo
	return &tailcfg.MapRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		Compress:  "zstd",
		KeepAlive: true,
		NodeKey:   c.m.NodeKey,
		DiscoKey:  c.disco,
		Stream:    stream,
		OmitPeers: omitPeers,
		Hostinfo:  &hi,
		Endpoints: c.endpoints(),
	}
}

func (c *client) do(ctx context.Context, mr *tailcfg.MapRequest) (*http.Response, error) {
	body, err := json.Marshal(mr)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/machine/map", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.nc.Do(req)
}

// runStream keeps a streaming MapRequest open, reconnecting when it drops.
// With reconnectEvery > 0 it deliberately tears the stream down on that
// cadence, which makes the server send a fresh full map each time.
func (c *client) runStream(ctx context.Context, reconnectEvery time.Duration, st *stats) {
	const backoff = 2 * time.Second
	for ctx.Err() == nil {
		sctx, cancel := context.WithCancel(ctx)
		if reconnectEvery > 0 {
			jitter := time.Duration(rand.Int63n(int64(reconnectEvery / 4)))
			sctx, cancel = context.WithTimeout(ctx, reconnectEvery+jitter)
		}

		resp, err := c.do(sctx, c.mapRequest(true, false))
		if err != nil {
			cancel()
			if ctx.Err() == nil {
				st.streamErr.Add(1)
				sleepCtx(ctx, backoff)
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			cancel()
			st.streamBad.Add(1)
			sleepCtx(ctx, backoff)
			continue
		}

		st.streamsOpen.Add(1)
		st.streamOpens.Add(1)
		_, copyErr := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		st.streamsOpen.Add(-1)
		cancel()

		if ctx.Err() != nil {
			return
		}
		if reconnectEvery == 0 || !errors.Is(copyErr, context.DeadlineExceeded) {
			// Server closed the stream on us; back off before re-polling.
			st.streamDrops.Add(1)
			sleepCtx(ctx, backoff)
		}
	}
}

// runEndpointUpdates sends a non-streaming, peers-omitted MapRequest at a
// fixed interval with a random initial phase, so the fleet-wide rate is
// smooth rather than bursty.
func (c *client) runEndpointUpdates(ctx context.Context, interval time.Duration, st *stats) {
	if !sleepCtx(ctx, time.Duration(rand.Int63n(int64(interval)))) {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		start := time.Now()
		rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		resp, err := c.do(rctx, c.mapRequest(false, true))
		if err != nil {
			cancel()
			if ctx.Err() == nil {
				st.epErr.Add(1)
			}
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		cancel()
		if resp.StatusCode == http.StatusOK {
			st.epOK.Add(1)
			st.recordLatency(time.Since(start))
		} else {
			st.epBad.Add(1)
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

type stats struct {
	streamsOpen atomic.Int64
	streamOpens atomic.Int64
	streamDrops atomic.Int64
	streamErr   atomic.Int64
	streamBad   atomic.Int64
	epOK        atomic.Int64
	epErr       atomic.Int64
	epBad       atomic.Int64

	mu      sync.Mutex
	lat     []time.Duration // endpoint-update latencies since last print
	lastOK  int64
	lastOpn int64
	lastAt  time.Time
}

func (s *stats) recordLatency(d time.Duration) {
	s.mu.Lock()
	s.lat = append(s.lat, d)
	s.mu.Unlock()
}

func (s *stats) printLoop(ctx context.Context, every time.Duration) {
	s.lastAt = time.Now()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.print("")
		}
	}
}

func (s *stats) print(tag string) {
	s.mu.Lock()
	lat := s.lat
	s.lat = nil
	now := time.Now()
	dt := now.Sub(s.lastAt).Seconds()
	s.lastAt = now
	ok := s.epOK.Load()
	opens := s.streamOpens.Load()
	okRate := float64(ok-s.lastOK) / dt
	openRate := float64(opens-s.lastOpn) / dt
	s.lastOK, s.lastOpn = ok, opens
	s.mu.Unlock()

	var p50, p99, max time.Duration
	if len(lat) > 0 {
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		p50 = lat[len(lat)/2]
		p99 = lat[len(lat)*99/100]
		max = lat[len(lat)-1]
	}
	log.Printf("%sstreams open=%d opens/s=%.2f drops=%d err=%d bad=%d | endpoint ok/s=%.2f err=%d bad=%d | lat p50=%s p99=%s max=%s",
		prefix(tag), s.streamsOpen.Load(), openRate, s.streamDrops.Load(), s.streamErr.Load(), s.streamBad.Load(),
		okRate, s.epErr.Load(), s.epBad.Load(),
		p50.Round(time.Millisecond), p99.Round(time.Millisecond), max.Round(time.Millisecond))
}

func prefix(tag string) string {
	if tag == "" {
		return ""
	}
	return tag + ": "
}
