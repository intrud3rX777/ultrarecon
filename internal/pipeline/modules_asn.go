package pipeline

import (
	"context"
	"encoding/binary"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

var cidrPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}/(?:[0-9]|[1-2][0-9]|3[0-2])\b`)

func runASNExpansionCollection(
	ctx context.Context,
	cfg config.Config,
	resolvers []dnsResolver,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []string {
	if !cfg.EnableASNExpansion || len(resolvers) == 0 {
		return nil
	}
	if !util.HaveCommand("asnmap") {
		*toolErrs = append(*toolErrs, ToolError{
			Stage: "asn_expansion",
			Tool:  "asnmap",
			Error: "tool missing: asnmap",
		})
		return nil
	}

	asnTimeout := minDuration(cfg.ToolTimeout, 90*time.Second)
	if cfg.HomeSafe {
		asnTimeout = minDuration(asnTimeout, 60*time.Second)
	}
	if asnTimeout < 20*time.Second {
		asnTimeout = 20 * time.Second
	}

	subCtx, cancel := context.WithTimeout(ctx, asnTimeout)
	res := util.RunCommand(subCtx, asnTimeout, "asnmap", "-d", cfg.Domain, "-silent", "-j")
	cancel()

	timedOut := subCtx.Err() == context.DeadlineExceeded
	if res.Err != nil {
		// Retry plain mode only when first run did not timeout.
		if !timedOut {
			subCtx2, cancel2 := context.WithTimeout(ctx, asnTimeout)
			res2 := util.RunCommand(subCtx2, asnTimeout, "asnmap", "-d", cfg.Domain, "-silent")
			cancel2()
			if res2.Err == nil || strings.TrimSpace(res2.Stdout) != "" {
				res = res2
			} else {
				*toolErrs = append(*toolErrs, ToolError{
					Stage: "asn_expansion",
					Tool:  "asnmap",
					Error: res.Err.Error(),
				})
				return nil
			}
		} else if strings.TrimSpace(res.Stdout) == "" {
			*toolErrs = append(*toolErrs, ToolError{
				Stage: "asn_expansion",
				Tool:  "asnmap",
				Error: "timed out; no output",
			})
			logf("[asn] timeout after %s", asnTimeout)
			return nil
		}
	}

	cidrs := extractCIDRsFromBlob(res.Stdout)
	hints := extractScopedHostsFromBlob(res.Stdout, cfg.Domain)
	if len(cidrs) > cfg.MaxASNCIDRs {
		cidrs = cidrs[:cfg.MaxASNCIDRs]
	}
	if len(cidrs) == 0 && len(hints) == 0 {
		return nil
	}

	ipSamples := sampleIPsFromCIDRs(cidrs, cfg.ASNIPsPerCIDR, cfg.MaxASNProbeIPs)
	ptrHosts := runASNPTRCollection(ctx, cfg, resolvers, ipSamples)

	out := append(hints, ptrHosts...)
	out = normalizeCandidates(out, cfg.Domain)
	if len(out) > cfg.MaxASNCandidates {
		out = out[:cfg.MaxASNCandidates]
	}
	logf("[asn] cidrs=%d sampled_ips=%d candidates=%d", len(cidrs), len(ipSamples), len(out))
	return out
}

func extractCIDRsFromBlob(blob string) []string {
	if strings.TrimSpace(blob) == "" {
		return nil
	}
	matches := cidrPattern.FindAllString(blob, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, c := range matches {
		c = strings.TrimSpace(c)
		ip, netw, err := net.ParseCIDR(c)
		if err != nil || ip == nil || netw == nil {
			continue
		}
		if ip.To4() == nil {
			continue
		}
		k := netw.String()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sampleIPsFromCIDRs(cidrs []string, perCIDR, maxTotal int) []string {
	if len(cidrs) == 0 || perCIDR <= 0 || maxTotal <= 0 {
		return nil
	}
	out := make([]string, 0, minInt(len(cidrs)*perCIDR, maxTotal))
	for _, c := range cidrs {
		if len(out) >= maxTotal {
			break
		}
		ip, netw, err := net.ParseCIDR(c)
		if err != nil || ip == nil || netw == nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		ones, bits := netw.Mask.Size()
		if bits != 32 || ones < 0 || ones > 32 {
			continue
		}
		base := binary.BigEndian.Uint32(v4)
		hostCount := uint64(1) << uint64(32-ones)
		want := perCIDR
		if hostCount < uint64(want) {
			want = int(hostCount)
		}
		for i := 0; i < want && len(out) < maxTotal; i++ {
			var n uint32
			if ones >= 31 {
				n = base + uint32(i)
			} else {
				n = base + 1 + uint32(i)
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], n)
			out = append(out, net.IPv4(b[0], b[1], b[2], b[3]).String())
		}
	}
	return util.UniqueSorted(out)
}

func runASNPTRCollection(ctx context.Context, cfg config.Config, resolvers []dnsResolver, ips []string) []string {
	if len(resolvers) == 0 || len(ips) == 0 {
		return nil
	}
	tasks := make(chan string, len(ips))
	for _, ip := range ips {
		tasks <- ip
	}
	close(tasks)

	workers := minInt(cfg.DNSThreads, 140)
	if cfg.HomeSafe {
		workers = minInt(workers, 35)
	}
	if workers < 1 {
		workers = 1
	}

	var rrCounter uint32
	outCh := make(chan []string, len(ips))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range tasks {
				if ctx.Err() != nil {
					return
				}
				start := int(atomic.AddUint32(&rrCounter, 1)-1) % len(resolvers)
				var hosts []string
				for retry := 0; retry <= cfg.DNSRetries; retry++ {
					r := resolvers[(start+retry)%len(resolvers)].Addr
					ptr, err := queryPTR(r, ip, cfg.DNSQueryTimeout)
					if err != nil || len(ptr) == 0 {
						continue
					}
					hosts = ptr
					break
				}
				if len(hosts) > 0 {
					outCh <- hosts
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(outCh)
	}()

	out := make([]string, 0, len(ips))
	for hosts := range outCh {
		out = append(out, hosts...)
	}
	return util.UniqueSorted(out)
}

func queryPTR(resolver, ip string, timeout time.Duration) ([]string, error) {
	ptrName, err := dns.ReverseAddr(ip)
	if err != nil {
		return nil, err
	}
	client := &dns.Client{
		Timeout: timeout,
		Net:     "udp",
	}
	m := new(dns.Msg)
	m.SetQuestion(ptrName, dns.TypePTR)
	in, _, err := client.Exchange(m, ensureResolverPort(resolver))
	if err != nil || in == nil {
		return nil, err
	}
	if in.Rcode != dns.RcodeSuccess {
		return nil, err
	}
	out := make([]string, 0, len(in.Answer))
	for _, ans := range in.Answer {
		ptr, ok := ans.(*dns.PTR)
		if !ok {
			continue
		}
		h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ptr.Ptr)), ".")
		if h != "" {
			out = append(out, h)
		}
	}
	return util.UniqueSorted(out), nil
}
