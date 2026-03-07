package pipeline

import (
	"sort"
	"sync"
)

type Candidate struct {
	Name          string              `json:"name"`
	Sources       map[string]struct{} `json:"-"`
	Resolved      bool                `json:"resolved"`
	IPs           map[string]struct{} `json:"-"`
	ResolverVotes int                 `json:"resolver_votes"`
	Wildcard      bool                `json:"wildcard"`
	Live          bool                `json:"live"`
	LiveURLs      []string            `json:"live_urls,omitempty"`
	OpenPorts     map[int]struct{}    `json:"-"`
	Confidence    float64             `json:"confidence"`
	Notes         []string            `json:"notes,omitempty"`
}

func (c *Candidate) SourceCount() int {
	return len(c.Sources)
}

func (c *Candidate) IPList() []string {
	if len(c.IPs) == 0 {
		return nil
	}
	out := make([]string, 0, len(c.IPs))
	for ip := range c.IPs {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func (c *Candidate) SourceList() []string {
	if len(c.Sources) == 0 {
		return nil
	}
	out := make([]string, 0, len(c.Sources))
	for s := range c.Sources {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func (c *Candidate) PortList() []int {
	if len(c.OpenPorts) == 0 {
		return nil
	}
	out := make([]int, 0, len(c.OpenPorts))
	for p := range c.OpenPorts {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

type SafeStore struct {
	mu      sync.RWMutex
	entries map[string]*Candidate
}

func NewSafeStore() *SafeStore {
	return &SafeStore{
		entries: make(map[string]*Candidate, 4096),
	}
}

func (s *SafeStore) Add(name, source string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.entries[name]
	if !ok {
		c = &Candidate{
			Name:      name,
			Sources:   map[string]struct{}{source: {}},
			IPs:       make(map[string]struct{}),
			OpenPorts: make(map[int]struct{}),
		}
		s.entries[name] = c
		return true
	}
	c.Sources[source] = struct{}{}
	return false
}

func (s *SafeStore) Exists(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.entries[name]
	return ok
}

func (s *SafeStore) AddBatch(names []string, source string) int {
	added := 0
	for _, n := range names {
		if s.Add(n, source) {
			added++
		}
	}
	return added
}

func (s *SafeStore) MarkResolved(name string, ips []string, votes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.entries[name]
	if !ok {
		return
	}
	c.Resolved = true
	c.ResolverVotes = votes
	if c.IPs == nil {
		c.IPs = make(map[string]struct{}, len(ips))
	}
	for _, ip := range ips {
		c.IPs[ip] = struct{}{}
	}
}

func (s *SafeStore) MarkWildcard(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.entries[name]; ok {
		c.Wildcard = true
	}
}

func (s *SafeStore) MarkLive(name, url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.entries[name]
	if !ok {
		return
	}
	c.Live = true
	for _, u := range c.LiveURLs {
		if u == url {
			return
		}
	}
	c.LiveURLs = append(c.LiveURLs, url)
}

func (s *SafeStore) AddNote(name, note string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.entries[name]
	if !ok {
		return
	}
	c.Notes = append(c.Notes, note)
}

func (s *SafeStore) MarkPortOpen(name string, port int) {
	if port <= 0 || port > 65535 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.entries[name]
	if !ok {
		return
	}
	if c.OpenPorts == nil {
		c.OpenPorts = make(map[int]struct{}, 4)
	}
	c.OpenPorts[port] = struct{}{}
}

func (s *SafeStore) Snapshot() []*Candidate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Candidate, 0, len(s.entries))
	for _, c := range s.entries {
		cp := &Candidate{
			Name:          c.Name,
			Sources:       make(map[string]struct{}, len(c.Sources)),
			Resolved:      c.Resolved,
			IPs:           make(map[string]struct{}, len(c.IPs)),
			ResolverVotes: c.ResolverVotes,
			Wildcard:      c.Wildcard,
			Live:          c.Live,
			LiveURLs:      append([]string(nil), c.LiveURLs...),
			OpenPorts:     make(map[int]struct{}, len(c.OpenPorts)),
			Confidence:    c.Confidence,
			Notes:         append([]string(nil), c.Notes...),
		}
		for sName := range c.Sources {
			cp.Sources[sName] = struct{}{}
		}
		for ip := range c.IPs {
			cp.IPs[ip] = struct{}{}
		}
		for p := range c.OpenPorts {
			cp.OpenPorts[p] = struct{}{}
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *SafeStore) Names() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.entries))
	for n := range s.entries {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (s *SafeStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}
