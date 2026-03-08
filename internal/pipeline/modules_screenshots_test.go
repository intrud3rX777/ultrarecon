package pipeline

import "testing"

func TestPreferredLiveURLPrefersHTTPS(t *testing.T) {
	got := preferredLiveURL([]string{
		"http://app.example.com",
		"https://app.example.com",
		"https://app.example.com/login",
	})
	if got != "https://app.example.com" {
		t.Fatalf("preferredLiveURL() = %q, want https root", got)
	}
}

func TestSelectScreenshotTargetsFiltersAndRanks(t *testing.T) {
	store := NewSafeStore()

	store.Add("alpha.example.com", "passive:a")
	store.Add("alpha.example.com", "passive:b")
	store.MarkResolved("alpha.example.com", []string{"1.1.1.1"}, 2)
	store.MarkLive("alpha.example.com", "https://alpha.example.com")

	store.Add("beta.example.com", "passive:a")
	store.Add("beta.example.com", "passive:b")
	store.Add("beta.example.com", "passive:c")
	store.MarkResolved("beta.example.com", []string{"2.2.2.2"}, 2)
	store.MarkLive("beta.example.com", "https://beta.example.com")
	store.MarkPortOpen("beta.example.com", 443)

	store.Add("wild.example.com", "passive:a")
	store.MarkResolved("wild.example.com", []string{"3.3.3.3"}, 1)
	store.MarkLive("wild.example.com", "https://wild.example.com")
	store.MarkWildcard("wild.example.com")

	targets := selectScreenshotTargets(store, 1)
	if len(targets) != 1 {
		t.Fatalf("selectScreenshotTargets() len = %d, want 1", len(targets))
	}
	if targets[0].Host != "beta.example.com" {
		t.Fatalf("selectScreenshotTargets() picked %q, want beta.example.com", targets[0].Host)
	}
}
