package pipeline

import (
	"fmt"
	"testing"
)

func TestTrimCollectorSkipReason(t *testing.T) {
	got := trimCollectorSkipReason(fmt.Errorf("%w: PDCP_API_KEY not set", errCollectorSkipped))
	if got != "PDCP_API_KEY not set" {
		t.Fatalf("got %q", got)
	}
}

func TestUnusualPassiveDiagnosticsFiltersCompleted(t *testing.T) {
	diags := []PassiveCollectorDiagnostic{
		{Collector: "subfinder", Status: "completed"},
		{Collector: "chaos", Status: "skipped", Reason: "missing api key"},
		{Collector: "amass", Status: "failed", Reason: "cli compatibility failure"},
		{Collector: "crtsh", Status: "downgraded", Reason: "capped"},
	}
	got := unusualPassiveDiagnostics(diags)
	if len(got) != 3 {
		t.Fatalf("got %d diagnostics, want 3", len(got))
	}
	for _, diag := range got {
		if diag.Status == "completed" {
			t.Fatalf("unexpected completed diagnostic: %#v", diag)
		}
	}
}
