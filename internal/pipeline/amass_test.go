package pipeline

import (
	"errors"
	"strings"
	"testing"

	"ultrarecon/internal/util"
)

func TestShouldRetryAmassOnFlagErrors(t *testing.T) {
	res := util.CmdResult{
		Err:    errors.New("exit status 1"),
		Stderr: "flag provided but not defined: -noalts",
	}
	if !shouldRetryAmass(res) {
		t.Fatal("expected shouldRetryAmass to retry on flag compatibility errors")
	}
}

func TestExplainAmassFailureClassifiesCommonErrors(t *testing.T) {
	cases := []struct {
		name string
		res  util.CmdResult
		want string
	}{
		{
			name: "cli",
			res: util.CmdResult{
				Err:    errors.New("exit status 1"),
				Stderr: "flag provided but not defined: -noalts",
			},
			want: "amass CLI compatibility failure",
		},
		{
			name: "lock",
			res: util.CmdResult{
				Err:    errors.New("exit status 1"),
				Stderr: "database is locked",
			},
			want: "amass workspace lock failure",
		},
		{
			name: "datasource",
			res: util.CmdResult{
				Err:    errors.New("exit status 1"),
				Stderr: "config error: data source credentials invalid",
			},
			want: "amass data source configuration failure",
		},
		{
			name: "generic",
			res: util.CmdResult{
				Err:    errors.New("exit status 1"),
				Stderr: "unexpected network failure",
			},
			want: "amass failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := explainAmassFailure(tc.res)
			if got == nil || !strings.Contains(got.Error(), tc.want) {
				t.Fatalf("got %v, want substring %q", got, tc.want)
			}
		})
	}
}
