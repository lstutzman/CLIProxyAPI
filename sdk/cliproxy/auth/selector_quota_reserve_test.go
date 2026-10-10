package auth

import (
	"context"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func reserveTestAuth(id, email string, used float64, reset time.Time) *Auth {
	signals := map[string]string{
		"anthropic-ratelimit-unified-5h-utilization": strconv.FormatFloat(used/100, 'f', 4, 64),
		"anthropic-ratelimit-unified-5h-reset":       unixString(reset),
	}
	a := quotaTestAuth(id, "claude", signals, reset.Add(-time.Hour))
	a.Metadata["email"] = email
	return a
}

func TestQuotaAwareReserveAccountKeepsItsMargin(t *testing.T) {
	now := time.Now()
	reset := now.Add(time.Hour)
	sel := &QuotaAwareSelector{Threshold: 100, AccountThresholds: map[string]float64{"reserve@example.com": 90}, nowFunc: func() time.Time { return now }}
	reserve := reserveTestAuth("a-reserve", "Reserve@example.com", 91, reset)
	other := reserveTestAuth("b-other", "other@example.com", 95, reset)
	got, err := sel.Pick(context.Background(), "claude", "m", cliproxyexecutor.Options{}, []*Auth{reserve, other})
	if err != nil || got.ID != "b-other" {
		t.Fatalf("want other account above 90%% to keep working, got %v err %v", got, err)
	}
	spent := reserveTestAuth("b-other", "other@example.com", 100, reset)
	got, err = sel.Pick(context.Background(), "claude", "m", cliproxyexecutor.Options{}, []*Auth{reserve, spent})
	if err != nil || got.ID != "b-other" {
		t.Fatalf("reserve must never be used past its threshold, got %v err %v", got, err)
	}
	if _, err = sel.Pick(context.Background(), "claude", "m", cliproxyexecutor.Options{}, []*Auth{reserve}); err == nil {
		t.Fatalf("reserve alone past its threshold must not be picked")
	}
	low := reserveTestAuth("a-reserve", "reserve@example.com", 50, reset)
	got, _ = sel.Pick(context.Background(), "claude", "m", cliproxyexecutor.Options{}, []*Auth{low, other})
	if got.ID != "b-other" {
		t.Fatalf("most-used non-spent account should still be drained first, got %v", got.ID)
	}
}
