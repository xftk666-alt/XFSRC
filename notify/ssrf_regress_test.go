package notify

import (
	"net"
	"testing"
)

func TestRegressionMetadataBlocked(t *testing.T) {
	for _, s := range []string{"169.254.169.254", "100.100.100.200", "127.0.0.1", "::1", "fd00:ec2::254"} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test IP %s", s)
		}
		if !isBlockedDialIP(ip) {
			t.Errorf("%s must be blocked", s)
		}
	}
	if isBlockedDialIP(net.ParseIP("93.184.216.34")) {
		t.Error("public address must not be blocked")
	}
}
