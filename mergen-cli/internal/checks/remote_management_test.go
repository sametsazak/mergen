package checks

import "testing"

func TestARDAgentRunning(t *testing.T) {
	tests := []struct {
		name string
		ps   string
		want bool
	}{
		{"agent running", "  501   812     1   0  9:14AM ??         0:01.20 /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent", true},
		{"agent not running", "  501   640     1   0  9:14AM ??         0:00.31 /usr/libexec/locationd\n  501   701     1   0  9:14AM ??         0:00.12 /usr/sbin/cfprefsd agent", false},
		{"name in another command", "  501  9001  8000   0 10:02AM ttys000    0:00.00 grep ARDAgent", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ardAgentRunning(tt.ps); got != tt.want {
				t.Errorf("ardAgentRunning() = %v, want %v", got, tt.want)
			}
		})
	}
}
