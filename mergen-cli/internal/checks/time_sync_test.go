package checks

import "testing"

func TestNetworkTimeResult(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want Status
	}{
		{"on", "Network Time: On", StatusPass},
		{"on with tab", "Network Time:\tOn", StatusPass},
		{"off", "Network Time: Off", StatusFail},
		{"not root", "You need administrator access to run this tool... exiting!", StatusWarn},
		{"empty", "", StatusWarn},
		{"unexpected", "Error:-99 File:/System/Library/PrivateFrameworks/Admin.framework", StatusWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := networkTimeResult(tt.out).Status; got != tt.want {
				t.Errorf("networkTimeResult(%q) = %v, want %v", tt.out, got, tt.want)
			}
		})
	}
}
