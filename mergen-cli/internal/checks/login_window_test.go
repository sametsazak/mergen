package checks

import "testing"

func TestSMBGuestAccessResult(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want Status
	}{
		{"disabled", "2026-10-21 20:52:21.158 sysadminctl[59893:9285486] SMB guest access disabled.", StatusPass},
		{"enabled", "2026-10-21 20:52:21.158 sysadminctl[59893:9285486] SMB guest access enabled.", StatusFail},
		{"usage", "2026-10-21 20:52:21.158 sysadminctl[59893:9285486] Usage: sysadminctl\n\t-smbGuestAccess <on || off || status>", StatusWarn},
		{"empty", "", StatusWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := smbGuestAccessResult(tt.out).Status; got != tt.want {
				t.Errorf("smbGuestAccessResult(%q) = %v, want %v", tt.out, got, tt.want)
			}
		})
	}
}
