package checks

import "testing"

// Excerpt of `pwpolicy -getaccountpolicies` after
// `pwpolicy -setglobalpolicy minChars=N`.
func legacyMinCharsPolicy(predicate, n string) string {
	return `<key>policyCategoryPasswordContent</key>
	<array>
		<dict>
			<key>policyContent</key>
			<string>policyAttributePassword matches '` + predicate + `'</string>
			<key>policyIdentifier</key>
			<string>com.apple.policy.legacy.minChars</string>
			<key>policyParameters</key>
			<dict>
				<key>minimumLength</key>
				<integer>` + n + `</integer>
			</dict>
		</dict>
	</array>`
}

func TestPasswordMinLengthResult(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want Status
	}{
		{"15 characters", legacyMinCharsPolicy(".{15,}", "15"), StatusPass},
		{"lazy quantifier", legacyMinCharsPolicy(".{15,}?", "15"), StatusPass},
		{"possessive quantifier", legacyMinCharsPolicy(".{20,}+", "20"), StatusPass},
		{"4 characters", legacyMinCharsPolicy(".{4,}+", "4"), StatusFail},
		{"stacked predicates", legacyMinCharsPolicy(".{15,}?", "15") + "\n<string>policyAttributePassword matches '.{4,}+'</string>", StatusPass},
		{"parameter only", "<key>minimumLength</key>\n<integer>15</integer>", StatusPass},
		{"short parameter only", "<key>minimumLength</key>\n<integer>8</integer>", StatusFail},
		{"unparsed predicate", "<string>policyAttributePassword matches '^(?=.*[0-9]).+'</string>", StatusWarn},
		{"no policy", "<dict>\n</dict>", StatusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := passwordMinLengthResult(tt.out).Status; got != tt.want {
				t.Errorf("passwordMinLengthResult() = %v, want %v\ninput:\n%s", got, tt.want, tt.out)
			}
		})
	}
}
