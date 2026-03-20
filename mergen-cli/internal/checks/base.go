package checks

// base is embedded by every concrete check.
type base struct {
	cisID       string
	name        string
	section     string
	category    string
	severity    string
	description string
	remediation string
	manual      bool
	fix         *FixInfo
}

func (b *base) CISID() string       { return b.cisID }
func (b *base) Name() string        { return b.name }
func (b *base) Section() string     { return b.section }
func (b *base) Category() string    { return b.category }
func (b *base) Severity() string    { return b.severity }
func (b *base) Description() string { return b.description }
func (b *base) Remediation() string { return b.remediation }
func (b *base) IsManual() bool      { return b.manual }
func (b *base) Fix() *FixInfo       { return b.fix }

// checkFn wraps a base + a run function — the standard way to define checks.
type checkFn struct {
	base
	runFn func() Result
}

func (c *checkFn) Run() Result { return c.runFn() }

// newCheck is the constructor used in every section file.
func newCheck(
	cisID, name, section, category, severity, description, remediation string,
	manual bool,
	fix *FixInfo,
	runFn func() Result,
) Check {
	return &checkFn{
		base: base{
			cisID:       cisID,
			name:        name,
			section:     section,
			category:    category,
			severity:    severity,
			description: description,
			remediation: remediation,
			manual:      manual,
			fix:         fix,
		},
		runFn: runFn,
	}
}

// adminFix is a helper to build a FixInfo that needs sudo/admin privileges.
func adminFix(cmd, desc string) *FixInfo {
	return &FixInfo{Command: cmd, RequiresAdmin: true, Description: desc}
}

// userFix is a helper for fixes that run as the current user.
func userFix(cmd, desc string) *FixInfo {
	return &FixInfo{Command: cmd, RequiresAdmin: false, Description: desc}
}
