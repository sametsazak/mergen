package report

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/sametsazak/mergen-cli/internal/checks"
)

// ── JSON ─────────────────────────────────────────────────────────────────────

type jsonCheck struct {
	CISID       string `json:"cis_id,omitempty"`
	Name        string `json:"name"`
	Section     string `json:"section"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Output      string `json:"output"`
	Remediation string `json:"remediation"`
	AutoFixable bool   `json:"auto_fixable"`
}

type jsonReport struct {
	GeneratedAt string      `json:"generated_at"`
	Benchmark   string      `json:"benchmark"`
	Total       int         `json:"total"`
	Pass        int         `json:"pass"`
	Fail        int         `json:"fail"`
	Warn        int         `json:"warn"`
	Manual      int         `json:"manual"`
	Score       float64     `json:"score_pct"`
	Checks      []jsonCheck `json:"checks"`
}

func JSON(results []checks.CheckResult) ([]byte, error) {
	var pass, fail, warn, manual int
	for _, r := range results {
		switch r.Result.Status {
		case checks.StatusPass:
			pass++
		case checks.StatusFail:
			fail++
		case checks.StatusWarn:
			warn++
		case checks.StatusManual:
			manual++
		}
	}
	automated := pass + fail + warn
	score := 0.0
	if automated > 0 {
		score = float64(pass) / float64(automated) * 100
	}

	var jChecks []jsonCheck
	for _, r := range results {
		jChecks = append(jChecks, jsonCheck{
			CISID:       r.Check.CISID(),
			Name:        r.Check.Name(),
			Section:     r.Check.Section(),
			Category:    r.Check.Category(),
			Severity:    r.Check.Severity(),
			Status:      r.Result.Status.String(),
			Output:      r.Result.Output,
			Remediation: r.Check.Remediation(),
			AutoFixable: r.Result.Status == checks.StatusFail && r.Check.Fix() != nil,
		})
	}

	rep := jsonReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Benchmark:   "CIS Apple macOS 26 Tahoe Benchmark v1.0.0",
		Total:       len(results),
		Pass:        pass,
		Fail:        fail,
		Warn:        warn,
		Manual:      manual,
		Score:       score,
		Checks:      jChecks,
	}
	return json.MarshalIndent(rep, "", "  ")
}

// ── HTML ─────────────────────────────────────────────────────────────────────

func HTML(results []checks.CheckResult) string {
	var pass, fail, warn, manual int
	for _, r := range results {
		switch r.Result.Status {
		case checks.StatusPass:
			pass++
		case checks.StatusFail:
			fail++
		case checks.StatusWarn:
			warn++
		case checks.StatusManual:
			manual++
		}
	}
	automated := pass + fail + warn
	score := 0.0
	if automated > 0 {
		score = float64(pass) / float64(automated) * 100
	}

	scoreColor := "#ef4444"
	scoreLabel := "At Risk"
	if score >= 80 {
		scoreColor = "#22c55e"
		scoreLabel = "Good"
	} else if score >= 50 {
		scoreColor = "#f97316"
		scoreLabel = "Fair"
	}

	var rows strings.Builder
	for _, r := range results {
		statusClass := map[checks.Status]string{
			checks.StatusPass:   "pass",
			checks.StatusFail:   "fail",
			checks.StatusWarn:   "warn",
			checks.StatusManual: "manual",
		}[r.Result.Status]
		if statusClass == "" {
			statusClass = "err"
		}
		statusLabel := map[checks.Status]string{
			checks.StatusPass:   "✓ PASS",
			checks.StatusFail:   "✗ FAIL",
			checks.StatusWarn:   "⚠ WARN",
			checks.StatusManual: "ℹ MANUAL",
		}[r.Result.Status]

		fixTag := ""
		if r.Result.Status == checks.StatusFail && r.Check.Fix() != nil {
			fixTag = `<span class="fix-badge">auto-fix</span>`
		}

		rows.WriteString(fmt.Sprintf(`
		<tr class="%s">
		  <td class="cis">%s</td>
		  <td>%s %s</td>
		  <td>%s</td>
		  <td><span class="sev-%s">%s</span></td>
		  <td class="status-badge">%s</td>
		  <td class="output">%s</td>
		</tr>`,
			statusClass,
			html.EscapeString(r.Check.CISID()),
			html.EscapeString(r.Check.Name()),
			fixTag,
			html.EscapeString(r.Check.Section()),
			strings.ToLower(r.Check.Severity()),
			html.EscapeString(r.Check.Severity()),
			statusLabel,
			html.EscapeString(r.Result.Output),
		))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mergen Security Report</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0f0f13; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', sans-serif; font-size: 14px; line-height: 1.5; }
  header { background: linear-gradient(135deg, #1e1b4b 0%%, #312e81 100%%); padding: 40px 48px; border-bottom: 1px solid #312e81; }
  header h1 { font-size: 28px; font-weight: 700; color: #a78bfa; letter-spacing: -0.5px; }
  header p { color: #94a3b8; margin-top: 4px; font-size: 13px; }
  .stats { display: flex; gap: 24px; padding: 24px 48px; background: #0f0f13; border-bottom: 1px solid #1f2937; flex-wrap: wrap; align-items: center; }
  .score { font-size: 48px; font-weight: 800; color: %s; line-height: 1; }
  .score-label { font-size: 13px; color: %s; font-weight: 600; margin-top: 2px; }
  .stat { padding: 0 20px; border-left: 1px solid #1f2937; }
  .stat .n { font-size: 28px; font-weight: 700; }
  .stat .l { font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 2px; }
  .stat.pass .n { color: #22c55e; }
  .stat.fail .n { color: #ef4444; }
  .stat.warn .n { color: #f97316; }
  .stat.manual .n { color: #3b82f6; }
  .generated { margin-left: auto; color: #4b5563; font-size: 12px; align-self: flex-end; }
  main { padding: 32px 48px; }
  table { width: 100%%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px 12px; background: #111827; color: #6b7280; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #1f2937; position: sticky; top: 0; }
  td { padding: 9px 12px; border-bottom: 1px solid #1a1a2e; vertical-align: top; }
  tr:hover td { background: #111827; }
  tr.fail td:first-child { border-left: 3px solid #ef4444; }
  tr.warn td:first-child { border-left: 3px solid #f97316; }
  tr.pass td:first-child { border-left: 3px solid #22c55e; }
  tr.manual td:first-child { border-left: 3px solid #3b82f6; }
  .cis { font-family: 'SF Mono', monospace; color: #94a3b8; font-size: 12px; white-space: nowrap; }
  .status-badge { font-weight: 700; white-space: nowrap; font-size: 12px; }
  tr.pass .status-badge { color: #22c55e; }
  tr.fail .status-badge { color: #ef4444; }
  tr.warn .status-badge { color: #f97316; }
  tr.manual .status-badge { color: #3b82f6; }
  .output { color: #6b7280; font-size: 12px; max-width: 320px; }
  .sev-critical { color: #dc2626; font-weight: 700; }
  .sev-high { color: #f97316; }
  .sev-medium { color: #eab308; }
  .sev-low { color: #3b82f6; }
  .fix-badge { background: #7f1d1d; color: #fca5a5; font-size: 10px; padding: 1px 5px; border-radius: 4px; margin-left: 6px; font-weight: 600; vertical-align: middle; }
  footer { padding: 24px 48px; color: #374151; font-size: 12px; border-top: 1px solid #1f2937; }
</style>
</head>
<body>
<header>
  <h1>🛡 Mergen Security Report</h1>
  <p>CIS Apple macOS 26 Tahoe Benchmark v1.0.0 · Generated %s</p>
</header>
<div class="stats">
  <div>
    <div class="score">%.0f%%</div>
    <div class="score-label">%s</div>
  </div>
  <div class="stat pass"><div class="n">%d</div><div class="l">Pass</div></div>
  <div class="stat fail"><div class="n">%d</div><div class="l">Fail</div></div>
  <div class="stat warn"><div class="n">%d</div><div class="l">Warn</div></div>
  <div class="stat manual"><div class="n">%d</div><div class="l">Manual</div></div>
  <div class="generated">%s</div>
</div>
<main>
<table>
<thead>
  <tr>
    <th>CIS ID</th><th>Check</th><th>§</th><th>Severity</th><th>Status</th><th>Finding</th>
  </tr>
</thead>
<tbody>
%s
</tbody>
</table>
</main>
<footer>Generated by <strong>mergen-cli</strong> · github.com/sametsazak/mergen</footer>
</body>
</html>`,
		scoreColor, scoreColor,
		time.Now().Format("2006-01-02"),
		score, scoreLabel,
		pass, fail, warn, manual,
		time.Now().Format("2006-01-02 15:04 MST"),
		rows.String(),
	)
}
