package report

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"
)

type Finding struct {
	Type        string    `json:"type"`
	Category    string    `json:"category"`
	Payload     string    `json:"payload"`
	StatusCode  int       `json:"status_code"`
	ResponseLen int       `json:"response_length"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Scheme      string    `json:"scheme"`
	Note        string    `json:"note"`
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
	Evidence    string    `json:"evidence,omitempty"`
}

//go:embed template.html
var htmlTemplate string

func GenerateJSON(findings []Finding, target, output string) error {
	report := map[string]interface{}{
		"tool":       "SSRF Exploitation Framework v3.0",
		"target":     target,
		"timestamp":  time.Now().Format(time.RFC3339),
		"total":      len(findings),
		"critical":   countSeverity(findings, "critical"),
		"high":       countSeverity(findings, "high"),
		"medium":     countSeverity(findings, "medium"),
		"low":        countSeverity(findings, "low"),
		"open_ports": countOpenPorts(findings),
		"findings":   findings,
	}

	data, err := json.MarshalIndent(report, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(output, data, 0644)
}

func countSeverity(findings []Finding, sev string) int {
	count := 0
	for _, f := range findings {
		if f.Severity == sev {
			count++
		}
	}
	return count
}

func countOpenPorts(findings []Finding) int {
	count := 0
	for _, f := range findings {
		if f.Type == "OpenPort" {
			count++
		}
	}
	return count
}

func GenerateHTML(findings []Finding, target, output string) error {
	// Sort by severity
	sort.Slice(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})

	data := struct {
		Target    string
		Timestamp string
		Total     int
		Critical  int
		High      int
		Medium    int
		Low       int
		OpenPorts int
		Findings  []Finding
	}{
		Target:    target,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Total:     len(findings),
		Critical:  countSeverity(findings, "critical"),
		High:      countSeverity(findings, "high"),
		Medium:    countSeverity(findings, "medium"),
		Low:       countSeverity(findings, "low"),
		OpenPorts: countOpenPorts(findings),
		Findings:  findings,
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"safe":  func(s string) template.HTML { return template.HTML(s) },
		"lower": func(s string) string { return strings.ToLower(s) },
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
