package scan_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gitv5 "github.com/go-git/go-git/v5"
	"github.com/kubescape/kubescape/v4/cmd/fix"
	"github.com/kubescape/kubescape/v4/cmd/scan"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

const multiInputPrivilegedManifest = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: app
          image: nginx:1.27
          securityContext:
            privileged: true
`

func TestScanPreservesIndependentInputRoots(t *testing.T) {
	root := t.TempDir()
	production := filepath.Join(root, "prod", "deployment.yaml")
	development := filepath.Join(root, "dev", "deployment.yaml")
	writeMultiInputFile(t, production, multiInputPrivilegedManifest)
	writeMultiInputFile(t, development, strings.ReplaceAll(multiInputPrivilegedManifest, "privileged: true", "privileged: false"))

	for _, tc := range []struct {
		name   string
		inputs []string
	}{
		{name: "production first", inputs: []string{filepath.Dir(production), filepath.Dir(development)}},
		{name: "development first", inputs: []string{filepath.Dir(development), filepath.Dir(production)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, _, err := scanMultiInputManifests(t, tc.inputs)

			assert.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
			assert.Equal(t, float32(50), report.SummaryDetails.ComplianceScore)
			assert.Equal(t, map[string]string{
				production:  "failed",
				development: "passed",
			}, multiInputSourceStatuses(t, report))
		})
	}
}

func TestScanMultiInputFormatsAndGitRoots(t *testing.T) {
	for _, tc := range []struct {
		name, extension, gitRoots, directorySuffix string
		files                                      bool
	}{
		{name: "YAML files", extension: ".yaml", files: true},
		{name: "JSON directories", extension: ".json"},
		{name: "JSON files", extension: ".json", files: true},
		{name: "JSON-named directories", extension: ".json", directorySuffix: ".json"},
		{name: "shared Git root", extension: ".yaml", gitRoots: "shared"},
		{name: "separate Git roots", extension: ".yaml", gitRoots: "separate"},
		{name: "files in separate Git roots", extension: ".yaml", gitRoots: "separate", files: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			production := filepath.Join(root, "prod"+tc.directorySuffix, "deployment"+tc.extension)
			development := filepath.Join(root, "dev"+tc.directorySuffix, "deployment"+tc.extension)
			for _, path := range []string{production, development} {
				manifest := multiInputPrivilegedManifest
				if path == development {
					manifest = strings.ReplaceAll(manifest, "privileged: true", "privileged: false")
				}
				if tc.extension == ".json" {
					data, err := yaml.YAMLToJSON([]byte(manifest))
					require.NoError(t, err)
					manifest = string(data)
				}
				writeMultiInputFile(t, path, manifest)
			}
			switch tc.gitRoots {
			case "shared":
				_, err := gitv5.PlainInit(root, false)
				require.NoError(t, err)
			case "separate":
				for _, path := range []string{production, development} {
					_, err := gitv5.PlainInit(filepath.Dir(path), false)
					require.NoError(t, err)
				}
			}

			// The common-parent invocation is a public reference for stable IDs:
			// selecting its two children must describe the same two resources.
			whole, _, err := scanMultiInputManifests(t, []string{root})
			require.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
			wantStatuses := map[string]string{production: "failed", development: "passed"}
			require.Equal(t, wantStatuses, multiInputSourceStatuses(t, whole))
			wholeIDs := multiInputSourceIDs(t, whole)
			inputs := []string{filepath.Dir(production), filepath.Dir(development)}
			if tc.files {
				inputs = []string{production, development}
			}
			for _, order := range [][]string{inputs, {inputs[1], inputs[0]}} {
				report, _, err := scanMultiInputManifests(t, order)
				assert.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
				assert.Equal(t, float32(50), report.SummaryDetails.ComplianceScore)
				assert.Equal(t, wantStatuses, multiInputSourceStatuses(t, report))
				assert.Equal(t, wholeIDs, multiInputSourceIDs(t, report), "input order and spelling must not change resource IDs")
				if tc.directorySuffix != "" {
					for _, resource := range report.Resources {
						assert.Contains(t, inputs, resource.Source.Path, "a directory's extension must not change its source root")
						assert.Equal(t, "deployment"+tc.extension, resource.Source.RelativePath)
					}
				}
			}
		})
	}
}

func TestScanMultiInputRepeatedAndOverlappingSources(t *testing.T) {
	root := t.TempDir()
	production := filepath.Join(root, "prod", "deployment.yaml")
	development := filepath.Join(root, "dev", "deployment.yaml")
	writeMultiInputFile(t, production, multiInputPrivilegedManifest)
	writeMultiInputFile(t, development, strings.ReplaceAll(multiInputPrivilegedManifest, "privileged: true", "privileged: false"))

	t.Run("repeated file retains its single-input identity", func(t *testing.T) {
		single, _, err := scanMultiInputManifests(t, []string{production})
		require.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
		repeated, _, err := scanMultiInputManifests(t, []string{production, production})
		require.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
		assert.Equal(t, map[string]string{production: "failed"}, multiInputSourceStatuses(t, repeated))
		assert.Equal(t, multiInputSourceIDs(t, single), multiInputSourceIDs(t, repeated))
		assert.Equal(t, float32(0), repeated.SummaryDetails.ComplianceScore)
	})

	t.Run("overlapping directory and file inputs count each document once", func(t *testing.T) {
		whole, _, err := scanMultiInputManifests(t, []string{root})
		require.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
		overlap, _, err := scanMultiInputManifests(t, []string{root, filepath.Dir(production), production})
		require.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
		assert.Equal(t, map[string]string{production: "failed", development: "passed"}, multiInputSourceStatuses(t, overlap))
		assert.Equal(t, multiInputSourceIDs(t, whole), multiInputSourceIDs(t, overlap))
		assert.Equal(t, float32(50), overlap.SummaryDetails.ComplianceScore)
	})
}

func TestScanMultiInputGeneratedExceptionsStayScopedToTheirSource(t *testing.T) {
	root := t.TempDir()
	production := filepath.Join(root, "prod", "deployment.yaml")
	development := filepath.Join(root, "dev", "deployment.yaml")
	writeMultiInputFile(t, production, multiInputPrivilegedManifest)
	writeMultiInputFile(t, development, strings.ReplaceAll(multiInputPrivilegedManifest, "privileged: true", "privileged: false"))
	inputs := []string{filepath.Dir(production), filepath.Dir(development)}
	baseline, reportPath, err := scanMultiInputManifests(t, inputs, "--format", "json,exceptions")
	require.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
	require.Equal(t, map[string]string{production: "failed", development: "passed"}, multiInputSourceStatuses(t, baseline))
	exceptionsPath := reportPath + ".exceptions.json"
	require.FileExists(t, exceptionsPath)

	// The generated baseline accepted only prod. A new failure in an identically
	// named dev resource must still fail the gate, even with reversed inputs.
	writeMultiInputFile(t, development, multiInputPrivilegedManifest)
	report, _, err := scanMultiInputManifests(t, []string{inputs[1], inputs[0]}, "--exceptions", exceptionsPath)
	assert.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
	assert.Equal(t, map[string]string{production: "passed", development: "failed"}, multiInputSourceStatuses(t, report))
	assert.Equal(t, multiInputSourceIDs(t, baseline), multiInputSourceIDs(t, report))
	productionID := multiInputSourceIDs(t, report)[production]
	for _, result := range report.Results {
		if result.ResourceID == productionID {
			assert.Equal(t, apis.SubStatusException, result.AssociatedControls[0].Status.SubStatus)
		}
	}
}

func TestScanMultiInputFixPreservesDocumentIndexes(t *testing.T) {
	root := t.TempDir()
	safe := strings.ReplaceAll(multiInputPrivilegedManifest, "privileged: true", "privileged: false")
	safe = strings.Replace(safe, "name: web", "name: safe", 1)
	documents := safe + "---\n" + multiInputPrivilegedManifest
	var inputs []string
	for _, directory := range []string{"prod", "dev"} {
		path := filepath.Join(root, directory, "deployment.yaml")
		writeMultiInputFile(t, path, documents)
		_, err := gitv5.PlainInit(filepath.Dir(path), false)
		require.NoError(t, err)
		inputs = append(inputs, filepath.Dir(path))
	}
	report, reportPath, err := scanMultiInputManifests(t, inputs)
	require.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
	require.Len(t, report.Resources, 4)
	require.Len(t, report.Results, 4)
	assert.Equal(t, float32(50), report.SummaryDetails.ComplianceScore)
	sources := map[string]int{}
	for _, resource := range report.Resources {
		require.NotNil(t, resource.Source)
		sources[filepath.Join(resource.Source.Path, resource.Source.RelativePath)]++
	}
	assert.Equal(t, map[string]int{
		filepath.Join(root, "prod", "deployment.yaml"): 2,
		filepath.Join(root, "dev", "deployment.yaml"):  2,
	}, sources)

	output := filepath.Join(t.TempDir(), "fixed")
	command := fix.GetFixCmd(core.NewKubescape(context.Background()))
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{reportPath, "--output-dir", output, "--base-path", root})
	require.NoError(t, command.Execute())
	for _, directory := range []string{"prod", "dev"} {
		original, err := os.ReadFile(filepath.Join(root, directory, "deployment.yaml"))
		require.NoError(t, err)
		assert.Equal(t, documents, string(original))
		fixed, err := os.ReadFile(filepath.Join(output, directory, "deployment.yaml"))
		require.NoError(t, err)
		assert.NotContains(t, string(fixed), "privileged: true", "fix the failing second document in each source")
	}
	fixedReport, _, err := scanMultiInputManifests(t, []string{output})
	require.NoError(t, err)
	assert.Len(t, fixedReport.Resources, 4, "both documents in both sources must survive fixing")
	assert.Len(t, fixedReport.Results, 4)
	assert.Equal(t, float32(100), fixedReport.SummaryDetails.ComplianceScore)
}

func TestScanMultiInputReportFixesCopiesOfBothSources(t *testing.T) {
	root := t.TempDir()
	production := filepath.Join(root, "prod", "deployment.yaml")
	development := filepath.Join(root, "dev", "deployment.yaml")
	for _, path := range []string{production, development} {
		writeMultiInputFile(t, path, multiInputPrivilegedManifest)
	}
	report, reportPath, err := scanMultiInputManifests(t, []string{filepath.Dir(production), filepath.Dir(development)})
	require.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
	require.Equal(t, map[string]string{production: "failed", development: "failed"}, multiInputSourceStatuses(t, report))

	t.Run("untrusted report root is refused", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "fixed")
		command := fix.GetFixCmd(core.NewKubescape(context.Background()))
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		command.SetArgs([]string{reportPath, "--output-dir", output, "--base-path", t.TempDir()})
		require.ErrorContains(t, command.Execute(), "outside --base-path")
		assert.NoDirExists(t, output)
	})

	t.Run("copies preserve both source paths", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "fixed")
		command := fix.GetFixCmd(core.NewKubescape(context.Background()))
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		command.SetArgs([]string{reportPath, "--output-dir", output, "--base-path", root})
		require.NoError(t, command.Execute())

		for _, directory := range []string{"prod", "dev"} {
			fixedPath := filepath.Join(output, directory, "deployment.yaml")
			fixed, err := os.ReadFile(fixedPath)
			require.NoError(t, err, "each independently scanned manifest must produce its own fixed copy")
			assert.Contains(t, string(fixed), "privileged: false")
		}
		fixedReport, _, err := scanMultiInputManifests(t, []string{output})
		require.NoError(t, err, "the actual written copies must pass the same policy")
		assert.Equal(t, float32(100), fixedReport.SummaryDetails.ComplianceScore)
		assert.Equal(t, map[string]string{
			filepath.Join(output, "prod", "deployment.yaml"): "passed",
			filepath.Join(output, "dev", "deployment.yaml"):  "passed",
		}, multiInputSourceStatuses(t, fixedReport))
	})

	for _, path := range []string{production, development} {
		original, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, multiInputPrivilegedManifest, string(original), "--output-dir must leave the original untouched")
	}
}

func writeMultiInputFile(t *testing.T, path, contents string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
}

// Exercise discovery, policy evaluation, report serialization, and the gate
// through the public scan command, without a cluster or downloaded policies.
func scanMultiInputManifests(t *testing.T, inputs []string, extraArgs ...string) (reporthandlingv2.PostureReport, string, error) {
	t.Helper()
	// Explicit local tenant settings keep a contributor's kubeconfig out of the scan.
	t.Setenv("KS_CLOUD_API_URL", "https://api.example.invalid")
	t.Setenv("KS_CLOUD_REPORT_URL", "https://report.example.invalid")
	for _, name := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_EXPORTER_OTLP_PROTOCOL",
	} {
		t.Setenv(name, "")
	}
	previousConnector := getter.GetKSCloudAPIConnector()
	getter.SetKSCloudAPIConnector(nil)
	t.Cleanup(func() { getter.SetKSCloudAPIConnector(previousConnector) })

	rule := reporthandling.PolicyRule{
		Rule: `package armo_builtins
import rego.v1
deny contains message if {
    resource := input[_]
    resource.spec.template.spec.containers[0].securityContext.privileged == true
    path := "spec.template.spec.containers[0].securityContext.privileged"
    message := {
        "alertMessage": "privileged container",
        "alertObject": {"k8sApiObjects": [resource]},
        "failedPaths": [path],
        "fixPaths": [{"path": path, "value": "false"}]
    }
}`,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"Deployment"},
		}},
	}
	rule.Name = "privileged-container"
	control := reporthandling.Control{ControlID: "C-TEST", BaseScore: 5, Rules: []reporthandling.PolicyRule{rule}}
	control.Name = "Privileged container"
	policy, err := json.Marshal(control)
	require.NoError(t, err)
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "control.json")
	inputsPath := filepath.Join(dir, "inputs.json")
	exceptionsPath := filepath.Join(dir, "exceptions.json")
	outputPath := filepath.Join(dir, "report.json")
	writeMultiInputFile(t, policyPath, string(policy))
	writeMultiInputFile(t, inputsPath, `{"probe":["value"]}`)
	writeMultiInputFile(t, exceptionsPath, `[]`)

	args := append([]string{"control", "C-TEST"}, inputs...)
	args = append(args,
		"--use-from", policyPath, "--controls-config", inputsPath,
		"--exceptions", exceptionsPath, "--submit=false", "--keep-local",
		"--account", "11111111-2222-3333-4444-555555555555", "--access-key", "local-test",
		"--compliance-threshold", "100", "--format", "json", "--output", outputPath,
	)
	args = append(args, extraArgs...)
	command := scan.GetScanCommand(core.NewKubescape(context.Background()))
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs(args)
	scanErr := command.Execute()
	data, err := os.ReadFile(outputPath)
	require.NoError(t, err, "scan did not write its report; command error: %v", scanErr)
	var report reporthandlingv2.PostureReport
	require.NoError(t, json.Unmarshal(data, &report), "scan wrote an invalid report; command error: %v", scanErr)
	return report, outputPath, scanErr
}

func multiInputSourceIDs(t *testing.T, report reporthandlingv2.PostureReport) map[string]string {
	t.Helper()
	ids := make(map[string]string)
	for i := range report.Resources {
		resource := &report.Resources[i]
		require.NotNil(t, resource.Source)
		path := filepath.Clean(filepath.Join(resource.Source.Path, resource.Source.RelativePath))
		require.NotContains(t, ids, path)
		ids[path] = resource.GetID()
	}
	return ids
}

func multiInputSourceStatuses(t *testing.T, report reporthandlingv2.PostureReport) map[string]string {
	t.Helper()
	statuses := make(map[string]string)
	for _, result := range report.Results {
		require.Len(t, result.AssociatedControls, 1)
		require.NotContains(t, statuses, result.ResourceID, "one result per resource")
		statuses[result.ResourceID] = string(result.AssociatedControls[0].Status.InnerStatus)
	}
	sources := make(map[string]string)
	for i := range report.Resources {
		resource := &report.Resources[i]
		require.NotNil(t, resource.Source)
		path := filepath.Clean(filepath.Join(resource.Source.Path, resource.Source.RelativePath))
		require.NotContains(t, sources, path, "each source must be counted once")
		require.Contains(t, statuses, resource.GetID(), "serialized resources and results must agree on identity")
		sources[path] = statuses[resource.GetID()]
	}
	assert.Len(t, report.Results, len(report.Resources))
	return sources
}
