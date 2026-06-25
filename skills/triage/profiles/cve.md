# CVE Profile

This profile applies to CVE/SCA findings from tools like Trivy, grype, osv-scanner, pip-audit, govulncheck, and github-advisory.

## Profile-Specific Guidance

### Dependency Presence Check

Before investigating reachability, confirm the vulnerable package is actually in the project:

1. **Check dependency manifests**: `go.mod`, `go.sum`, `requirements.txt`, `package.json`, `Cargo.toml`, `pom.xml`
2. **If the package is not found in ANY manifest**: Classify as `likely_fp` with reasoning: "Component not present in dependency manifests"
3. **If NO manifests exist**: Classify as `uncertain` with reasoning: "Cannot prove package absence, no dependency manifests found"

### Version Analysis

Check if the installed version is in the vulnerable range:

1. **Extract the installed version** from lock files or manifests
2. **Compare against the vulnerable version range** (from CVE data)
3. **If the installed version is at or above the fixed version**: Classify as `likely_fp` with reasoning: "Installed version X.Y.Z is >= fixed version A.B.C"
4. **If the version is in the vulnerable range**: Proceed to reachability analysis

### Reachability Analysis

The key question: Is the vulnerable function actually called in the codebase?

#### Phase 1: Tool-Based Reachability (Preferred)

For Go projects, run `govulncheck -mode=source ./...` to get definitive reachability from the official tool. If the tool reports "not called" or "unreachable", classify as `confirmed_dead_code`.

For other ecosystems:
- Python: `pip-audit` or check import graphs
- JavaScript: `npm audit` or trace dependency trees
- Rust: `cargo audit`

If the tool confirms the vulnerable function is NOT called, classify as `confirmed_dead_code`.

#### Phase 2: Manual Reachability (Fallback)

If tool scan is inconclusive or not available:

1. **Grep for imports/usage** of the vulnerable package
2. **Identify the vulnerable function/module** (from CVE description)
3. **Grep for that specific function call**
4. **Trace from entry points** (main, handlers, init) to determine if the vulnerable code path is exercised
5. **For transitive dependencies**, check if the intermediate package that pulls it in is actually used

### Supply Chain Assessment

Determine the dependency context:

1. **Direct vs Transitive**:
   - Direct: Listed in manifest (e.g., `go.mod` require statement)
   - Transitive: Pulled by another dependency (appears in lock file but not manifest)

2. **Pinned vs Floating**:
   - Pinned: Version is locked in `go.sum`, `package-lock.json`, `poetry.lock`
   - Floating: Version range (e.g., `^1.2.0`) allows auto-updates

3. **Upgrade Feasibility**:
   - Does a fixed version exist?
   - Are there known breaking changes?
   - Is the version pinned in a way that blocks auto-upgrade?

### VEX Alignment

If VEX (Vulnerability Exploitability eXchange) data is available:

1. **Check VEX status**: `not_affected`, `affected`, `fixed`, `under_investigation`
2. **Check VEX justification**: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`
3. **Compare with your analysis**:
   - If VEX says `not_affected` and you confirm the vulnerable function is NOT called: Align with VEX, classify as `confirmed_dead_code`
   - If VEX says `affected` but you confirm the vulnerable function is NOT called: VEX tracks product-level status (shipped binaries), your analysis is source-level. Classify as `confirmed_dead_code` and note `vex_alignment: "contradicts"` in evidence.

**Important**: VEX is advisory, not definitive. Your source-level reachability analysis takes precedence for triage.

### Evidence Fields (CVE-Specific)

Add these fields to the `evidence` object:

```json
{
  "package_location": "go.mod:45",
  "installed_version": "1.2.3",
  "vulnerable_range": "< 1.2.4",
  "fixed_version": "1.2.4",
  "import_sites": ["pkg/server/handler.go:12", "pkg/client/http.go:8"],
  "vulnerable_function": "parseRequest",
  "vulnerable_function_called": true,
  "call_sites": ["pkg/server/handler.go:67"],
  "vex_status": "affected",
  "vex_justification": "none",
  "vex_alignment": "agrees | contradicts | no_vex",
  "dependency_type": "direct | transitive",
  "pinned": true,
  "tool_scan_result": "govulncheck: called"
}
```

## Example Classifications

### Confirmed: Vulnerable Function Called

```json
{
  "classification": "confirmed",
  "confidence": 0.9,
  "reasoning": "govulncheck confirms vulnerable function parseRequest() is called at pkg/server/handler.go:67. Traced from HTTP handler to vulnerable code path.",
  "evidence": {
    "package_location": "go.mod:45",
    "installed_version": "1.2.3",
    "vulnerable_range": "< 1.2.4",
    "fixed_version": "1.2.4",
    "import_sites": ["pkg/server/handler.go:12"],
    "vulnerable_function": "parseRequest",
    "vulnerable_function_called": true,
    "call_sites": ["pkg/server/handler.go:67"],
    "dependency_type": "direct",
    "pinned": true,
    "tool_scan_result": "govulncheck: called"
  },
  "risk_statement": "CVE-2024-1234: Denial of service via malformed request to /api/parse",
  "fix_recommendation": "Upgrade github.com/example/lib from 1.2.3 to 1.2.4 in go.mod",
  "upgrade_path": {
    "current": "1.2.3",
    "fixed": "1.2.4",
    "breaking_changes": false
  }
}
```

### Confirmed Dead Code: Package Imported but Function Not Called

```json
{
  "classification": "confirmed_dead_code",
  "confidence": 0.95,
  "reasoning": "Package github.com/example/lib is imported at pkg/client/http.go:8, but the vulnerable function parseRequest() is never called. Grep found no call sites. govulncheck confirms: not called.",
  "evidence": {
    "package_location": "go.mod:45",
    "installed_version": "1.2.3",
    "vulnerable_range": "< 1.2.4",
    "import_sites": ["pkg/client/http.go:8"],
    "vulnerable_function": "parseRequest",
    "vulnerable_function_called": false,
    "call_sites": [],
    "dependency_type": "direct",
    "pinned": true,
    "tool_scan_result": "govulncheck: not called"
  },
  "risk_statement": "No runtime risk, but supply chain risk remains until upgrade",
  "fix_recommendation": "Upgrade github.com/example/lib from 1.2.3 to 1.2.4 to eliminate supply chain risk"
}
```

### Likely FP: Component Not Present

```json
{
  "classification": "likely_fp",
  "confidence": 0.95,
  "reasoning": "Package github.com/example/vuln not found in go.mod or go.sum. Scanner may have flagged a transitive dependency that was removed in a recent commit.",
  "evidence": {
    "package_location": "not found",
    "installed_version": null,
    "dependency_type": "unknown"
  },
  "risk_statement": "N/A",
  "fix_recommendation": "No action needed. Component not present."
}
```

### Likely FP: Version Already Fixed

```json
{
  "classification": "likely_fp",
  "confidence": 0.95,
  "reasoning": "Installed version 1.2.5 (from go.sum:89) is >= fixed version 1.2.4. CVE does not affect this version.",
  "evidence": {
    "package_location": "go.mod:45",
    "installed_version": "1.2.5",
    "vulnerable_range": "< 1.2.4",
    "fixed_version": "1.2.4"
  },
  "risk_statement": "N/A",
  "fix_recommendation": "No action needed. Already patched."
}
```

### Uncertain: VEX Contradicts Analysis

```json
{
  "classification": "uncertain",
  "confidence": 0.5,
  "reasoning": "VEX data marks this as affected, but govulncheck reports the vulnerable function is not called. VEX may track product-level status (shipped binaries) while source analysis shows no runtime calls. Escalate for human review to reconcile VEX and source-level findings.",
  "evidence": {
    "package_location": "go.mod:45",
    "installed_version": "1.2.3",
    "vulnerable_function_called": false,
    "vex_status": "affected",
    "vex_alignment": "contradicts",
    "tool_scan_result": "govulncheck: not called"
  },
  "risk_statement": "Uncertain: VEX vs source analysis mismatch",
  "fix_recommendation": "Review VEX data source and reconcile with govulncheck result"
}
```
