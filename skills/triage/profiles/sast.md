# SAST Profile

This profile applies to static analysis findings from tools like Semgrep, gosec, kube-linter, actionlint, zizmor, rbac-analyzer, adversarial-reviewing, semantic-scan, and general-review.

## Profile-Specific Guidance

### Code Reachability

SAST tools flag patterns that *look* dangerous, but may not be exploitable. Your job is to prove reachability:

1. **Trace from entry points**: Start at HTTP handlers, CLI commands, event listeners, or `main()` functions.
2. **Follow the call chain**: Document each function call from entry point to the flagged code.
3. **Check for dead code**: If grep returns no callers, the code may be unreachable. Classify as `confirmed_dead_code`.

### Injection Pattern Analysis

For injection vulnerabilities (SQL injection, command injection, XSS, SSRF, path traversal):

1. **Identify the sink**: Where does the user input flow into a dangerous function? (e.g., `exec()`, `eval()`, SQL query, template render)
2. **Trace the source**: Where does the input come from? (HTTP param, file upload, environment variable, database)
3. **Check for sanitization**: Are there validation or escaping functions between source and sink?
4. **Test the bypass**: Can the sanitization be bypassed? (e.g., incomplete regex, encoding tricks)

Common sinks to watch for:
- **SQL injection**: `db.Query()`, `db.Exec()`, string concatenation in SQL
- **Command injection**: `exec.Command()`, `os.system()`, `subprocess.run()`, shell=True
- **XSS**: `innerHTML`, `document.write()`, template render without escaping
- **SSRF**: HTTP client with user-controlled URL
- **Path traversal**: `os.Open()`, `ioutil.ReadFile()` with user-controlled path

### OWASP Mapping

Map the finding to OWASP Top 10 or CWE for risk assessment:
- **A01:2021 – Broken Access Control**: Missing auth checks, IDOR
- **A02:2021 – Cryptographic Failures**: Weak crypto, hard-coded keys
- **A03:2021 – Injection**: SQL, command, LDAP, XSS
- **A04:2021 – Insecure Design**: Missing security controls by design
- **A05:2021 – Security Misconfiguration**: Default credentials, verbose errors
- **A06:2021 – Vulnerable Components**: Outdated libraries (overlap with CVE profile)
- **A07:2021 – Authentication Failures**: Weak password policy, no MFA
- **A08:2021 – Software and Data Integrity Failures**: Unsigned code, insecure deserialization
- **A09:2021 – Logging Failures**: No logging, logs not monitored
- **A10:2021 – SSRF**: Server-side request forgery

Include the OWASP category in your `risk_statement`.

### Generated or Vendored Code

Before investigating, check if the file is generated or vendored:
- Generated code markers: `// Code generated`, `zz_generated_` prefix, `*.pb.go`, `*_generated.go`
- Vendored code: file path starts with `vendor/`

If the file is generated or vendored, classify as `uncertain` with `confidence=0.3` and reasoning: "Finding is in generated/vendored code, not maintainable by this repo".

### Evidence Fields (SAST-Specific)

Add these fields to the `evidence` object:

```json
{
  "call_chain": ["main.go:92", "handler.go:45", "executor.go:128"],
  "mitigations_found": ["auth middleware at router.go:34"],
  "mitigations_missing": ["no input sanitization before eval()"],
  "entry_points": ["HTTP POST /api/execute"],
  "generated_or_vendored": false,
  "owasp_category": "A03:2021 - Injection",
  "sink_location": "executor.go:128",
  "source_location": "handler.go:45"
}
```

## Example Classifications

### Confirmed: SQL Injection

```json
{
  "classification": "confirmed",
  "confidence": 0.9,
  "reasoning": "Traced user input from HTTP POST /api/query (handler.go:34) to SQL query construction (db.go:67) with no sanitization. The input is concatenated directly into SQL string.",
  "evidence": {
    "call_chain": ["main.go:45", "handler.go:34", "db.go:67"],
    "mitigations_found": [],
    "mitigations_missing": ["no input validation", "no prepared statements"],
    "entry_points": ["HTTP POST /api/query"],
    "owasp_category": "A03:2021 - Injection",
    "sink_location": "db.go:67",
    "source_location": "handler.go:34"
  },
  "risk_statement": "Attacker can execute arbitrary SQL queries via /api/query",
  "fix_recommendation": "Use prepared statements at db.go:67. Replace string concatenation with db.Query(?, ?) parameterized query."
}
```

### Likely FP: Command Injection with Validation

```json
{
  "classification": "likely_fp",
  "confidence": 0.85,
  "reasoning": "Semgrep flagged exec.Command() at deploy.go:89, but input is validated against strict regex at deploy.go:78 (^[a-z0-9-]+$). Only alphanumeric and hyphens are allowed. Command injection is not possible.",
  "evidence": {
    "call_chain": ["main.go:12", "cmd.go:34", "deploy.go:89"],
    "mitigations_found": ["regex validation at deploy.go:78: ^[a-z0-9-]+$"],
    "mitigations_missing": [],
    "entry_points": ["CLI command: ./app deploy <name>"],
    "sink_location": "deploy.go:89",
    "source_location": "cmd.go:34"
  },
  "risk_statement": "N/A",
  "fix_recommendation": "No fix needed. Validation is sufficient."
}
```

### Confirmed Dead Code: Unused Function

```json
{
  "classification": "confirmed_dead_code",
  "confidence": 0.95,
  "reasoning": "Flagged function evaluateExpression() at eval.go:45 uses eval() without sanitization, but grep found no callers. The function is defined but never imported or called. Dead code.",
  "evidence": {
    "call_chain": [],
    "mitigations_found": [],
    "mitigations_missing": [],
    "entry_points": [],
    "generated_or_vendored": false
  },
  "risk_statement": "No runtime risk, but dead code should be removed",
  "fix_recommendation": "Delete eval.go:45 or mark as deprecated if intended for future use."
}
```
