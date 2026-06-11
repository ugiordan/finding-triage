---
name: fast-triage
description: Lightweight initial classification of security findings. Pattern matching on metadata only, no code reading. Fast routing for obvious FPs and high-confidence issues.
type: skill
model_tier: light
tools: []
supported_backends:
  - vertex
  - anthropic
estimated_tokens:
  base: 2000
  per_finding: 100
---

# Fast Triage for Initial Classification

## Instructions

You are performing a lightweight initial assessment of a security finding to quickly route it to the appropriate next step. This is NOT a deep investigation. You work from finding metadata only.

## Investigation Steps

### Step 1: Assess Severity

Check the finding metadata:
- Tool name and rule ID
- Severity level (critical, high, medium, low)
- CWE/CVE identifiers if present
- File path (is it test code, vendor, generated?)
- Message/description

### Step 2: Check False Positive Patterns

Look for high-confidence FP indicators:
- Test files: `*_test.go`, `test/`, `tests/`, `testdata/`
- Example/fixture code: `example/`, `examples/`, `fixtures/`
- Vendored code: `vendor/`, `node_modules/`, `.venv/`
- Generated code: `*.pb.go`, `zz_generated_*`, `// Code generated`
- Documentation: `docs/`, `*.md`, `examples/`
- Tool-specific FP patterns: hadolint DL3059 (FROM as scratch), shellcheck SC2317 (unreachable code in trap handlers)

### Step 3: Quick Verdict

Produce a classification based on metadata only:
- **likely_real**: High severity, no obvious FP markers, in production code path
- **likely_fp**: Clear FP pattern (test/vendor/generated), or known noisy rule
- **needs_deep_triage**: Borderline case, requires code reading to confirm

## Output Format

Respond with valid JSON only. No markdown, no prose.

```json
{
  "classification": "likely_real | likely_fp | needs_deep_triage",
  "confidence": 0.0-1.0,
  "reasoning": "Why you chose this classification based on metadata patterns"
}
```

## Rules

- "likely_real": High severity + production code path + no obvious FP markers. Confidence >0.7.
- "likely_fp": Test/vendor/generated code, OR known noisy rule with low exploitability. Confidence >0.8.
- "needs_deep_triage": Default for everything else. Use when metadata is insufficient.
- This is a routing decision, NOT a final verdict. Overconfidence wastes triage time.
- If you're not >70% confident, use "needs_deep_triage".
