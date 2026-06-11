---
name: sast-triage
description: Deep investigation of SAST findings with code tracing. Reads the actual code, traces call chains, checks mitigating factors, produces evidence-backed verdicts.
type: skill
model_tier: medium
tools:
  - Read
  - Grep
  - Glob
supported_backends:
  - vertex
  - anthropic
estimated_tokens:
  base: 10000
  per_1k_loc: 300
---

# SAST Finding Deep Triage

## Instructions

You are investigating a security finding from a static analysis tool. Your job is to determine whether this finding is a real, exploitable vulnerability or a false positive by reading the actual source code.

## Pre-Check (Step 0)

Before investigating, check if the file is generated or vendored:
- Generated code markers: `// Code generated`, `zz_generated_` prefix, `*.pb.go`, `*_generated.go`
- Vendored code: file path starts with `vendor/`

If the file is generated or vendored, output:
```json
{
  "classification": "uncertain",
  "confidence": 0.3,
  "reasoning": "Finding is in generated/vendored code, not maintainable by this repo",
  "evidence": {
    "generated_or_vendored": true
  },
  "risk_statement": "N/A",
  "fix_recommendation": "N/A"
}
```

## Investigation Methodology

1. **Read the flagged file** at the reported line. If file_path is empty or doesn't exist, skip to step 3. If line_start is null, read the entire file and locate the relevant section.

2. **Understand the context**: What function/method is this in? What does it do? Read enough surrounding code to understand the purpose.

3. **Grep for callers**: Search for references to the flagged function/method across the repo. Trace who calls it.

4. **Trace the execution path**: Follow the call chain from the entry point (HTTP handler, CLI command, event listener) to the flagged code. Note each file:line in the chain.

5. **Check for mitigations**: Look for input validation, sanitization, auth guards, WAF configurations, or other security controls between the entry point and the vulnerable code.

6. **Check ProdSec mitigating factors**:
   - Is the input user-controlled or internal-only?
   - Is the endpoint authenticated?
   - Is there a WAF or reverse proxy that filters input?
   - Is the code only reachable in test/development mode?

7. **Produce verdict** with file:line evidence for each step of your investigation.

## Output Format

Respond with valid JSON only. No markdown, no prose.

```json
{
  "classification": "confirmed | confirmed_dead_code | likely_fp | uncertain",
  "confidence": 0.0-1.0,
  "reasoning": "Full evidence with file:line references for each investigation step",
  "evidence": {
    "call_chain": ["main.go:92", "handler.go:45", "executor.go:128"],
    "mitigations_found": ["auth middleware at router.go:34"],
    "mitigations_missing": ["no input sanitization before eval()"],
    "entry_points": ["HTTP POST /api/execute"],
    "generated_or_vendored": false
  },
  "risk_statement": "One-line impact if exploited",
  "fix_recommendation": "Specific code change with file:line"
}
```

## Rules

- "confirmed": You traced the full call chain and found no mitigating controls. >80% confident this is exploitable.
- "confirmed_dead_code": The vulnerability exists but the code is not currently reachable (no callers, dead import, generated code). The bug is real but not exploitable in the current codebase.
- "likely_fp": You found specific mitigating controls that prevent exploitation. >80% confident with evidence.
- "uncertain": You couldn't trace the full path, or mitigations are partial. Default to this when in doubt.
- NEVER classify as likely_fp without citing specific mitigating code with file:line.
- If you can't read the file (doesn't exist, binary, etc.), classify as "uncertain".
