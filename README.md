# RHOAI Triage Skills

Security finding triage skills for the RHOAI Security Scanner pipeline. Each skill is an LLM prompt that guides an AI agent to investigate and classify a specific type of security finding.

## Skills

| Skill | Purpose | Input |
|-------|---------|-------|
| **sast-triage** | 7-step SAST finding investigation with exploitability assessment | semgrep, kube-linter, adversarial-reviewing findings |
| **agent-cve-triage** | CVE reachability analysis with supply chain assessment | trivy, grype, osv-scanner, pip-audit, govulncheck findings |
| **secrets-triage** | Credential validation (confirmed_secret, test_fixture, placeholder, revoked) | gitleaks, trufflehog findings |
| **container-triage** | Container image CVE assessment (base_image_only, build_time_only) | trivy-image, grype-image findings |
| **fast-triage** | Lightweight prompt-only classification (likely_real, likely_fp, needs_deep_triage) | Any finding (no tools, fast) |
| **triage-scorer** | Second-agent review of borderline verdicts (agree/disagree) | Findings with low-confidence triage |
| **cve-triage** | Deterministic CVE verdict computation | SCA findings with VEX context |

## Skill Structure

Each skill directory contains:

- `SKILL.md`: The prompt that guides the AI agent (YAML frontmatter + methodology + output format)
- `schema.json`: JSON schema for the expected output (used by the validation engine)
- `rubric.yaml` (optional): Completeness scoring rubric (0-8 points)

## How They're Used

The RHOAI Security Scanner pipeline dispatches these skills during Stage 2 (AI Triage):

1. **Routing**: Each finding is matched to the appropriate skill based on its source tool
2. **Agent execution**: A Claude agent clones the repo and uses Read/Grep/Glob tools to investigate
3. **Output validation**: The Skill Enforcement Engine validates the output against schema.json
4. **Confidence calibration**: CodeClaimVerifier verifies the agent's factual claims

## Classifications

All triage skills produce one of these canonical classifications:

- `confirmed`: Real vulnerability, exploitable
- `confirmed_dead_code`: Vulnerability exists but code is unreachable
- `likely_fp`: Likely false positive with evidence
- `uncertain`: Insufficient evidence to classify

## Installation

The scanner clones this repo at build time:

```dockerfile
RUN git clone --depth 1 --branch v1.0.0 https://github.com/ugiordan/rhoai-triage-skills.git /app/skills/bundled/triage
```

## License

Apache 2.0

## Copyright

Copyright (c) Red Hat, Inc.
