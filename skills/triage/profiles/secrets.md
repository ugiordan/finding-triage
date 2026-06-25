# Secrets Profile

This profile applies to secret/credential findings from tools like TruffleHog and gitleaks.

## Profile-Specific Guidance

### Real vs Test Credentials

The primary triage question: Is this a real, active credential or a test fixture?

#### Test/Fixture Indicators

Check for these signals:
- **File path**: `*_test.go`, `test/`, `tests/`, `testdata/`, `fixtures/`, `examples/`, `docs/`, `*.md`
- **File content**: `// test`, `// example`, `// mock`, `// fixture`, `// sample`
- **Variable names**: `mockToken`, `testKey`, `examplePassword`, `dummySecret`, `fakeAPIKey`
- **Comments near the secret**: "test only", "example", "placeholder", "not real", "for demo purposes"
- **Value patterns**: `YOUR_TOKEN_HERE`, `changeme`, `password123`, `secretkey`, `replace-with-actual-key`

If multiple indicators are present, classify as `test_fixture` with high confidence.

#### Real Credential Indicators

Signals this is a real credential:
- **High entropy**: Random base64, hex, or UUID format (AWS keys, GitHub tokens, API keys)
- **Production code path**: Used in `main()`, HTTP client, database connection, auth middleware
- **No test/example context**: File is not in test directory, no fixture comments
- **Proper credential format**: Matches known patterns (AWS `AKIA...`, GitHub `ghp_...`, JWT structure)

### Credential Type Detection

Identify the credential type for risk assessment:
- **AWS Access Key**: `AKIA[0-9A-Z]{16}`
- **GitHub Token**: `ghp_[a-zA-Z0-9]{36}`, `github_pat_[a-zA-Z0-9_]{82}`
- **Password/Hash**: bcrypt, scrypt, plaintext
- **API Key**: Generic high-entropy string
- **Private Key**: PEM format, SSH key
- **Database Credential**: Connection string, username/password
- **JWT/Bearer Token**: `eyJ...` base64 structure

Include the type in `evidence.secret_type`.

### Entropy Analysis

Check the entropy of the secret:
- **High entropy**: Random base64/hex (e.g., `dGhpc2lzYXJhbmRvbXNlY3JldA==`). More likely real.
- **Medium entropy**: Mixed alphanumeric with some randomness (e.g., `apiKey123XyZ`). Could be either.
- **Low entropy**: Dictionary words, simple patterns (e.g., `password`, `admin123`, `secretkey`). More likely placeholder.

Include entropy assessment in `evidence.entropy`.

### .gitignore Check

Check if the file is in `.gitignore`:
- If YES: The file is not supposed to be committed. This strongly suggests the secret is real and was accidentally committed.
- If NO: The file is tracked by git. Could be intentional (test fixture) or accidental (real secret).

Use `grep -F "path/to/file" .gitignore` to check.

### Git History Analysis

Check when the secret was added:
- **Recent commit**: More likely to be a real secret that was just leaked
- **Old commit**: May be a test fixture that's been in the repo for years
- **Commit message**: Look for "test", "example", "fixture" in the message

Use `git log --all --full-history -- path/to/file` to trace history.

### Rotation and Revocation

If the credential appears real, check for evidence of rotation or revocation:
- **Commit message**: "rotate keys", "revoke token", "update credentials"
- **Code comments**: "revoked", "expired", "replaced"
- **Secret commented out**: The secret is in a comment or disabled code

If rotation/revocation is evident, classify as `revoked`.

### Exposure Scope

Assess the impact if this is a real, active secret:
- **Public repo**: Critical. Secret is exposed to the internet.
- **Private repo**: High. Secret is exposed to repo collaborators.
- **Local-only**: Medium. Secret may not be pushed yet.
- **Test environment**: Low. Secret is for test/dev, not production.

Include exposure scope in `risk_statement`.

### Evidence Fields (Secrets-Specific)

Add these fields to the `evidence` object:

```json
{
  "secret_type": "AWS access key | GitHub token | password | API key | private_key | JWT | database_credential | other",
  "file_context": "production | test | example | config | documentation",
  "is_test_fixture": true,
  "is_placeholder": false,
  "in_gitignore": false,
  "entropy": "high | medium | low",
  "variable_name": "mockToken",
  "commit_age": "2023-01-15 (3 years old)",
  "rotation_evidence": "none | commit_message | code_comment"
}
```

## Example Classifications

### Confirmed: Real AWS Key

```json
{
  "classification": "confirmed",
  "confidence": 0.95,
  "reasoning": "High-entropy AWS access key (AKIA...) found in config/prod.yaml:23. File is in production config directory, not a test file. No test/example comments. File is in .gitignore, suggesting it should not be committed. Commit was recent (2024-03-01). This is a confirmed real secret.",
  "evidence": {
    "secret_type": "AWS access key",
    "file_context": "production",
    "is_test_fixture": false,
    "is_placeholder": false,
    "in_gitignore": true,
    "entropy": "high",
    "commit_age": "2024-03-01 (recent)"
  },
  "risk_statement": "Real AWS access key exposed in public repo. Attacker can access AWS resources with this key.",
  "fix_recommendation": "1. Revoke the AWS key immediately via AWS Console. 2. Remove config/prod.yaml:23 from git history using git filter-repo. 3. Add config/prod.yaml to .gitignore. 4. Use AWS Secrets Manager or environment variables for credentials."
}
```

### Likely FP: Test Fixture, Mock Token

```json
{
  "classification": "likely_fp",
  "confidence": 0.9,
  "reasoning": "Token found in test/fixtures/auth_test.go:12. File path contains 'test' and 'fixtures'. Variable name is 'mockBearerToken'. Comment above says '// test fixture for auth middleware'. Low entropy value 'test-token-123'. This is a test fixture, not a real credential.",
  "evidence": {
    "secret_type": "API key",
    "file_context": "test",
    "is_test_fixture": true,
    "is_placeholder": false,
    "in_gitignore": false,
    "entropy": "low",
    "variable_name": "mockBearerToken"
  },
  "risk_statement": "N/A",
  "fix_recommendation": "No action needed. This is a test fixture, not a real credential."
}
```

### Likely FP: Placeholder, Generic Value

```json
{
  "classification": "likely_fp",
  "confidence": 0.85,
  "reasoning": "Password value is 'changeme' in config/default.yaml:5. This is a well-known placeholder. Low entropy. Comment above says '// Replace with actual password before deployment'. File is example config, not production. This is a placeholder value, not a real secret.",
  "evidence": {
    "secret_type": "password",
    "file_context": "example",
    "is_test_fixture": false,
    "is_placeholder": true,
    "in_gitignore": false,
    "entropy": "low",
    "variable_name": "db_password"
  },
  "risk_statement": "N/A",
  "fix_recommendation": "No action needed. This is a placeholder value in example config."
}
```

### Likely FP: Revoked Token with Rotation Evidence

```json
{
  "classification": "likely_fp",
  "confidence": 0.8,
  "reasoning": "GitHub token found at scripts/deploy.sh:34. Commit message for SHA abc123 says 'rotate GitHub token after leak'. The token is commented out with '# revoked 2024-02-01' above it. Token has been revoked, so no active risk, but should be scrubbed from history.",
  "evidence": {
    "secret_type": "GitHub token",
    "file_context": "production",
    "is_test_fixture": false,
    "is_placeholder": false,
    "in_gitignore": false,
    "entropy": "high",
    "rotation_evidence": "commit_message"
  },
  "risk_statement": "Token was revoked, but should be removed from git history",
  "fix_recommendation": "Remove the commented-out token from scripts/deploy.sh:34 and scrub from git history using git filter-repo."
}
```

### Uncertain: High Entropy, Unclear Context

```json
{
  "classification": "uncertain",
  "confidence": 0.5,
  "reasoning": "High-entropy base64 string found in src/utils/crypto.go:89. Could be a real key or a test fixture. File is not in test directory, but function name is 'generateTestKey'. No .gitignore entry. Cannot determine if this is a real secret or generated for testing.",
  "evidence": {
    "secret_type": "API key",
    "file_context": "production",
    "is_test_fixture": false,
    "is_placeholder": false,
    "in_gitignore": false,
    "entropy": "high",
    "variable_name": "testKey"
  },
  "risk_statement": "Uncertain: May be a real key or test-generated value",
  "fix_recommendation": "Manual review required. Check if this key is used in production or only for testing."
}
```
