# Container Profile

This profile applies to container image CVE findings from tools like trivy-image and grype-image.

## Profile-Specific Guidance

### Container-Specific Context

Container image CVEs require a different triage approach than source code CVEs. Key differences:
- **Layering**: Vulnerabilities may be in the base image (not controlled by this repo) or in packages added by the Dockerfile
- **Build vs Runtime**: Some packages are only used during build, not present in the final runtime image
- **VEX Data**: Container scanners often include VEX data from upstream vendors (Red Hat, Ubuntu, Alpine)

### Layer Analysis

Determine which layer the vulnerable package is in:

#### Base Image Layer

The vulnerability is inherited from the upstream base image (e.g., `FROM registry.access.redhat.com/ubi8/ubi:8.6`):
- Package was NOT explicitly installed in the Dockerfile
- Package is part of the base image OS (Red Hat, Ubuntu, Alpine)
- Fix depends on upstream vendor releasing an updated base image

To check: Read the Dockerfile and look for `RUN yum install`, `RUN apt-get install`, `RUN apk add`, etc. If the package is not in any of these commands, it's in the base layer.

#### Application Layer

The vulnerability is in a package explicitly added by this repo's Dockerfile:
- Package is installed via `RUN yum install`, `RUN apt-get install`, `RUN apk add`
- Package is added via `COPY` or `ADD` from the build context
- This repo controls the version and can fix it

### VEX Status for Containers

Container scanners (Trivy, grype) often include VEX data from upstream vendors. Check the VEX status:

#### VEX Justifications

- **"vulnerable_code_not_in_execute_path"**: The vulnerable function is not executed at runtime. This is common for libraries that ship many features but only a subset is used.
- **"vulnerable_code_not_present"**: The vulnerable code was removed or patched by the vendor, even though the package version number suggests it's vulnerable.
- **"inline_mitigations_already_exist"**: The vendor backported a security fix without bumping the version number. Common in RHEL/CentOS/Ubuntu LTS.
- **"component_not_present"**: The package is not actually in the image (scanner false positive).

If VEX data is present and the justification is strong, align your classification with VEX.

### Build vs Runtime Packages

Some packages are only used during the build process and are not present in the final runtime image:

#### Build-Time Only

Indicators:
- Package is installed in a multi-stage build's early stage (before `FROM ... AS runtime`)
- Package is in `BuildRequires` or build dependencies (e.g., `gcc`, `make`, `npm`)
- Package is removed in the same Dockerfile layer (`RUN yum install gcc && ... && yum remove gcc`)

If the package is build-time only, classify as `build_time_only`.

#### Runtime Packages

Indicators:
- Package is in the final stage of a multi-stage build
- Package is used by the application at runtime (libraries, interpreters, utilities)
- Package is not removed by Dockerfile `RUN` commands

### Dockerfile Pinning

Check if the vulnerable package version is pinned in the Dockerfile:
- **Pinned**: `RUN yum install -y curl-1.2.3` (specific version)
- **Unpinned**: `RUN yum install -y curl` (latest version at build time)

If unpinned, rebuilding the image may automatically pick up the fixed version.

### Runtime Usage Assessment

Determine if the vulnerable code is actually executed at runtime:

1. **Read the Dockerfile**: What commands are run? What binaries are executed?
2. **Check entrypoint/CMD**: What process is started when the container runs?
3. **Grep the application code**: Does the application import or call the vulnerable package?
4. **For libraries**: Is the vulnerable function called? (requires reading CVE details and tracing code)

If the package is present but the vulnerable function is never called, classify as `likely_fp` (with VEX alignment if VEX agrees).

### Evidence Fields (Container-Specific)

Add these fields to the `evidence` object:

```json
{
  "package_layer": "base | application | unknown",
  "base_image": "registry.access.redhat.com/ubi8/ubi:8.6",
  "installed_by": "base_image | Dockerfile:RUN_line_12 | unknown",
  "vex_status": "not_affected | fixed | affected | no_vex_data",
  "vex_justification": "vulnerable_code_not_in_execute_path | vulnerable_code_not_present | inline_mitigations_already_exist | component_not_present | none",
  "fix_available": true,
  "fix_version": "1.2.4",
  "fix_in_base_image": true,
  "runtime_usage": "confirmed | likely | unlikely | unknown",
  "package_pinned": false,
  "build_time_only": false,
  "dockerfile_location": "Dockerfile:23"
}
```

## Example Classifications

### Confirmed: Application Layer, Runtime Used

```json
{
  "classification": "confirmed",
  "confidence": 0.9,
  "reasoning": "CVE-2024-1234 in curl (libcurl.so.4) is in application layer, installed at Dockerfile:23. Grep found curl used in healthcheck script (scripts/health.sh:12) executed at runtime. Fix is available (upgrade to curl-1.2.4).",
  "evidence": {
    "package_layer": "application",
    "installed_by": "Dockerfile:RUN_line_23",
    "vex_status": "affected",
    "fix_available": true,
    "fix_version": "1.2.4",
    "runtime_usage": "confirmed",
    "package_pinned": false,
    "dockerfile_location": "Dockerfile:23"
  },
  "risk_statement": "CVE-2024-1234: RCE via curl in healthcheck script",
  "fix_recommendation": "Upgrade curl in Dockerfile:23 to 1.2.4: RUN yum install -y curl-1.2.4"
}
```

### Base Image Only: Wait for Upstream

```json
{
  "classification": "base_image_only",
  "confidence": 0.85,
  "reasoning": "CVE-2024-5678 in openssl is part of base image UBI 8.6. Not explicitly installed in Dockerfile. Application code does not import openssl (Go TLS uses stdlib, not openssl). Wait for Red Hat to release updated UBI 8.7.",
  "evidence": {
    "package_layer": "base",
    "base_image": "registry.access.redhat.com/ubi8/ubi:8.6",
    "installed_by": "base_image",
    "vex_status": "affected",
    "fix_available": true,
    "fix_in_base_image": true,
    "runtime_usage": "unlikely",
    "package_pinned": false
  },
  "risk_statement": "Low impact: openssl not used by application runtime",
  "fix_recommendation": "Monitor for UBI 8.7 release with openssl fix. Rebuild image when available."
}
```

### Build Time Only: Not in Runtime Layer

```json
{
  "classification": "build_time_only",
  "confidence": 0.9,
  "reasoning": "CVE-2024-9999 in gcc is only used during build (Dockerfile:15, multi-stage build). The final runtime stage (FROM scratch) does not include gcc. Package is not in the final image.",
  "evidence": {
    "package_layer": "application",
    "installed_by": "Dockerfile:RUN_line_15",
    "build_time_only": true,
    "runtime_usage": "unlikely",
    "dockerfile_location": "Dockerfile:15"
  },
  "risk_statement": "No runtime risk: gcc not present in final image",
  "fix_recommendation": "No action needed. Build-time dependency only, not in runtime."
}
```

### Likely FP: VEX Inline Mitigation

```json
{
  "classification": "likely_fp",
  "confidence": 0.85,
  "reasoning": "CVE-2024-7777 in glibc flagged by Trivy, but VEX data from Red Hat marks as not_affected with justification 'inline_mitigations_already_exist'. RHEL backported the fix without bumping version number.",
  "evidence": {
    "package_layer": "base",
    "base_image": "registry.access.redhat.com/ubi8/ubi:8.6",
    "vex_status": "not_affected",
    "vex_justification": "inline_mitigations_already_exist",
    "runtime_usage": "confirmed"
  },
  "risk_statement": "N/A",
  "fix_recommendation": "No action needed. Red Hat backported fix in UBI 8.6."
}
```

### Likely FP: Vulnerable Function Not Called

```json
{
  "classification": "likely_fp",
  "confidence": 0.8,
  "reasoning": "CVE-2024-8888 in libxml2 affects parseExternal() function. Grepped application code and found libxml2 is only used for internal config parsing (config/parse.go:45), which calls parseInternal() only. Vulnerable function is not called.",
  "evidence": {
    "package_layer": "application",
    "installed_by": "Dockerfile:RUN_line_34",
    "vex_status": "no_vex_data",
    "runtime_usage": "likely",
    "vulnerable_function": "parseExternal",
    "call_sites": []
  },
  "risk_statement": "N/A",
  "fix_recommendation": "No immediate action needed. Consider upgrading libxml2 to eliminate supply chain risk."
}
```

### Uncertain: Cannot Determine Layer

```json
{
  "classification": "uncertain",
  "confidence": 0.5,
  "reasoning": "CVE-2024-3333 in zlib flagged by scanner, but cannot determine if it's in base image or application layer. Dockerfile uses multi-stage build with COPY --from=builder, and zlib may be pulled transitively. Cannot grep for usage (binary-only image).",
  "evidence": {
    "package_layer": "unknown",
    "base_image": "registry.access.redhat.com/ubi8/ubi:8.6",
    "installed_by": "unknown",
    "vex_status": "no_vex_data",
    "runtime_usage": "unknown"
  },
  "risk_statement": "Uncertain: Cannot determine package source or usage",
  "fix_recommendation": "Manual investigation required. Inspect image layers with 'docker history' or 'dive' tool."
}
```
