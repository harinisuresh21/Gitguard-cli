# GitGuard: Feature Requirements

## 1. Product Definition

GitGuard is a CLI for repository risk assessment, not a general vulnerability scanner.

Its job is to help a user decide whether a public repository appears safe to inspect or execute.
It does this by combining:

- deterministic static checks
- isolated runtime observation inside Docker
- optional AI-assisted explanation

GitGuard must never claim that a repository is "fully safe". A `SAFE` result means "no strong malicious indicators were found within the limits of this scan."

## 2. Security Boundaries

These boundaries are mandatory:

1. The host CLI may validate URLs, inspect metadata, parse manifests, and call Docker.
2. The host CLI must never execute untrusted repository code directly on the host.
3. Repository cloning for runtime analysis must happen inside the sandbox container only.
4. No host directory may be mounted into the sandbox.
5. The sandbox must run as a non-root user with restricted resources.
6. The sandbox must be destroyed after the scan or on interruption.

## 3. Supported Scope

### MVP Scope

- Public GitHub and GitLab repository URLs
- Static checks for Python and Node dependency manifests
- Dynamic analysis for repositories that look like browser-based web apps
- Final verdicts: `SAFE`, `SUSPICIOUS`, `MALICIOUS`, `ERROR`

### Out of Scope for MVP

- Private repository authentication
- Full source-code vulnerability scanning
- Kernel- or container-escape detection
- Native execution on the host OS
- Guaranteed support for every repository language or build system
- Claims of comprehensive malware detection

## 4. Verdict Model

GitGuard must use deterministic findings as the primary basis for verdicts.
AI may explain or correlate findings, but it must not invent hard signals.

### Verdict Rules

- `MALICIOUS`
  - Confirmed typosquatted or misleading dependency name
  - Attempted connection to blocked local-network targets
  - Hidden or inconsistent outbound network exfiltration relative to stated README intent
  - Clear install-time or runtime behavior consistent with credential theft, clipboard theft, or hidden payload execution
- `SUSPICIOUS`
  - Unexpected external network access
  - Obfuscated code requiring further review
  - Permission requests or browser behavior inconsistent with the repository description
  - Dangerous shell or subprocess execution patterns discovered statically without clear proof of maliciousness
- `SAFE`
  - No strong malicious indicators found during supported checks
- `ERROR`
  - Scan could not complete due to environment, unsupported flow, timeout, or internal failure

## FR-1.1: CLI Initiation and Input Validation

### Goals

Accept a repository URL, validate it, verify host prerequisites, and create a scan record without executing untrusted code.

### Functional Requirements

1. The CLI command must be `gitguard check <url>`.
2. The system must reject concurrent scans by default.
3. The system must validate the URL before allocating sandbox resources.
4. The system must verify Docker daemon availability.
5. The system must create a local scan record before sandbox launch.
6. The system must support public `github.com` and `gitlab.com` repository URLs only for MVP.

### URL Validation

1. Accepted schemes: `https://` and `http://`.
2. The URL must resolve to `github.com` or `gitlab.com`.
3. The system must normalize trailing `.git` and remove query parameters for internal processing.
4. The system must reject localhost, IP literal targets, and `file://` paths.
5. Maximum URL length: 2048 characters.
6. The system must verify remote repository accessibility without cloning to the host filesystem.

### Pre-flight Checks

1. Docker daemon reachability must be checked with a timeout of 5 seconds.
2. The system must verify at least 1 GB of free host memory before launching the sandbox.
3. The system must verify whether `GEMINI_API_KEY` is present only if AI audit is enabled.
4. Missing Docker must produce an actionable error message and non-zero exit code.
5. Missing optional AI credentials must not block deterministic scanning.

### Local State

1. The system must generate a `scan_id` using UUIDv4.
2. The scan record must store `scan_id`, `target_url`, timestamp, host OS, and initial status.
3. Initial status must be `initializing`.
4. Scan records must be stored under a local `.gitguard` state directory.

### Acceptance Criteria

- Invalid URLs are rejected before container launch.
- Host local paths and localhost targets are blocked.
- Docker unavailability is detected in under 5 seconds.
- A scan record is created before runtime analysis starts.

## FR-2.1: Static Dependency and Manifest Guard

### Goals

Detect obviously risky dependencies and install-time execution patterns before dynamic execution begins.

### Functional Requirements

1. The system must search the repository for supported manifests after the repository is available in the sandbox or a non-executing static analysis stage.
2. Supported Python manifests for MVP:
   - `requirements.txt`
   - `pyproject.toml`
   - `setup.py`
   - `Pipfile`
3. Supported Node manifests for MVP:
   - `package.json`
4. The system must extract dependency names without executing repository code.
5. The system must compare package names against cached high-popularity package lists for PyPI and npm.
6. Exact matches must not be flagged as typosquatting.
7. High-similarity names must be flagged for review.
8. If a clear typosquatted dependency is detected, the system must stop before dynamic execution.

### Static Risk Checks

1. The system must use Levenshtein or equivalent string similarity for dependency-name comparisons.
2. The system must parse `setup.py` statically and must not execute it.
3. The system must flag suspicious install-time patterns such as:
   - `os.system`
   - `subprocess`
   - `urllib.request`
   - `requests` network calls
4. The system may flag very new packages or reputation anomalies as `SUSPICIOUS`, not automatically `MALICIOUS`.

### Acceptance Criteria

- A repository containing `requsts` instead of `requests` is flagged before dynamic execution.
- `setup.py` is analyzed without being executed.
- Exact package matches are not false-flagged.

## FR-3.1: Sandboxed Runtime Detonation

### Goals

Run untrusted repository code only inside a constrained Docker sandbox.

### Functional Requirements

1. The system must launch the sandbox via the Docker Python SDK.
2. The target repository must be cloned inside the container only.
3. The clone must use `--depth 1`.
4. The sandbox must enforce a hard runtime timeout of 60 seconds.
5. The system must support cleanup on success, failure, timeout, and `Ctrl+C`.

### Isolation Requirements

1. No host volume mounts may be attached.
2. The container must run as a non-root user.
3. The container must drop unnecessary Linux capabilities.
4. The container must be read-only where practical, with explicit writable temp locations only.
5. Memory limit must be 512 MB.
6. CPU limit must be 1 logical core.

### Network Requirements

1. The sandbox may use a bridged network for outbound observation.
2. The implementation must attempt to block outbound access to private LAN ranges.
3. If LAN blocking cannot be enforced on the current host platform, the scan must surface a degraded-isolation warning rather than claiming full protection.
4. The local app server used for browser inspection must remain internal to the sandbox.

### Cleanup Requirements

1. The system must force-remove the container on completion.
2. The system must force-remove the container on timeout.
3. The system must intercept `Ctrl+C` and remove the container before exiting.
4. The system must leave no persistent sandbox artifacts by default.

### Acceptance Criteria

- Untrusted code never executes directly on the host.
- The container is removed after every terminal state.
- The scan reports degraded isolation when LAN blocking is unavailable.

## FR-3.2: Dynamic Browser and Network Observation

### Goals

Observe runtime browser behavior for supported web-style repositories.

### Applicability

This feature runs only when the repository appears to be a browser-based web app.
Unsupported repository types must fall back to static analysis and return a limited-coverage result.

### Functional Requirements

1. The spy process must start a local HTTP server inside the sandbox against the cloned repository.
2. The spy process must launch headless Chromium via Playwright.
3. The browser may apply anti-automation hardening such as `navigator.webdriver = false`.
4. The system must capture outbound HTTP and HTTPS requests.
5. The system must capture WebSocket connection attempts.
6. The system must record target URL, method, headers, and payload size when available.
7. The system must monitor access to:
   - clipboard APIs
   - camera or microphone permissions
   - `file://` navigation attempts
8. The system must wait at least 5 seconds before concluding the page is idle.
9. The system must simulate basic mouse movement and scrolling.
10. Telemetry must be streamed as NDJSON to stdout for the host CLI to consume.

### Acceptance Criteria

- Outbound requests are logged with normalized event structure.
- Time-delayed page behavior is still observable after the required wait period.
- Unsupported repo types do not crash the scan flow.

## FR-3.3: README Intent vs Runtime Audit

### Goals

Compare the repository's stated purpose against deterministic findings and runtime telemetry.

### Functional Requirements

1. The system must read `README.md` when present.
2. The system must truncate README context to a bounded size before AI submission.
3. The system must combine README text with telemetry and static findings.
4. The system must submit a structured prompt to the AI model only after deterministic checks complete.
5. The AI response must be constrained to a structured JSON schema.
6. The AI output must include:
   - `verdict_recommendation`
   - `reasoning`
   - `evidence_summary`
7. The host must remain the final authority on verdict assignment.

### Non-Requirements

1. AI must not overrule a deterministic `MALICIOUS` finding.
2. AI must not be required for basic scan completion.
3. Missing AI credentials must degrade to deterministic-only reporting.

### Acceptance Criteria

- The scan still completes when AI is disabled.
- AI output is structured and parseable.
- Final verdict assignment remains deterministic-first.

## FR-3.4: Static Obfuscation Review

### Goals

Identify suspicious encoded or hidden payloads before or alongside runtime analysis.

### Functional Requirements

1. The system must scan supported source files for:
   - high-entropy strings
   - nested `eval()` or `exec()` usage
   - `atob()`, `b64decode()`, or similar decode chains
2. The system must extract suspicious code blocks without executing them.
3. The system may send extracted blocks to AI for translation into plain-language summaries.
4. The final report must separate deterministic evidence from AI interpretation.

### Acceptance Criteria

- Encoded payload patterns are surfaced in the report.
- AI-translated explanations do not replace the raw evidence.

## FR-3.5: Interactive Auditor Mode

### Goals

Allow the user to ask follow-up questions about the most recent scan report.

### Functional Requirements

1. The system may prompt the user after scan completion to enter chat mode.
2. The system may accept a `--chat` flag to enter chat mode immediately after a completed scan.
3. The chat session must load the just-completed scan context only.
4. The system must support `exit`, `quit`, and `Ctrl+C` to terminate chat mode safely.

### Acceptance Criteria

- The user can ask about flagged dependencies, network events, and verdict reasoning.
- Chat mode does not alter stored scan evidence.

## 5. Reporting Requirements

The final report must include:

1. Scan metadata
2. Isolation status
3. Deterministic findings
4. Dynamic telemetry summary, when applicable
5. AI reasoning, when available
6. Final verdict
7. Coverage limitations or degraded-mode warnings

## 6. MVP Success Criteria

GitGuard MVP is considered complete when all of the following are true:

1. Running `gitguard check` on a known-safe public repository returns `SAFE` or limited-coverage `SAFE` in an understandable report.
2. Running `gitguard check` on a repository containing a clear typosquatted dependency returns `MALICIOUS` before dynamic execution.
3. Running `gitguard check` on a browser-based repository that silently performs unexpected outbound requests returns at least `SUSPICIOUS`, with evidence.
4. Pressing `Ctrl+C` during a scan leaves no lingering GitGuard containers.
5. The tool never clones or executes the untrusted repository directly on the host.
