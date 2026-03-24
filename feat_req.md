# GitGuard: Detailed Feature Requirements
## FR-1.1: CLI Initiation & Input Validation 🟡 PRE-MVP (12 hours)
### Scan Initiation:

1. User enters GitHub repository URL via CLI command: gitguard check <url>
2. System checks for actively running GitGuard containers - block concurrent scans to save host resources
3. System validates URL format before allocating local resources
4. System verifies host environment prerequisites (Docker daemon running, Python 3.10+)
5. System verifies GEMINI_API_KEY is present in environment variables
6. System creates a local scan record in .gitguard/scans.json

**URL & Input Validation:**

7. URL must include protocol (http:// or https://)
8. URL must contain valid domain name matching github.com or gitlab.com
9. System auto-strips trailing .git or URL parameters if present
10. System strictly rejects localhost, IP addresses, or local file paths (file://)
11. System validates repository is publicly accessible (receives HTTP 200 on shallow fetch)
12. Maximum URL length: 2048 characters

**Pre-Flight Verification:**

13. System pings local Docker daemon API via docker-py
14. Timeout for Docker daemon reachability check: 5 seconds
15. If Docker unreachable, display actionable error: "Docker daemon not running."
16. If API key missing, prompt user to input it and save securely to .env
17. System checks host available RAM (requires minimum 1GB free for sandbox)

**Scan Record Creation (Local State):**

18. System generates unique scan_id (UUIDv4)
19. System stores: scan_id, target_url, timestamp, host_os
20. System sets initial status: initializing_sandbox

**User Feedback (UI):**

21. After validation, clear terminal and render Rich dashboard
22. Display animated progress spinner with status messages
23. Show estimated completion time (30-45 seconds)

**Error Handling:**

24. Invalid URL format: Display red inline error message and exit(1)
25. Repository private/404: Display "Cannot access repository. Is it public?"
26. Docker not installed/running: Display download link and exit(1)

**Dependencies: None**
**Acceptance Criteria:**

URL validation successfully blocks local paths and invalid domains.
Pre-flight checks accurately detect Docker and API key states.
Local scan record created with initial metadata.
Rich UI renders without breaking terminal formatting.

## FR-3.1: Sandboxed Detonation (The "Air Gap") 🔴 MVP (16 hours)

**Container Lifecycle:**

1. System dynamically pulls or builds the target Docker image upon scan initiation.
2. System executes the container using docker-py client.
3. System clones the target repository directly inside the container, skipping host filesystem completely.
4. System restricts git clone to --depth 1 to optimize speed and resource usage.
5. System enforces a strict 60-second maximum execution timeout for the container.

**Resource & Host Isolation:**

6. System explicitly disables all host volume mounts (volumes={}).
7. System runs the container process under a restricted, non-root user (USER pwuser).
8. System drops all default Linux capabilities (cap_drop=["ALL"]).
9. System restricts container memory to 512MB (mem_limit="512m").
10. System restricts CPU usage to 1 core (nano_cpus=1000000000).

**Network Containment:**

11. System provisions the container on a standard Docker bridge network.
12. System allows outbound HTTP/HTTPS traffic (ports 80, 443) to external WAN IP addresses.
13. System explicitly blocks outbound traffic to internal LAN ranges (e.g., 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12) via iptables/Docker networking rules to prevent local network scanning.

**Cleanup & Teardown:**

14. System immediately issues a docker rm -f <container_id> upon scan completion.
15. System intercepts user interrupts (Ctrl+C) and guarantees container destruction before the CLI process exits.

**Dependencies: FR-1.1 (CLI Initiation)**
**Acceptance Criteria:**

Untrusted code executes entirely within the container.
Container cannot read or write to the host machine's filesystem.
Container is forcefully removed after 60 seconds or upon completion, leaving zero persistent artifacts.

## FR-3.2: Playwright Spy (Dynamic Behavioral Analysis) 🔴 MVP (24 hours)

**Browser Initialization:**

1. Spy script starts a local Python HTTP server targeting the cloned repository directory.
2. Spy script launches a Headless Chromium browser via Playwright.
3. Spy script modifies browser fingerprints (e.g., sets navigator.webdriver = false) to evade anti-bot detection.

**Network Interception:**

4. System hooks page.on("request") to capture all outbound HTTP and HTTPS requests.
5. System records the target URL, HTTP Method (GET/POST/PUT), and Request Headers.
6. System intercepts and logs WebSocket (ws://, wss://) connection attempts.
7. System captures DNS queries made by the running application.

**Resource Monitoring:**

8. System hooks browser APIs to detect unauthorized access to navigator.clipboard.
9. System monitors and logs attempts to request Microphone or Webcam permissions.
10. System flags attempts to read local file paths (file://).

**Human Interaction Simulation ("Lazy Loading" Defeat):**

11. System injects a mandatory sleep(5000) (5-second wait) to trigger time-delayed payloads.
12. System executes randomized mouse.move() events across the viewport.
13. System simulates random scrolling behavior to trigger onScroll event listeners.

**Telemetry Export:**

14. System formats all intercepted events into a standardized NDJSON (Newline Delimited JSON) payload.
15. System streams NDJSON to stdout to be consumed by the Host CLI.

**Dependencies: FR-3.1 (Sandboxed Detonation)**
**Acceptance Criteria:**

All outbound network requests and WebSocket connections are accurately logged.
Time-delayed malware executes due to the simulated human interaction and 5-second wait.
Telemetry streams successfully from the container to the host in NDJSON format.

## FR-3.3: Gemini 3 Audit (The Logic Firewall) 🔴 MVP (12 hours)

**Context Aggregation:**

1. System reads the raw text of the target repository's README.md.
2. System truncates the README to a maximum of 3000 tokens to save API context window.
3. System parses the NDJSON telemetry stream captured from FR-3.2.
4. System formats the README and Telemetry into the predefined "Intent vs. Reality" prompt template.

**AI Invocation & Semantic Scoring:**

5. System initializes the google-genai client using the configured GEMINI_API_KEY.
6. System sends the context to the Gemini 3 model with temperature=0.1 for strict, deterministic analysis.
7. System instructs the AI to evaluate if the observed network telemetry matches the stated intent of the README (e.g., flagging a local calculator that connects to an external IP).
8. System sets a 15-second timeout for the API response.

**Response Parsing & Output:**

9. System enforces structured JSON output via response_schema.
10. System extracts the verdict field (Must be SAFE, SUSPICIOUS, or MALICIOUS).
11. System extracts the reasoning field (Natural language explanation of the verdict).
12. System passes the parsed data to the CLI Rich formatter for terminal display.

**Dependencies: FR-3.2 (Playwright Spy)**
**Acceptance Criteria:**

System correctly identifies discrepancies between the README intent and actual network behavior.
AI returns a strict JSON object with a definitive Verdict and natural language explanation.

## FR-3.4: AI De-Obfuscation (Hidden Code Revealer) 🟡 PRE-MVP (16 hours)
**Static Scanning & High-Entropy Detection:**

1. System scans all .py, .js, and .sh files in the repository prior to dynamic execution.
2. System calculates Shannon Entropy on all string literals to identify gibberish/obfuscated text.
3. System specifically searches for deeply nested eval(), exec(), atob(), and b64decode() calls.

**Code Translation:**

4. System extracts the flagged high-entropy strings and obfuscated blocks.
5. System sends the extracted blocks to Gemini 3 with a dedicated "De-obfuscation" system prompt.
6. Gemini 3 decodes the string (Base64, Hex, etc.) and analyzes the hidden logic.

**Payload Analysis & Reporting:**

7. System extracts Gemini's plain-English translation of the payload (e.g., "This script downloads a file from attacker.com").
8. System appends the translated payload analysis to the final GitGuard security report under a "Hidden Payloads" section.

**Dependencies: None (Runs via Host static analysis)**
**Acceptance Criteria:**

Base64 encoded malicious payloads are successfully detected and extracted.
Gemini 3 accurately translates the obfuscated code into a readable summary.

## FR-3.5: Visual Phishing Guard (Multimodal Feature) 🔵 POST-MVP (20 hours)

**Image Capture:**

1. Playwright Spy triggers a page.screenshot(full_page=True) after the 5-second wait period.
2. System converts the screenshot to a Base64 encoded image string.

**Multimodal Analysis:**

3. System streams the Base64 image to the Gemini 3 Vision API.
4. System appends the prompt: "Does this screenshot look like a known login page (Google, Microsoft, Bank) but is hosted on a local or strange URL?"
5. System passes the local HTTP server URL as context to the AI.

**Verdict Integration:**

6. If Gemini Vision returns a match, system forces the overall scan verdict to MALICIOUS.
7. System outputs a specific "PHISHING ALERT" warning to the user interface, detailing which brand the app is attempting to mimic.

**Dependencies: FR-3.2 (Playwright Spy)**
**Acceptance Criteria:**

Playwright successfully captures a screenshot of the running app.
Gemini Vision correctly identifies pixel-perfect clones of major login portals running on localhost.

## FR-3.6: Dependency "Typosquatting" Check 🔴 MVP (8 hours)
**Manifest Parsing:**

1. System locates requirements.txt (Python) or package.json (Node) in the repository root.
2. System parses and extracts all listed package names.

**Similarity Calculation:**

3. System loads a cached dictionary of the Top 5000 most downloaded PyPI and NPM packages.
4. System uses the Levenshtein Distance algorithm to compare repository packages against the Top 5000.
5. System flags any package that scores between 85% and 99% similarity to a top package (e.g., pandaas vs pandas).
6. System explicitly ignores exact matches (100% similarity).

**Alert Generation:**

7. If a typosquatted package is detected, system halts the dynamic execution phase to prevent accidental malware installation.
8. System displays a critical warning: "Warning: This repo installs [FakePackage]. Did you mean [RealPackage]?"

**Dependencies: None (Runs via Host static analysis)**

Acceptance Criteria:
System successfully parses standard package manifests.
Levenshtein algorithm accurately flags misspelled variations of popular packages.

## FR-3.7: "Ask the Auditor" (Interactive Mode) 🟡 PRE-MVP (12 hours)
**Chat Initialization:**

 1. System prompts the user after a completed scan: "Would you like to ask the Auditor about this report? (y/n)".
 2. Alternately, system accepts `--chat` flag via CLI to bypass the prompt and launch immediately.
 3. System initializes a continuous chat session using the `google-genai` chat functionality.

**Context Retention:**

 4. System injects the entirety of the previous scan's context (README, Telemetry, Gemini Verdict, and De-obfuscated code) into the chat session's system memory.
 5. System ensures the AI maintains the persona of a "Senior Security Auditor".

**User Interaction Loop:**

 6. System provides a standard CLI input prompt (`GitGuard> `).
 7. System sends user queries to the active Gemini chat session.
 8. System streams the AI's response back to the terminal using Rich markdown formatting.
 9. System supports `exit`, `quit`, or `Ctrl+C` commands to safely terminate the interactive mode.

**Dependencies:** FR-3.3 (Gemini 3 Audit)
**Acceptance Criteria:**

* Chat session successfully retains the context of the just-completed scan.
* User can ask specific questions about flagged lines of code or network calls.
* Markdown responses render correctly in the terminal interface.
