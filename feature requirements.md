#  GitGuard: Developer Requirements & Specifications
This document defines the strict engineering requirements, architectural boundaries, and implementation details for GitGuard. It serves as the source of truth for contributors building the platform.

### 🛠️ Core System Prerequisites & Constraints
Language Environment: Python 3.10+ (Type hinting is mandatory across the codebase).

Containerization: Docker Engine API v1.41+ (Host must have Docker daemon running).

Resource Limits: The sandbox must be hard-capped at 512MB RAM and 1.0 CPU cores to prevent fork-bomb malware from crashing the host.

API Dependencies: Google GenAI SDK (google-genai).

### 🚀 Feature 1: CLI Interface & Orchestration (The Host)
Description: The controller that manages the user lifecycle, input validation, and rendering the final output.

#### Functional Requirements:

Must expose a Typer-based CLI with commands: gitguard check <url>, gitguard doctor (system check), and gitguard history.

Must parse and validate GitHub URLs, handling standard HTTP formats, SSH formats, and short-links.

Must enforce a global timeout (e.g., 120 seconds maximum execution time per scan).

Must capture and handle KeyboardInterrupt (Ctrl+C) to instantly kill the Docker container before exiting the CLI.

#### Technical Requirements:

Libraries: typer, rich (for tables, progress spinners, and syntax-highlighted JSON).

State Management: Scan logs and verdicts must be temporarily written to a local .gitguard/ cache folder in the user's home directory for the history command.

### 🛡️ Feature 2: Air-Gapped Sandbox (The Jail)
Description: The secure execution environment. This is the most security-critical component; a failure here means malware infects the user.

#### Functional Requirements:

Must dynamically pull mcr.microsoft.com/playwright/python:v1.40.0-jammy if not present.

The container must run as a non-root user (USER pwuser) to prevent basic privilege escalation.

Volume Mounts: Absolutely NO host directories may be mounted. Code must be injected via git clone from inside the container or via a buffered docker cp equivalent.

Network Isolation: Must allow outbound WAN access (to catch exfiltration) but strictly block internal LAN access (e.g., 192.168.x.x, 10.x.x.x) to prevent the malware from scanning the user's local router or IoT devices.

#### Technical Requirements:

Implementation: Use the docker Python SDK.

Docker Run Equivalent: client.containers.run(..., network_mode="bridge", mem_limit="512m", read_only=True, tmpfs={'/tmp': '', '/app': ''})

### 🕵️ Feature 3: Playwright Spy (Dynamic Behavioral Analysis)
Description: The internal agent that records what the malware actually does at runtime.

#### Functional Requirements:

Must start a local HTTP server targeting the cloned repository's root.

Must launch a Headless Chromium browser, navigating to the local server.

Must override browser navigator properties (e.g., webdriver: false) to prevent malware from detecting it is in an automated sandbox.

Must log every network request: URL, Method, Headers, and Payload Size.

Must simulate human interaction: scrolling the page randomly and moving the mouse to trigger event-listeners tied to malware.

#### Technical Requirements:

Hooks: Implement page.on("request", handler) and page.on("console", handler).

Output: Must stream a standardized NDJSON (Newline Delimited JSON) feed to stdout so the Host can parse it line-by-line in real-time.

### 🐍 Feature 4: Python Package Misleading Attacks (Dependency Guard)
Description: Attackers rely on typosquatting (e.g., coloramaa instead of colorama), dependency confusion (forcing the app to pull from public PyPI instead of a private repo), and starjacking. This feature statically audits dependencies before execution.

#### Functional Requirements:

Manifest Parsing: Must locate and parse all Python dependency manifests: requirements.txt, setup.py, pyproject.toml, and Pipfile.

Typosquatting Detection (The "Fat Finger" Attack): * Extract every package name.

Compare each name against a cached list of the Top 5000 downloaded PyPI packages.

If a package name has a high similarity score (e.g., missing one letter, transposed letters) to a top package, flag it as CRITICAL.

#### Age & Reputation Verification:

Must query the PyPI public API for every dependency.

Flag packages that were published less than 7 days ago.

Flag packages with a disproportionately low version number relative to their name.

Malicious setup.py Detection: * setup.py is executed upon installation. Attackers often put reverse shells directly inside setup.py.

Must parse setup.py without running it to look for os.system, subprocess, or urllib.request calls outside of standard setup logic.

#### Technical Requirements:

Algorithms: Use Levenshtein distance (thefuzz library) for string similarity.

AST Parsing: Use Python's built-in ast (Abstract Syntax Tree) module to safely analyze setup.py without executing it (preventing premature detonation).

API Integration: Use https://pypi.org/pypi/<package_name>/json to fetch metadata.

### 🧠 Feature 5: Gemini 3 Logic Audit (Intent vs. Implementation)
Description: The AI component that acts as the reasoning engine to eliminate false positives.

#### Functional Requirements:

Must read README.md to establish the "Developer's Promise" (e.g., "This is a local calculator").

Must parse the combined outputs of the Playwright Spy and the Dependency Guard.

Must format this evidence into a strict, predefined prompt template.

Must enforce structured JSON output from the AI.

#### Technical Requirements:

Prompt Engineering Strategy: Use a system prompt defining the persona: "You are an expert malware analyst. Your job is to find logical contradictions between a tool's stated purpose and its runtime network behavior."

Temperature: Set the model temperature to 0.1 to ensure highly deterministic, factual reasoning rather than creative hallucinations.

### 🔦 Feature 6: AST-Based De-Obfuscation
Description: Static scanners fail when code is obfuscated. This feature identifies hidden payloads.

#### Functional Requirements:

Scan source code for high-entropy strings (long blocks of random-looking characters) and deeply nested eval() or exec() calls.

Must extract these specific blocks and send them to the AI for decoding.

Example: If the tool finds exec(__import__('base64').b64decode('...')), it must ask Gemini to translate the decoded payload back into plain Python.

#### Technical Requirements:

Heuristics: Implement Shannon Entropy calculations on string literals within the Abstract Syntax Tree. Any string with an entropy score > 4.5 is flagged for AI review.

acceptance_criteria.txt (For Developers)
To consider this project "Dev Complete" for the hackathon:

Running gitguard check on a known safe repo (e.g., a simple hello-world) must return 🟢 SAFE in under 15 seconds.

Running gitguard check on a repo with requests misspelled as requsts in requirements.txt must halt and return 🔴 MALICIOUS (Typosquatting Detected).

Running gitguard check on a repo that pings http://localhost:8080/steal via a hidden JavaScript fetch() must be caught by Playwright and flagged 🔴 MALICIOUS (Network Exfiltration).

If the user presses Ctrl+C during a scan, docker ps must show NO lingering containers.
