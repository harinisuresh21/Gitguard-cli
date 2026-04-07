# 🛡️ GitGuard
Don't Just Clone. Verify Intent.

GitGuard is an AI-powered "Logic Firewall" for developers. It audits the behavioral intent of unknown open-source software by executing it in an air-gapped local sandbox and using LLM to verify that the code's actual behavior matches its stated purpose.

# 🚩 The Problem: The "Blind Trust" Vulnerability
Modern developers routinely run git clone followed by npm install or python main.py to test new tools. This reflexive muscle memory grants untrusted code full access to the host machine, including SSH keys, .env files, and local networks.

The Gap in Existing Security:

SCA Tools (Snyk, Dependabot): Only scan package.json for known vulnerabilities (CVEs) in third-party libraries. They ignore custom malware written directly into the source code.

Static Analysis: Scans for syntax. But a line of code that uploads a file is valid syntax. Static tools cannot know if that upload is a legitimate "Backup Feature" or malicious "Data Exfiltration."

The Real Threat: An app might claim to be a "Simple Offline Calculator" (Intent) but contain a background script that steals your AWS credentials (Implementation).

There is currently no tool that answers: "Does the behavior of this code match its description, and is it safe to run?"

# 💡 The Solution
GitGuard bridges the gap between static code scanning and runtime security through a novel Behavioral Intent Audit.

Sandboxed Detonation: We don't just read code; we run it in an ephemeral, isolated Docker Sandbox on your local machine.

Dynamic Espionage: We inject a Playwright Spy to monitor network calls, WebSocket connections, and file system access attempts while the code executes.

Intent Verification: We use Gemini 3's Enhanced Reasoning to compare the repository's README.md (The Promise) against the runtime telemetry (The Reality) to catch logic mismatches and hidden malware.

# 🚀 Key Features
    .🛡️ Zero-Risk Execution (The Air Gap): Every scan spins up a disposable Docker container. If the code contains ransomware, it only destroys the temporary jail, leaving your host machine 100% safe.

    .🕵️ Playwright Spy: Acts as a digital wiretap. It intercepts hidden HTTP requests and catches "lazy-loading" malware that waits for user interaction before phoning home.

    .🧠 LLM Logic Audit: Understands context. It knows a "Weather App" should make external API calls, but a "Local Image Resizer" should not.

    .🔦 AI De-Obfuscation: Automatically detects Base64 or minified strings, feeds them to Gemini 3, and translates the hidden payloads into readable logic.

    .👁️ Visual Phishing Guard: Uses Gemini Vision to analyze screenshots of the running app to detect pixel-perfect clones of fake login screens (e.g., a fake Microsoft 365 portal).

    .📦 Dependency Typosquatting Check: Protects you from accidentally installing reqests instead of requests.

    .💬 Interactive Auditor Chat: After a scan, chat directly with Gemini to ask, "Exactly which line of code tried to access my webcam?"

# ⚙️ System Architecture
GitGuard operates on a privacy-first, "Bring Your Own Compute" model. No source code is ever uploaded to a cloud server.

The Host (Safe Zone): The Typer CLI parses your command and orchestrates the scan.

The Sandbox (Danger Zone): The Docker Manager spins up an isolated container, clones the target repo, and unleashes the Playwright Spy to monitor execution.

The Brain (Intelligence): The host streams the captured logs to the LLM, which analyzes the evidence and returns a color-coded security verdict.

# 🛠️ Tech Stack
AI Reasoning Engine: Google Gemini 3 (Pro & Flash) + Gemini Vision

Core Backend: Python 3.10+

Isolation Layer: Docker Engine (python-docker SDK)

Dynamic Analysis: Playwright for Python

CLI User Interface: Typer + Rich

# ⚡ Installation & Usage
Prerequisites
Docker Desktop (Must be running)

Python 3.10+

Gemini API Key (Set as GEMINI_API_KEY in your environment)

Quick Start
Bash
#### 1. Install GitGuard
     pip install gitguard

#### 2. Run a pre-flight system check
      gitguard doctor

#### 3. Audit an unknown repository
     gitguard check https://github.com/suspicious-user/free-bitcoin-miner
     
## Demo Case Study: The "Trojan Resizer"
We tested GitGuard against a custom-built dummy malware repository called simple-image-resizer.
The Target's Claim: "A simple Python script to resize images. Works 100% offline."
The Target's Code: Contained a time-delayed script to find .env files and POST them to a remote IP.

GitGuard's Output:

Plaintext
[SANDBOX ALERT] Outbound Network Request Detected
-------------------------------------------------
Target URL:  http://192.168.1.55:8080/upload
Payload:     AWS_ACCESS_KEY_ID=AKIA... (Size: 24kb)

# 🔴 VERDICT: MALICIOUS
### Reasoning from Gemini 3: 
    The README claims this tool is "100% offline", but the application initiated a delayed POST request to an external IP address, attempting 
    to transmit data formatted as AWS Credentials. DO NOT execute this code.
    (Note: Traditional scanners like Snyk and Pylint passed this repository with a 100% safe score because the syntax was valid and dependencies were clean).

# Future Roadmap
    * IDE Integration: A VS Code extension that automatically runs GitGuard in the background before you open a newly cloned folder.
    * Continuous Integration: A GitHub Action to audit pull requests for malicious intent, not just syntax errors.
    * Heuristic Engine: Pre-caching common malicious behavioral patterns to reduce AI token usage and speed up scan times.

apei; lmKLM



