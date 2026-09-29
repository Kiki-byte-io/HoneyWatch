# HoneyWatch

### AI-Powered Honeypot Attack Monitoring & Security Intelligence

HoneyWatch is a controlled cybersecurity monitoring platform built
around the [Cowrie](https://github.com/cowrie/cowrie) SSH/Telnet
honeypot. It captures attacker interactions, structures honeypot
telemetry, analyzes observed behavior, generates security intelligence,
and presents the results through a Flask monitoring dashboard and
executive reporting layer.

> **Python establishes the facts. The LLM explains the facts.**

------------------------------------------------------------------------

## Architecture

``` text
Controlled Attacker
       │
       ▼
Cowrie SSH/Telnet Honeypot
       │
       ▼
Cowrie JSON Logs
       │
       ▼
Python Parser (parse_logs.py)
       │
       ▼
MySQL (cowrie_logs)
       │
       ▼
Security Intelligence
 ┌────────────────────────┐
 │ Evidence Analyzer      │
 │ Bot/Human Classifier   │
 │ AI Attack Summarizer   │
 │ Mitigation Engine      │
 └────────────┬───────────┘
              │
              ▼
          Flask API
              │
              ▼
     HoneyWatch Dashboard
              │
              ▼
      Executive PDF Report
```

------------------------------------------------------------------------

## Security Intelligence Layer

### 1. Evidence Analyzer

The Evidence Analyzer performs deterministic analysis of captured Cowrie
data.

It identifies:

-   Successful and failed authentication attempts
-   Executed commands
-   Reconnaissance activity
-   Session information
-   Command-level meanings
-   Authentication and activity patterns

The analyzer establishes verified evidence before AI-generated
interpretation.

### 2. Bot vs Human Behavioral Classifier

HoneyWatch includes an explainable heuristic classifier that produces a
**0--100 automation score** using four behavioral indicators:

  Indicator             What it examines
  --------------------- -------------------------------------
  Command Timing        Time gaps between commands
  Repeated Sequences    Repeated command patterns
  Repeated Source IPs   IP reuse across sessions
  Session Frequency     Frequency of sessions from a source

Possible assessments:

``` text
Insufficient Evidence
Possibly Automated
Likely Automated
```

The score is a behavioral indicator, not proof that a session was
automated.

### 3. AI Attack Summarizer

HoneyWatch uses a local **Llama 3.2 3B** model through **Ollama**.

``` text
MySQL
  ↓
Evidence Analyzer
  ↓
Verified Security Facts
  ↓
Llama 3.2 3B
  ↓
Natural-Language Security Summary
```

The LLM receives structured findings rather than being treated as the
source of truth for security evidence. This helps separate deterministic
analysis from language-model interpretation.

### 4. Mitigation Engine

The mitigation layer maps verified observations to defensive
recommendations, such as:

-   Reviewing SSH authentication controls
-   Monitoring reconnaissance activity
-   Monitoring access to sensitive account information
-   Reviewing rate limiting for repeated failed authentication attempts

The system provides recommendations rather than automatically blocking
attackers.

------------------------------------------------------------------------

## Example Analysis

A captured session may contain:

``` text
whoami
id
uname -a
ls -la
cat /etc/passwd
exit
```

The deterministic layer can identify these as system/account
reconnaissance activity. The verified findings are then passed to the
local LLM to generate an analyst-readable summary.

An observed command is evidence that the command was entered into the
honeypot; it is not automatically proof of successful execution,
compromise, malware execution, or real-world impact.

------------------------------------------------------------------------

## Dashboard

HoneyWatch provides views for:

-   Overview Dashboard
-   Attack Monitor
-   Sessions
-   IP Analysis
-   Command Analysis
-   Credentials
-   Timeline
-   Log Viewer
-   Executive Report
-   Settings & Architecture

The dashboard provides visibility into captured sessions, attacker IPs,
commands, behavioral analysis, AI-generated summaries, and reporting.

------------------------------------------------------------------------

## Executive Reporting

HoneyWatch includes executive PDF reporting with:

-   Date-scope filtering
-   Attack statistics
-   Visual charts
-   Security intelligence summaries
-   Report generation from analyzed honeypot data

------------------------------------------------------------------------

## Technology Stack

**Security** - Cowrie SSH/Telnet Honeypot - Kali Linux - Ubuntu Linux -
Honeypot telemetry analysis - Behavioral heuristics

**AI & Security Intelligence** - Python - Llama 3.2 3B - Ollama -
Heuristic classification - Prompt engineering - Deterministic evidence
analysis

**Backend & Data** - Flask - MySQL - REST APIs - JSON log processing

**Infrastructure** - VirtualBox - Linux - Git / GitHub

------------------------------------------------------------------------

## Key Metrics

  Component                       Implementation
  ------------------------------- -----------------------
  Security intelligence modules   **4**
  Behavioral indicators           **4**
  Automation score                **0--100**
  Local LLM                       **Llama 3.2 3B**
  LLM Runtime                     **Ollama**
  Database                        **MySQL**
  Backend                         **Flask**
  Honeypot                        **Cowrie SSH/Telnet**

------------------------------------------------------------------------

## My Contribution

HoneyWatch is a collaborative academic cybersecurity project.

My primary contribution focuses on the **Security Intelligence /
Analysis Layer**.

### Developed components

**Evidence Analyzer** - Deterministic security evidence extraction -
Authentication analysis - Reconnaissance detection - Command
interpretation

**Bot/Human Behavioral Classifier** - Explainable 0--100 automation
scoring - Four behavioral indicators - Evidence-aware classification

**AI Attack Summarizer** - Local Llama 3.2 3B deployment - Ollama-based
inference - Verified-evidence → LLM pipeline - Prompt constraints to
reduce unsupported claims

**Mitigation Engine** - Rule-based defensive recommendations -
Observation-to-mitigation mapping - No automatic blocking

### Team

-   **Khushi Kothari** --- Security Intelligence / Analysis
-   **Noel George Francis** --- Cowrie / Honeypot Infrastructure
-   **Shashank M V** --- Dashboard / Monitoring Interface

------------------------------------------------------------------------

## Design Principle

> **Python establishes the facts; the LLM explains the facts.**

Deterministic analysis is treated as the authoritative security
evidence, while the language model converts those findings into
human-readable intelligence.

------------------------------------------------------------------------

## Deployment Architecture

The deployment uses two VirtualBox VMs connected through a Host-only
network:

``` text
┌───────────────────────┐
│     Kali Linux VM     │
│   Controlled Attacker │
└──────────┬────────────┘
           │
           │ Host-only Network
           ▼
┌───────────────────────┐
│      Ubuntu VM        │
│   Cowrie Honeypot     │
└──────────┬────────────┘
           │
           ▼
      Cowrie JSON
           │
           ▼
     Python + MySQL
           │
           ▼
   Security Intelligence
           │
           ▼
      Flask Dashboard
```

The honeypot VM uses NAT for package installation/internet access and a
Host-only adapter for isolated communication with the attacker VM.

------------------------------------------------------------------------

## Cowrie Setup

### Install dependencies

``` bash
sudo apt update
sudo apt install -y git python3-venv python3-pip
```

### Install Cowrie

``` bash
git clone https://github.com/cowrie/cowrie.git
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -e .
```

For the pip-based installation, the configuration template is located
at:

``` text
src/cowrie/data/etc/cowrie.cfg.dist
```

Create a working configuration:

``` bash
cp src/cowrie/data/etc/cowrie.cfg.dist \
   src/cowrie/data/etc/cowrie.cfg
```

Start and verify Cowrie:

``` bash
cowrie start
cowrie status
sudo ss -tlnp | grep 2222
```

------------------------------------------------------------------------

## Controlled Attack Testing

From Kali, verify connectivity:

``` bash
ping <HONEYPOT_HOST_ONLY_IP>
```

Then connect to Cowrie:

``` bash
ssh -p 2222 root@<HONEYPOT_HOST_ONLY_IP>
```

Example telemetry-generating commands:

``` bash
whoami
id
uname -a
ls -la
cat /etc/passwd
ps aux
ifconfig
history
exit
```

Only perform these tests against systems you own or are explicitly
authorized to test.

------------------------------------------------------------------------

## Log Collection

Cowrie generates structured events such as:

``` text
cowrie.session.connect
cowrie.login.success
cowrie.login.failed
cowrie.command.input
cowrie.session.closed
```

Example:

``` bash
tail -50 var/log/cowrie/cowrie.json
```

Raw session logs are not tracked in Git because generated telemetry can
contain IP addresses and other runtime data.

------------------------------------------------------------------------

## Database

HoneyWatch uses MySQL to store structured honeypot telemetry,
separating:

-   Session metadata
-   Authentication attempts
-   Command events

This allows the intelligence modules to query structured evidence
instead of repeatedly parsing raw JSON.

------------------------------------------------------------------------

## Environment Variables

Database credentials should be supplied through environment variables.

### Linux

``` bash
export COWRIE_DB_PASSWORD="your-password"
```

### Windows PowerShell

``` powershell
$env:COWRIE_DB_PASSWORD="your-password"
```

Never commit passwords, API keys, access tokens, `.env` files, or
sensitive logs.

------------------------------------------------------------------------

## Running HoneyWatch

After configuring the database and required services:

``` bash
python3 dashboard/app.py
```

Open:

``` text
http://127.0.0.1:5000/
```

------------------------------------------------------------------------

## Project Structure

``` text
HoneyWatch/
├── dashboard/
│   ├── app.py
│   └── templates/
├── ai_mitigation.py
├── ai_summarizer.py
├── bot_human_classifier.py
├── evidence_analyzer.py
├── parse_logs.py
├── database_test.py
├── db_client.py
├── log_watcher.py
├── report_generator.py
├── seed_vm_logs.py
├── test_app.py
├── cowrie.cfg
├── .gitignore
└── README.md
```

------------------------------------------------------------------------

## Limitations

-   Cowrie operates as a low-interaction honeypot environment.
-   Behavioral classification is heuristic and cannot definitively prove
    whether activity was automated.
-   Local language models can still produce incorrect interpretations.
-   The demonstrated deployment is a controlled laboratory environment.
-   An observed command does not by itself prove successful execution,
    compromise, malware execution, or real-world impact.

------------------------------------------------------------------------

## Security & Ethics

HoneyWatch is intended for controlled cybersecurity research, education,
and defensive monitoring.

Attack simulations should only be performed against systems that you own
or have explicit authorization to test.

The project is not intended to replace production-grade firewalls,
IDS/IPS, SIEM platforms, endpoint protection, or other security
controls.

------------------------------------------------------------------------

## Project Status

**Academic Cybersecurity Project --- Active Development**

HoneyWatch combines honeypot telemetry collection, deterministic
security analysis, behavioral heuristics, local LLM-based summarization,
defensive recommendations, dashboard monitoring, and executive reporting
into a single controlled security-monitoring workflow.
