import os

content_to_append = '''

## 7.6 Cryptographic Receipts, Hash Chains, and Tamper-Evident Forensics

### 7.6.1 Containment Action Receipt Cryptographic Lifecycle
In high-consequence enterprise and industrial networks, automated containment actions (e.g., process suspension, network port isolation) represent severe interventions. If an autonomous system mistakenly isolates a critical supervisory server, the incident response team must be able to verify the authenticity of the containment order and execute an immediate, verified rollback without manual firewall reconfiguration.

CyberGuard addresses this operational requirement through a cryptographic receipt mechanism implemented in `backend/actuators/process_actuator.py` and `backend/actuators/network_actuator.py` `[CE-15], [CE-41]`. Whenever an active defense actuation is executed, the actuator issues an authenticated rollback receipt token:

Let an actuation event be defined by the tuple $\mathcal{A} = (\tau, \alpha, \theta, t_0, \Delta t_{\text{valid}}, \text{op}_1, \text{op}_2, \text{id}_{\text{act}})$, where $\tau$ is the actuator type, $\alpha$ is the action verb, $\theta$ is the target identifier (PID or IP:port), $t_0$ is the execution epoch, $\Delta t_{\text{valid}}$ is the validity duration (defaulting to 3,600 seconds), $\text{op}_1, \text{op}_2$ are the dual-authorizing operator credentials, and $\text{id}_{\text{act}}$ is a cryptographically random UUID4 nonce.

The actuator serializes $\mathcal{A}$ into canonical JSON representation $M_{\text{act}} = \text{JSON}_{\text{canon}}(\mathcal{A})$ and computes a Keyed-Hash Message Authentication Code (HMAC) using the machine-local master secret $K_{\text{receipt}}$:

$$R_{\text{act}} = \text{HMAC-SHA256}(K_{\text{receipt}}, M_{\text{act}}) \tag{7.1}$$

The resulting token $\mathcal{T}_{\text{rollback}} = (\text{id}_{\text{act}}, M_{\text{act}}, R_{\text{act}})$ is returned to the calling client and committed to the SQLite persistence store. When an operator requests a rollback via `POST /api/actuators/rollback`, the system validates three cryptographic invariants before reversing the intervention:
1. **Integrity and Authenticity Verification:** The engine recomputes $\text{HMAC-SHA256}(K_{\text{receipt}}, M_{\text{act}}')$ and asserts equality with $R_{\text{act}}$ using constant-time comparison (`hmac.compare_digest`) to prevent timing side-channel attacks.
2. **Temporal Validity Bounds:** The rollback engine verifies that the current epoch $t_{\text{current}} \le t_0 + \Delta t_{\text{valid}}$. Expired receipts are rejected, preventing adversaries from executing delayed rollback attacks to reopen compromised ports after an incident has been remediated.
3. **Replay Invalidation:** Once a receipt $\text{id}_{\text{act}}$ is successfully redeemed for rollback, its identifier is committed to a spent-receipt registry. Subsequent attempts to present the same receipt are rejected with `HTTP 409 Conflict`.

### 7.6.2 Forensic Audit Trail Immutability Analysis
As established in Section 4.18.3, administrative operations and autonomous decisions are committed to an append-only hash chain in table `audit_events` `[CE-38]`. To formally evaluate the tamper-resistance of this ledger, we analyze three adversary models:

1. **Adversary $\mathcal{A}_1$ (Historical Record Modification):** Suppose an insider attempts to alter an old audit entry $E_k$ ($k < N$) to conceal an unauthorized process termination. Because $h_k = \mathcal{H}_{\text{SHA-256}}(m_k)$, altering any attribute in $m_k$ changes $h_k$ with probability $1 - 2^{-256}$ due to the collision resistance of SHA-256. Furthermore, because event $E_{k+1}$ stores $h_k$ as its `previous_hash`, the discrepancy cascades through all subsequent events $E_{k+1}, \dots, E_N$. Unless the adversary recalculates SHA-256 digests for all $N - k$ subsequent records in the database, `verify_audit_chain()` immediately flags the modification.
2. **Adversary $\mathcal{A}_2$ (Intermediate Record Deletion):** If an adversary deletes row $E_k$ entirely, the chain breaks at row $E_{k+1}$, because $E_{k+1}.\text{previous_hash} = h_k \neq h_{k-1} = E_{k-1}.\text{event_hash}$. The verification harness detects the missing link and rejects the ledger.
3. **Adversary $\mathcal{A}_3$ (Database Truncation):** If an adversary drops the final $m$ records ($E_{N-m+1}, \dots, E_N$), the remaining prefix $E_1, \dots, E_{N-m}$ remains internally consistent. To mitigate prefix truncation attacks, CyberGuard supports external periodic anchoring: the latest digest $h_N$ is exported to an external write-once-read-many (WORM) syslog server or remote SIEM with RFC 3161 trusted timestamps.

## 7.7 Least Privilege, OS Sandboxing, and Linux Capability Minimization

### 7.7.1 Threat of Monolithic Root Execution
A fundamental architectural tension in Network Intrusion Detection and Containment Systems is the requirement for elevated operating system privileges. CyberGuard requires elevated privileges for three distinct operations:
- Opening raw promiscuous network sockets (`AF_PACKET` on Linux, `SOCK_RAW` on Windows) to sniff link-layer frames `[CE-04]`.
- Manipulating host firewall rules (invoking `iptables` or `powershell.exe Netsh`) `[CE-16]`.
- Suspending or terminating compromised operating system processes (`os.kill`, `taskkill.exe`) `[CE-15]`.

In the default deployment topology (`run.bat` or `main.py`), CyberGuard executes as a single monolithic process running under root (Linux) or Administrator (Windows) privileges. This design violates the **Principle of Least Privilege** {{cite:saltzer1975protection}}. A vulnerability in any parsing component—such as an out-of-bounds read in the flow assembly engine (`tailer.py`) or an unauthenticated command injection in the REST API (`auth.py`)—yields arbitrary code execution with full administrative access over the host operating system.

### 7.7.2 Linux Capability Decomposition Architecture
To achieve defense-in-depth, CyberGuard's runtime architecture can be decoupled into isolated privilege domains using POSIX Linux Capabilities (`libcap`) and namespace isolation {{cite:torvalds2023linux}}:

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XVI-B.</b> PRIVILEGE DECOMPOSITION ACROSS CYBERGUARD SUBSYSTEMS
</div>

| Subsystem Component | Process Identity | Required Linux Capabilities | Dropped Capabilities | Sandboxing Mechanism |
|:---|:---|:---|:---|:---|
| **Live Sniffer Engine** (`live_sniffer.py`) | `cyberguard-sniffer` (UID 1001) | `CAP_NET_RAW` (packet capture)<br>`CAP_NET_ADMIN` (promiscuous mode) | All others (`CAP_SYS_ADMIN`, `CAP_KILL`, `CAP_SETUID`, etc.) | Seccomp-BPF network filter; chroot to empty directory; no filesystem write access |
| **Inference Pipeline** (`pipeline.py`) | `cyberguard-worker` (UID 1002) | None (`CAP_NONE`) | All capabilities dropped | Unprivileged worker; no raw socket access; read-only access to `data/models/` |
| **REST API & Telemetry Gateway** (`main.py`) | `cyberguard-api` (UID 1003) | `CAP_NET_BIND_SERVICE` (bind port 8000) | All system administration capabilities dropped | Restricted SQLite access; non-root unprivileged daemon |
| **Active Containment Actuator** (`actuators/`) | `cyberguard-actuator` (UID 1004) | `CAP_NET_ADMIN` (firewall rules)<br>`CAP_KILL` (signal dispatch) | All others dropped | IPC over authenticated Unix Domain Socket with mutual TLS; strict target validation |

### 7.7.3 Hardened Systemd Service Profile
In an enterprise Linux deployment, CyberGuard's execution boundaries should be enforced via systemd security profiles. Listing 7.1 details the recommended sandboxing configuration for the CyberGuard API and Inference service:

```ini
# Listing 7.1: Production Systemd Sandboxing Unit (cyberguard-api.service)
[Unit]
Description=CyberGuard Real-Time Intrusion Detection Engine
After=network.target remote-fs.target
Wants=network-online.target

[Service]
Type=exec
User=cyberguard
Group=cyberguard
WorkingDirectory=/opt/cyberguard
ExecStart=/opt/cyberguard/venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000

# Linux Capability Minimization
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

# Filesystem Sandboxing
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
PrivateTmp=true
ReadWritePaths=/opt/cyberguard/data /opt/cyberguard/logs

# Network and IPC Isolation
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service @network-io
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
```

Enforcing `NoNewPrivileges=true` prevents setuid binaries from escalating privileges, while `MemoryDenyWriteExecute=true` prevents exploitation techniques involving dynamic shellcode execution (W^X memory protection).

## 7.8 Formal Verification Limits and Neuro-Symbolic Safety Gate Deficiencies

### 7.8.1 Propositional Satisfiability vs. Satisfiability Modulo Theories (SMT)
The project documentation and marketing materials assert that CyberGuard incorporates "SMT-based formal verification" to mathematically guarantee that autonomous response actions cannot disrupt critical operational infrastructure `[CE-18]`. Our source code audit of `backend/safety/formal_verifier.py` establishes that this claim is technically inaccurate and conflates **Propositional Boolean Satisfiability (SAT)** with **Satisfiability Modulo Theories (SMT)**:

```python
# File: backend/safety/formal_verifier.py:28-48
from sympy import symbols
from sympy.logic.inference import satisfiable

# Invariants are encoded strictly over 4 boolean propositions
allow_high_risk, manual_override, quarantine, unverified = symbols(
    "allow_high_risk manual_override quarantine unverified"
)

# SymPy propositional satisfiability check
is_safe = satisfiable(safety_formula)
```

As demonstrated in the source listing, the safety invariants are evaluated using SymPy's `satisfiable()` routine over four boolean variables:
- `allow_high_risk` ($b_1$)
- `manual_override` ($b_2$)
- `quarantine_requested` ($b_3$)
- `unverified_anomaly` ($b_4$)

True Satisfiability Modulo Theories (SMT) solvers—such as Z3 {{cite:de2008z3}}, CVC5, or Yices—extend propositional logic by evaluating formulas with respect to background theories expressed in first-order logic, including:
- **Quantifier-Free Linear Integer Arithmetic (QF_LIA):** Evaluating inequality constraints over continuous flow metrics (e.g., asserting that packet rate $\lambda_{\text{pkt}} > 10,000 \implies \text{rate\_limit} \le 100$).
- **Quantifier-Free Bit-Vectors (QF_BV):** Evaluating subnet mask containment and CIDR bitwise operations (e.g., verifying that target IP $\text{IP}_{\text{dst}} \ \& \ \text{Mask}_{\text{crit}} \neq \text{Subnet}_{\text{crit}}$).
- **Theory of Arrays / Uninterpreted Functions:** Evaluating routing tables and network reachability state machines.

In CyberGuard, no background theories are defined. The four boolean variables have only $2^4 = 16$ possible truth assignments. A simple 16-row truth table or a 4-line `if/else` propositional check evaluates the exact same logic in under 5 microseconds, rendering the overhead of symbolic AST parsing in SymPy unnecessary.

### 7.8.2 Inert SMT-LIB2 Export Analysis
To provide apparent SMT integration, `formal_verifier.py:45-52` includes a helper function `to_smtlib2()` that formats an SMT-LIB2 dialect script string `[CE-42]`:

```python
# File: backend/safety/formal_verifier.py:45-52
def export_smtlib2(self) -> str:
    \"\"\"Export invariants as standard SMT-LIB2 format.\"\"\"
    return f\"\"\"(set-logic QF_UF)
(declare-const allow_high_risk Bool)
(declare-const manual_override Bool)
(declare-const quarantine Bool)
(declare-const unverified Bool)
(assert (=> (and quarantine unverified (not manual_override)) false))
(check-sat)
(exit)\"\"\"
```

Our empirical analysis confirms:
1. **Zero External Solver Invocations:** The exported SMT-LIB2 text is never piped to an external SMT solver process (such as `z3 -in` or `cvc5`). The string is merely stored in memory or logged to diagnostic endpoints.
2. **Logic Mismatch:** The header specifies `QF_UF` (Quantifier-Free Uninterpreted Functions), but the asserted formula contains only propositional boolean variables and standard logical connectives (`and`, `not`, `=>`), which belongs to the simpler logic `QF_BOOL`.
3. **Absence of Proof Certificates:** Because no SMT solver is executed, the system produces no mathematical unsatisfiability proofs (UNSAT cores) or proof certificates that could be archived in the audit ledger for compliance verification.
'''

with open('report/chapters/07-security-and-safety-analysis.md', 'r', encoding='utf-8') as f:
    text = f.read()

if '## 7.6 Cryptographic Receipts' not in text:
    with open('report/chapters/07-security-and-safety-analysis.md', 'a', encoding='utf-8') as f:
        f.write(content_to_append)
    print('Successfully appended Sections 7.6, 7.7, and 7.8 to 07-security-and-safety-analysis.md')
else:
    print('Sections already present.')
