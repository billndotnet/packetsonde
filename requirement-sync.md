# Packetsonde Framework: Requirements Document

## Executive Summary

Packetsonde is a lightweight, distributed network visibility and anomaly detection framework designed to provide real-time insight into network behavior across Linux, FreeBSD, and OpenBSD hosts. The framework operates as a client-centric system that maps network topology and behavioral baselines, flags deviations, and surfaces anomalies through a 3D visualization client. The primary goal is to enable security teams and operators to understand "what's supposed to be here" and immediately identify "what's not."

Core design principle: **Stay lightweight and unobtrusive.** The agent must remain negligible in CPU/memory impact on production systems, even during baseline learning phases.

---

## Agent Architecture

### 1. Deployment & Scope

**Deployment:**
- Lightweight, single-binary agent deployable on production hosts
- Runs in promiscuous mode (where network topology permits)
- Operates passively: observation and reporting only, no blocking/remediation
- Multi-platform support: Linux (primary), FreeBSD, OpenBSD

**Responsibility:**
- Network flow accounting and summarization (non-DPI)
- File system access monitoring (inotify on Linux, sampled `/proc` on BSD variants)
- Process-level baseline learning and anomaly detection
- Request forwarding to peer agents (via existing network paths)
- Local data aggregation and anomaly scoring

---

## Data Collection Mechanisms

### 2. Flow Accounting

**Collection:**
- Passive observation of network traffic without deep packet inspection
- Generation of flow tuples: (source IP, dest IP, source port, dest port, protocol, bytes transferred, timestamp)
- Summarization strategies configurable per host:
  - Full granularity for management traffic (SSH, SNMP, DNS)
  - Aggregated summaries for high-volume traffic (bulk data transfer)
  - Time-windowed aggregation on busy hosts (e.g., "CDN edge pushing 500TB/day on ports 80/443")

**On High-Traffic Hosts:**
- Summarize bulk flows by range rather than individual connections
- Keep granular records for anomalous or low-frequency connections
- Discard complete flow records after summarization; retain summary statistics for longer periods

---

### 3. File System Access Monitoring

**Linux (via inotify):**
- Event-driven monitoring of watched directories (configurable per host role)
- Typical watch paths: `/home`, `/var/cache`, sensitive config directories, user data paths
- Correlate file access events with simultaneous network socket activity (within ~100ms window)
- Flag: "process X read from path Y and opened socket to IP Z in same window"

**FreeBSD/OpenBSD (platform-specific constraints):**
- FreeBSD: dtrace when available; fallback to sampled `/dev/fd` inspection
- OpenBSD: sampled `/proc` inspection with aggressive filtering to minimize overhead
- Coarser granularity acceptable on these platforms; agent documents capability limitations

**Correlation Logic:**
- Tie file access events to process context (PID, user, parent process)
- Cross-reference with concurrent socket activity
- Summarize correlated pairs: "nginx (UID www) read /var/cache/user_data, connected to 203.0.113.50:443"
- Report anomalies where process accesses paths outside its baseline envelope

---

### 4. Process-Level Baselines & Anomaly Detection

**Baseline Learning:**
- Agent learns per-process behavioral envelope during initial deployment phase
- Captures: allowed file paths (read/write), allowed network destinations (IP ranges/ports), typical data volumes, connection timing patterns
- Learning modes:
  - **Bootstrapped:** Admin provides initial config stating expectations (e.g., "nginx serves ports 80/443 to any external, SSH from these 2 bastion IPs")
  - **Passive learning:** "Learn all activity for 7 days, I'll curate"
  - **Hybrid:** Initial bootstrap + dynamic learning with human approval loop

**Anomaly Detection:**
- Flag deviations from learned envelope (path access outside allowlist, outbound to unexpected destination, unexpected process spawning)
- Detection types:
  - Path traversal exploitation (process reading unauthorized files)
  - Lateral movement (SSH from unexpected source)
  - Data exfiltration (file read + immediate socket open to unknown destination)
  - Anomalous process behavior (unexpected outbound, unexpected internal process generation)

**Scoring & Reporting:**
- Agent computes anomaly flags locally with full context
- Reports flagged events upstream with:
  - Process details (PID, user, command line, parent process)
  - Access details (file path, network destination, timestamp, correlation confidence)
  - Deviation from baseline (what was expected vs. what occurred)
  - No blocking; detection and reporting only

---

### 4a. NTP Monitoring (Passive)

**NTP Traffic Analysis:**
- Agent monitors NTP traffic passively (unencrypted, observable in flight)
- Extracts clock offset information from NTP response packets
- Correlates across multiple NTP exchanges to detect drift patterns

**Anomaly Detection:**
- Flag: "Host sent NTP request, received correction, but reported offset persists in subsequent requests"
  - Indicates: compromised host deliberately rejecting NTP corrections, or NTP MITM'd
- Flag: "Host sends NTP requests but receives no responses"
  - Indicates: NTP blocked, spoofed, or misconfigured
- Flag: "NTP clock offset should be corrected but agent analysis shows offset unchanged"
  - Indicates: host clock being held at wrong offset by malware or attacker

**Reporting:**
- Clock drift anomalies reported as potential indicators of compromise
- NTP correction failures flagged at management layer (not host layer)
- Used in conjunction with request timestamp validation for replay attack detection

---

## Machine Learning & Envelope Management

### 5. ML Strategy (Multi-Layered)

**Agent-Level ML (Local):**
- Built-in, compiled anomaly detection logic; not exposed to attackers
- Process baselines learned from observed behavior
- Envelope parameters (allowed paths, allowed destinations) stored locally in agent memory
- Config flags enable/disable ML components; don't encode the algorithms themselves

**User/Account-Level ML (Central Aggregation):**
- Built from auth logs + flow/access summaries reported by agents
- Learns typical behavior per user: "Alice typically SSHes to these 5 hosts, from these IPs, at these times"
- Flags cross-host anomalies (user accessing unexpected host, access from unexpected source IP)
- Requires central aggregation; agents cannot perform this analysis in isolation

**Network Segmentation Constraints:**
- Assume agents *cannot* directly communicate with each other (no mesh)
- Agent-to-agent forwarding is optional optimization; not required for core functionality
- All correlation that requires data from multiple hosts happens centrally

---

## Configuration Management

### 6. Agent Configuration & Security

**Bootstrap Configuration (Minimal Plaintext):**
- Minimal hardcoded defaults stored in plaintext: TLS cert pinning/CA cert, central management URL, agent identifier (hostname or UUID)
- Agent identifier used to register with central and fetch encrypted configuration
- Only information necessary to bootstrap decryption process stored in plaintext

**Agent Key Generation & Registration:**
- Agent generates its own public/private keypair on first run (or pre-provisioned)
- Public key registered with central management out-of-band:
  - Config management system (SALT, CF Engine) captures generated public key at deployment time
  - Also captures binary checksum (SHA256 of deployed agent binary)
  - Reports both to central management for manual validation by deploying engineer
  - Engineer validates reported values match expected deployment before finalizing registration
- Private key stored securely locally (encrypted at rest, kept in memory during runtime)

**Configuration Encryption:**
- Main agent configuration encrypted at rest using agent's public key
- Only that agent can decrypt using its private key (private key never leaves agent, never transmitted)
- Central management holds encrypted configs; cannot decrypt them
- If central is compromised, configs remain encrypted and unusable to attacker

**Configuration Content (Examples):**
- "Interface eth0 will serve bulk traffic on ports 80/443; flag anything else as anomalous"
- "Process sshd allowed to read /home/*, /etc/ssh; flag reads outside this envelope"
- "Expected outbound: only to internal IPs 10.0.0.0/8 on ports 22, 25, 53; flag others"
- "Learn baseline for 7 days; report all deviations; await human approval"
- Authorized keys mapping: `key_id -> role -> capabilities + network restrictions`
- Trusted payload signing keys

**Configuration Updates & Rotation:**
- Central node pushes config changes (push mechanism, not polling)
- Agent receives config over TLS, decrypts with private key, validates, reloads (no restart required where possible)
- Version control: all configs stored in central Git repository with diffs and audit trail
- Updates delivered via: direct central push (TLS authenticated) OR config management system (SALT, CF Engine, etc.) per deployment model

**Automatic Key Rotation:**
- Central initiates key rotation on configurable schedule (daily, weekly, monthly per environment)
- Rotation only proceeds if agent's binary checksum matches originally registered checksum
- Binary mismatch blocks rotation and flags host as potentially compromised
- New keypair encrypted with current public key, sent over TLS to agent
- Agent stores new keypair for use in subsequent reconfigurations
- Agent updates registration with central with new public key

**Config Update Loop:**
1. Agent reports anomaly with full context
2. Out-of-band logging (signed events) or TLS to central for sensitive data
3. Central aggregation indexes and surfaces anomaly for human review
4. Human reviews: "Is this normal? Bad? Ignore?"
5. Decision folded into config (add to whitelist, tighten envelope, suppress future reports)
6. Deploying engineer updates config in central Git repository
7. Updated config encrypted with agent's registered public key
8. Central pushes encrypted config to agent
9. Agent decrypts (using private key), validates schema, reloads
10. Agent updates local baselines and stops flagging that pattern (or escalates if marked "bad")

---

## Port Knocking & Network Stealth

### 6a. Cryptographic Port Knocking

**Service Port Access:**
- Agent service port remains closed by default (not listening)
- Port scans see no open ports; agent is invisible to network reconnaissance
- Agent only opens service port after validating cryptographic knock packet

**Knock Protocol:**
- Client sends knock packet containing: user key signature, timestamp (respects 2-second expiration), target request ID or payload hash
- Signature must be valid and match authorized key in agent config
- Agent validates knock signature before opening port
- Invalid knock attempts logged as potential reconnaissance
- If valid: agent opens service port for configurable timeout (e.g., 30 seconds)
- If invalid: no response sent (silent rejection, stealth)

**Benefits:**
- Agent invisible to passive/active network scanning
- DoS harder (no open port to target)
- Failed knock attempts indicate reconnaissance attempt
- Minimal overhead (knock validation is cryptographically cheap)

---

## Deployment Modes

### 6b. Agent Deployment Configurations

**Standard Host Agent:**
- Deployed on production/lab hosts
- Runs in promiscuous mode (where permitted)
- Monitors flows, process baselines, file access
- Full anomaly detection and reporting

**Auditor Proxy Mode (Isolated Device):**
- Deployed on small isolated device (Raspberry Pi, small Linux box)
- Placed on auditor-controlled VLAN
- Auditor's laptop connects to proxy device (never directly to target network)
- Proxy forwards all requests through to target network agents
- Target network sees requests originating from proxy device, not auditor's laptop
- Use case: compliance audits, vulnerability scanning without fingerprinting analyst workstation

**Trunk-Based Multi-VLAN Agent:**
- Deployed on small server with access to 802.1Q trunk port
- Dynamically brings up vlan interfaces for each VLAN to monitor
- Two operational modes:

  **Active Mode:** Actively probes/scans each VLAN
  - Runs scheduled audit payloads across all accessible VLANs
  - Good for: security assessments, periodic network audits
  
  **Passive/Honeypot Mode:** Listens to broadcast and multicast traffic
  - Monitors for unauthorized scanning (port scans, service discovery)
  - Flags unexpected probes from unexpected sources
  - Good for: detecting unauthorized network reconnaissance

**Transparent Bridge Mode (Handheld Device):**
- Deployed on handheld Linux PC with dual Gigabit Ethernet + battery + WiFi
- Sits transparently between two network segments as L2 bridge
- Sees all traffic flowing through bridge (pure passive observation)
- Generates flow accounting from bridged traffic
- WiFi backhaul connects to analyst laptop
- Use case: segment analysis in production networks, passive monitoring without modifying traffic

**Configuration:**
All modes use same binary; deployment mode configured via flags or bootstrap config. Network topology and capability requirements determine which mode is appropriate per deployment.

---

## Inter-Agent Communication

### 7. Agent Forwarding & Query Chains

**Architecture:**
- Agent queries can be forwarded through existing network paths (no new mesh)
- Forwarding respects network topology: bastion can reach edge networks → bastion agent can proxy queries to edge agents
- Client makes request to local/reachable agent; that agent forwards through bastion if needed to reach target agent
- Each hop is authenticated via TLS with certificate-based or key-based auth

**Use Cases:**
- Central operator at home (VPN → bastion → edge) can query edge agents through bastion
- Bastion agent can forward queries to multiple edge agents in sequence
- Forensics: "Show me all flows for user X across all hosts they touched" (bastion gathers from all reachable agents)

**Forward Authorization:**
- Agent accepts forwarded requests only from authenticated peers
- Central config specifies which agents can forward to which other agents
- Forwarding creates a directed graph of trust; no loops unless explicitly created by user (user error is user's problem)

**Probe Logic Location:**
- Agent does NOT store probe recipes or detection logic
- All probe logic lives on client (analyst's machine)
- Client sends full recipe to agent: "Here's what to check, here's how to validate the response"
- Agent executes recipe, returns raw data
- If agent is compromised, attacker sees only request formats, not reconnaissance intent

### 7a. Payload Management & Cryptographic Control

**Payload Repository (Central):**
- All probes/payloads stored in central, version-controlled repository
- Payloads are templates/recipes for queries (Elasticsearch scan, DNS enumeration, flow analysis, etc.)
- Each payload includes: name, description, parameters, validation rules, execution class, required permissions
- Examples:
  - "Scan Elasticsearch cluster for field count" (READ_ONLY payload)
  - "Pull DNS query logs from last 24 hours" (READ_ONLY payload)
  - "Profile process baseline on host X" (READ_ONLY payload)
  - "Enumerate SSH keys on host" (STATE_MODIFY payload)

**Execution Classes:**
- **READ_ONLY:** Network inspection, flow queries, baseline reads, process table inspection, filesystem inspection. No state modification.
- **STATE_MODIFY:** Code execution, process forking/stopping, filesystem writes, any operation that modifies system state.

**Payload Signing:**
- Central repository signs payloads with a private key (organization controls key)
- Signature embedded in payload metadata
- Multiple signing keys possible (different teams, different permission levels)
- Payload versioning: each iteration gets new signature

**Dual-Signature Enforcement:**
- READ_ONLY payloads: require single signature (user's authorization)
- STATE_MODIFY payloads: require dual signatures (central authority + user authorization)
- Central signature proves: "This payload is approved and safe"
- User signature proves: "I (authorized user) am requesting this execution on this target"
- Agent validates both signatures before executing STATE_MODIFY payload; rejects if either signature invalid

**Agent-Side Verification:**
- Agent config includes trusted signing key(s)
- Agent accepts and executes only payloads with valid signature(s) from trusted key(s)
- Agent rejects unsigned, mis-signed, or improperly-signed payloads
- Execution log: which payload, which user, which signature key(s) used, timestamp, result

**User Request Flow (READ_ONLY):**
1. User (via CLI or 3D client) requests execution of payload "Scan-ES-Cluster-v2" (READ_ONLY)
2. Client retrieves payload from central repo (already signed by central authority)
3. Client signs request with user's private key (user authorization)
4. Client sends: (payload + central signature) + (user signature)
5. Agent verifies central signature (payload is approved)
6. Agent verifies user signature (user is authorized)
7. Agent checks RBAC (user's role permits this payload on this network segment)
8. Agent executes payload, logs the action
9. Returns raw data to client

**User Request Flow (STATE_MODIFY):**
1. User requests execution of payload "Extract-SSH-Keys" (STATE_MODIFY)
2. Client retrieves payload from central repo (already signed by central authority)
3. Client signs request with user's private key
4. Client sends: (payload + central signature) + (user signature)
5. Agent verifies central signature (payload approved for state-modify operations)
6. Agent verifies user signature (user is authorized)
7. Agent checks RBAC + approval tier if configured
8. Only if all checks pass: agent executes, logs with both signatures
9. Returns raw data to client

---

### 7a-b. Signed Discovery Protocol

**Cold-Drop Network Discovery:**
- Analyst drops into unknown network, needs to find available agents
- Client sends signed broadcast/multicast discovery packet: "Here I am, validate my signature"
- Packet contains: user public key signature, timestamp (respects 2-second expiration)
- All agents on network that recognize the signing key validate the signature

**Discovery Response (Capability Matrix):**
- Agent responds only if signature is valid and from authorized user
- Response includes capability matrix filtered by user's signing key/role:
  - Agent location/endpoint (IP:port or hostname)
  - Deployment mode (host, proxy, bridge, multi-VLAN)
  - Available payloads/capabilities for this user
  - Network restrictions (which segments this user can access on this agent)
- Different users get different capability lists based on their role

**Example Discovery Response:**

Auditor (limited role):
```
Agent: edge-01.prod
Mode: host
Role: auditor
Capabilities: [read-flows, read-baselines, process-inspection]
Networks: [edge, non-critical]
```

Security Admin (broader access):
```
Agent: edge-01.prod
Mode: host
Role: sysadmin
Capabilities: [all-read, forensic-analysis, config-update, state-modify]
Networks: [all]
```

**Implementation:**
- Agent config maps each authorized signing key to a role with capability set + network restrictions
- Discovery validates signature, looks up role, returns filtered capabilities
- Client immediately knows "what can I do on this agent with my current credentials?"
- Invalid signature: no response sent (silent rejection, stealth)

### 7b. Role-Based Access Control (RBAC) for Payloads

**Permission Model:**
- Each payload has required permissions: `monitor:read-flows`, `analyze:process-baseline`, `forensics:ssh-keys`, etc.
- Each user has assigned role(s): `auditor`, `sysadmin`, `security-analyst`, `network-operator`, `forensic-analyst`
- Each role has granted permission set
- Network segments can be restricted: "Only sysadmin can run payloads on core network; auditor can run on edge only"

**Example RBAC Matrix:**

| Role | Payloads Allowed | Network Segments | Justification |
|------|------------------|------------------|---------------|
| Network Operator | Read flows, baseline queries | All segments | Monitoring duties |
| Systems Admin | All read payloads + config changes | Core + assigned clusters | Operational needs |
| Security Analyst | All forensic payloads | All segments | Incident investigation |
| Auditor | Read-only payloads (flows, baselines) | Restricted segments only | Audit access control |
| Forensic Analyst | All forensic payloads + deep inspection | Post-incident hosts only | Forensics post-compromise |

**Authorization Enforcement:**
- User requests payload execution on network segment
- Client/Agent checks: Does this user's role have permission for this payload on this segment?
- If no: request rejected (with audit log of attempted unauthorized action)
- If yes: execute and log

**Payload Restrictions (Encoded in Payload Metadata):**
```
payload: "Enumerate-SSH-Keys"
required_role: ["forensic_analyst", "security_lead"]
allowed_networks: ["incident_response_segment"]
frequency_limit: "once per hour per host"
approval_required: true  # Additional human approval needed before execution
```

### 7c. Audit Trail & Accounting

**Logged on Each Payload Execution:**
- User identity (who initiated)
- Payload name + version + signature key used
- Target host(s) / network segment
- Timestamp
- Result (success/failure/rejected)
- Why rejected (if applicable: "User lacks permission", "Payload signature invalid", etc.)
- User's role at time of request
- User's authorization token

**Central Audit Log:**
- All payload requests (approved and rejected) centralized
- Queryable by: user, payload, time window, network segment, result
- Immutable (append-only, no deletion)
- Retention: indefinite (compliance/forensics)

**Compliance Reporting:**
- "Which users accessed SSH keys on production in the last 30 days?"
- "Has anyone run the Elasticsearch scanner on core?"
- "Are there any rejected payload requests?"
- "Who has approval to run forensic payloads?"

### 7d. Approval Workflow (Optional)

**High-Risk Payloads:**
- Certain payloads flagged as high-risk (forensic key extraction, data exfiltration detection, etc.)
- Require additional approval step before execution
- Approval can be: manager sign-off, ticket in ITSM, email confirmation, etc.

**Workflow Example:**
1. Analyst requests "Extract-SSH-Keys" on core host
2. Agent/Client identifies payload as `approval_required: true`
3. Client prompts for approval ticket/reason
4. Request goes to approval queue (could be human or automated)
5. Approver reviews: is this analyst authorized? Is there a legitimate reason (incident ticket, audit, etc.)?
6. If approved: payload executes with approval metadata in audit log
7. If rejected: logged as denied attempt

### 7e. Payload Lifecycle

**Creation:**
- Team creates probe/payload (security, ops, audit, etc.)
- Submits to central repository with metadata (permissions, description, version)
- Gets reviewed by authorized approver
- If approved: signed with central key, made available

**Distribution:**
- Users fetch payloads from central repo on demand
- Repo versioning allows rollback (if payload is buggy or dangerous)
- Deprecation: old payloads can be marked deprecated (still runnable if role allows, but warnings issued)

**Execution:**
- User/client executes payload (requires signature + user auth)
- Agent verifies, logs, executes

**Retirement:**
- Payload can be revoked (no longer signed)
- Agents reject unsigned versions
- Audit log shows which users were affected (last execution dates)

---

## Data Reporting & Retention

### 8. Reporting Streams

**Reporting Architecture:**

**Standard Event Reporting (Out-of-Band Signed Logging):**
- Agents send signed events via side channel (not syslog)
- Event format: (event data + agent signature)
- Signature includes: agent identity, timestamp, event content
- Central can verify: came from agent X, not forged or modified
- Transport: can use syslog as transport layer, but signature proves origin/integrity
- Examples: baseline changes, config updates, normal operational events

**Sensitive Data Reporting (TLS to Central):**
- Forensics data, anomaly flags, and sensitive operational data sent over authenticated TLS to central management
- Direct connection from agent to central (not through syslog aggregator)
- Payload signed by agent for additional authentication
- Examples: intrusion detection flags, potential compromise indicators, forensic findings
- Caching strategy varies by deployment model:
  - Online networks: stream immediately to central
  - Offline/latent networks: cache locally in encrypted form, send when central becomes reachable
  - Network-partitioned environments: buffer with TTL, periodic retry

**Transport Flexibility:**
- Deployment model determines optimal reporting path
- Some networks may use centralized syslog for audit trails but TLS for security findings
- Some may use hybrid approach: non-sensitive data via syslog, sensitive data via direct TLS

**Data Reported Upward:**
- Anomaly flags with full context (process, file access, network activity, correlation)
- Flow summaries (aggregated traffic by route/port/protocol)
- Baseline snapshots (periodic export of learned envelopes)
- Health/status (agent uptime, learning phase progress, config version, key rotation status)
- NTP monitoring data (clock offset, correction application, drift detected)
- Failed knock attempts (unauthorized access attempts via port knocking)
- Payload execution logs (what payloads, by which users, success/failure, both signatures validated)

---

## Central Aggregation Layer

### 9. Aggregation & Correlation

**Responsibilities:**
- Collect anomaly flags and summaries from all agents
- Build user-level behavioral baselines (across multiple hosts)
- Correlate session chains: "User A → Bastion → Host B → Host C"
- Detect cross-host anomalies (user accessing unexpected host, lateral movement)
- Generate business process maps (service dependencies, traffic flows)
- Surface findings for human review and policy decision-making

**Session Chain Reconstruction:**
- Bastion agent: captures inbound (VPN user → bastion) + outbound (bastion → internal hosts) with process correlation
- Internal agent: captures inbound (bastion → host) with process/user context
- Central aggregator: stitches inbound/outbound via timestamps and process trees to create full user activity chain
- Output: "User alice@vpn → Bastion (auth at 14:00) → Host-03 (SSH at 14:02) → accessed /var/cache at 14:03 → Host-05 at 14:05"

**Lateral Movement Detection:**
- Flag: SSH from unexpected internal IP
- Query bastion agent: "Do you know about this connection?"
- Query target host: "Is this source in your baseline?"
- If both agents say "no," high confidence lateral movement detected

**Business Process Mapping:**
- Extract service-to-service dependencies from observed flows
- Build directed graph: which services talk to which
- Annotate with traffic volume, criticality, typical timing
- Identify anomalous new connections (service pair not previously observed)

---

## Configuration Metadata & Versioning

### 10. Config Versioning & Audit Trail

**Version Control:**
- All agent configs stored in central Git repository (hosted internally)
- Commit message per change: reason, approver, timestamp
- Diffs visible for every config change
- Ability to revert to previous version

**Dating Scheme:**
- Config version includes timestamp of last generation/approval
- Agent reports which config version it's running
- Central can audit "which agents are running outdated configs"

**Distributed Config Delivery (TBD Implementation):**
- **Option 1:** Direct push from central config server to agents (TLS authenticated)
- **Option 2:** Config management system (SALT, CF Engine, Puppet) pulls from central Git and deploys
- **Option 3:** Hybrid (different deployment models for different network segments)
- **Decision needed:** Which mechanism fits the deployment environment?

---

## 3D Visualization Client

### 11. Unreal Engine 3D Interface

**Architecture:**
- Standalone client (analyst's workstation) running Unreal Engine 3D application
- Connects to central aggregation for topology + baseline data
- Subscribes to real-time anomaly stream (from log aggregator)
- Optional: proxies queries through agent network (via bastion agent forwarding)

**Rendering & Abstraction:**

**High-Level View:**
- 3D representation of network topology (hosts, subnets, data centers)
- Baseline connections rendered as wireframe or muted (normal)
- Anomalies highlighted/animated (something is wrong here)
- User can filter by: severity, time window, user, process, host class

**Mid-Level View (Drill-Down):**
- Click host to zoom in
- View host's process baselines and typical dependencies
- Overlay live anomalies for that host
- Timeline scrubber to replay activity over past 24 hours

**Detail View:**
- Individual flow/access records
- File path accessed, process PID/user, destination socket
- Correlation confidence score
- Baseline context (was this path/destination expected?)

**User Interactions:**
- Drill down from anomaly flag to full context
- Correlate across hosts in same view
- Build hypotheses (is this user behaving oddly? Is this host?)
- Export forensics data for incident response

**Data Feeds:**
- Static: network topology, service dependencies, business process map (from central aggregation)
- Dynamic: real-time anomaly stream + agent responses to queries

**Query Capability:**
- User can probe live or historical data via agent network
- Client formulates request, forwards through agent proxy chain
- Results rendered in place

---

## Non-Functional Requirements

### 12. Performance & Deployment

**Agent Resource Impact:**
- Must remain unobtrusive on production systems
- CPU usage: target <1% on typical busy host (to be benchmarked)
- Memory footprint: <50MB resident (target; TBD based on baseline size)
- Network overhead: passive observation only; reporting is summarized/batched
- Disk I/O: minimal; local storage is ephemeral (baseline in memory)

**Ease of Deployment:**
- Single binary per platform (compiled)
- Minimal dependencies (no heavy ML libraries, no JVM, etc.)
- Config-only customization; no recompilation required
- Drop-and-go: agent starts, fetches config, begins learning

**Ease of Management:**
- Centralized config management (Git + push/pull mechanism)
- Single point of policy review (one place to approve baselines)
- Automatic propagation of config updates to fleet
- Clear audit trail of decisions (who approved what, when, why)

**Scalability:**
- Agent designed for individual host operation; no global state required
- Central aggregation must handle thousands of hosts' data streams
- Visualization client must handle complex topologies (architecture TBD)

---

## Open Questions & TBD

### Configuration & Delivery
- [ ] Config delivery mechanism: direct API, SALT/CF Engine, hybrid? (Implementation dependent)
- [ ] Config validation: does agent verify digital signatures on config pushes?
- [ ] Does agent validate schema before activation?

### Agent Configuration & Key Management
- [ ] Private key storage strategy: encrypted file + passphrase, TPM, HSM, or memory-only?
- [ ] Key rotation interval: daily, weekly, monthly, configurable per environment?
- [ ] What happens if agent loses its private key (re-register, manual recovery)?
- [ ] Out-of-band registration mechanism: API call from SALT/CF Engine to central? Database insert? Webhook?
- [ ] Who validates the reported checksum/key matches what central expects? (Deploying engineer manual validation)
- [ ] Retry/recovery if initial out-of-band registration fails?

### Port Knocking & Discovery
- [ ] Knock packet port: standard port or randomized? Configurable per deployment?
- [ ] Port opening behavior: random port each knock, or reuse same service port? Timeout duration configurable?
- [ ] Should agent log failed knock attempts rate-limit or throttle repeated invalid knocks?
- [ ] Discovery broadcast method: multicast, broadcast to specific port? Configurable?
- [ ] Discovery response: what metadata included beyond capabilities (agent version, last checkin, etc.)?

### Payload Management & RBAC
- [ ] Which crypto algorithm for payload signing? (RSA-2048, Ed25519, etc.)
- [ ] How are signing keys distributed and rotated? (Central secret store, HSM, etc.)
- [ ] Multiple signing keys per organization, or single key? (Different keys for different teams/approval levels?)
- [ ] Dual-signature enforcement: which payloads require it? (Answer: State-modify payloads; read-only requires single signature)
- [ ] How is RBAC enforced: on client before sending, on agent before execution, or both?
- [ ] User authentication for payload requests: OAuth, LDAP, client certs, API keys?
- [ ] Frequency/rate limits on payload execution: enforce at agent or central level?
- [ ] How are new users/roles provisioned in RBAC system?
- [ ] How often are RBAC changes audited? (Real-time audit or periodic reports?)

### Reporting & Logging
- [ ] Out-of-band event signing: which algorithm? Same as request signing?
- [ ] Caching strategy for offline networks: duration, capacity, encryption at rest for cached events?
- [ ] Which data goes over TLS vs. syslog: decision criteria per deployment model?
- [ ] Payload execution audit log retention: indefinite, or configurable?
- [ ] NTP monitoring: what threshold for "unexpected drift" to trigger flag?

### Threat Model & Trust Boundaries
- [ ] What is the explicit trust boundary? (Central trusted, client trusted, SALT trusted, TLS CAs trusted)
- [ ] Impact analysis: if central is compromised, if client is compromised, if config mgmt is compromised
- [ ] Agent binary attestation: how is "original binary matches registered checksum" proven after deployment?

### ML/Detection Strategy
- [ ] Does agent do local anomaly scoring (return flags) or return raw data for central correlation?
- [ ] For inotify + flow correlation (path traversal/exfiltration): agent-level or central-level?

### Data Retention
- [ ] Exact retention windows for granular vs. summarized data (baseline: 48h detail, 30d summary)?
- [ ] Does agent support historical queries ("give me flows from yesterday") or streaming only?

### Visualization
- [ ] Real-time vs. historical: does 3D client show live anomalies or historical replay?
- [ ] Export format for business process map: API integration with ServiceNow, JSON/YAML, visualization only?
- [ ] Auto-flag missing/unexpected dependencies in process map?

### Scope Boundaries
- [ ] What prevents this from becoming CrowdStrike-heavy? (Principle: lightweight, compiled logic, minimal config)
- [ ] Active defense out of scope; detection and forensics only?
- [ ] DPI out of scope; flow accounting + file access monitoring only?

---

## Design Principles

1. **Stay lightweight.** Every feature must justify its CPU/memory cost. If it requires heavy libraries or continuous scanning, find another way.

2. **Assume agents can't talk to each other.** Design for isolated operation; inter-agent communication via forwarding is an optimization, not a requirement.

3. **Respect network segmentation.** Use existing access controls (ACLs, firewalls) as authorization; don't punch new holes. Agents forward through existing network paths.

4. **Leave no weapons on the edge.** Agent configs and binaries should not reveal detection logic, reconnaissance intent, or capability lists to unauthenticated parties. Port knock to discover, sign to authorize.

5. **Trust the request, not the agent.** Agents are proxies, not authorities. All authorization lives in signatures and RBAC. Compromised agent can forward requests but cannot forge them.

6. **Compartmentalize compromise.** Compromised agent cannot escalate itself, forge requests as other users, or unlock its own config. Blast radius is limited.

7. **Collect ground truth, surface anomalies.** Agents observe and report; central aggregation correlates and builds context. Agents do not make policy decisions.

8. **Make the invisible visible.** The 3D client's job is to make "what should be here" and "what shouldn't be here" obvious at a glance for the human analyst.

9. **Separate read from write, single from dual.** Read-only operations (inspection, analysis) require single signature; state-modifying operations require dual signature (central + user). Trust is split.

---

## Next Steps

1. Prototype agent on Linux with eBPF (flow + inotify monitoring)
2. Implement config bootstrap and fetch mechanism
3. Build agent-to-agent forwarding (TLS auth, request routing)
4. Develop central aggregation layer (session correlation, baseline learning)
5. Design 3D visualization wireframe (topology rendering, anomaly overlay)
6. Validate resource impact on production-like hosts
7. Iterate on ML thresholds based on lab testing
8. Design config management integration (SALT/CF Engine connector or direct API)
