# Packetsonde Management Layer: Requirements Document

## Executive Summary

The Packetsonde Management Layer is the centralized orchestration, correlation, and policy enforcement system. It receives signed events from distributed agents, aggregates data into user-level and network-level context, manages configurations and payloads, enforces role-based access control for administrators and analysts, and surfaces findings through the 3D visualization client and ITSM integrations. The management layer does NOT hold agent private keys or decrypt agent configs; it is a policy authority and correlation engine, not a cryptographic hub.

---

## Architecture Overview

**Three functional domains:**

1. **Event Ingestion & Aggregation** - Receive signed events from agents (directly via TLS or via proxy agents), validate signatures, index, and correlate
2. **Configuration & Payload Management** - Manage agent configs (encrypted with agent keys), manage approved payloads (signed centrally), distribute securely
3. **Policy & Analytics** - User/account baselines, lateral movement detection, business process mapping, compliance reporting

---

## Event Ingestion & Aggregation

### 1. Event Reception

**Direct TLS Channel (Sensitive Data):**
- Agents send anomaly flags, forensics findings, and sensitive operational data directly to central management over authenticated TLS
- Agent authenticates via: TLS client certificate (agent public key) or API key (agent identity)
- Each event payload signed by agent (signature proves origin and integrity)
- Central validates agent identity + signature before processing

**Proxy Report Channel (Intermediate Agents as Reporting Relays):**
- Agents without direct management connectivity send events through intermediate agent (e.g., bastion agent)
- Intermediate agent acts as reporting proxy: receives event from downstream agent, validates signature, forwards to central under its own TLS identity
- Central receives: (original event + original agent signature) + (proxy agent TLS identity)
- Validates: original agent signature authentic, event hasn't been modified in transit
- Records: which proxy relayed it (for operational visibility)

**Out-of-Band Signed Events (Standard Operations):**
- Agents send operational events (baseline changes, config updates, normal activity) via syslog or other log transport
- Events signed by agent (signature embedded in event)
- Central receives via log aggregator (Sluice, Logstash, etc.)
- Central validates signature (proves event came from agent, not forged or modified by log infrastructure)

**Reception Rules:**
- Unsigned events rejected
- Events with invalid signatures rejected and logged as security incident
- Events from unregistered agents rejected
- Events with timestamps outside acceptable range (clock drift detection) flagged for NTP review
- Duplicate events (same signature, same content) de-duplicated

### 2. Event Validation & Parsing

**Signature Verification:**
- Extract agent public key from central's agent registry (registered at deployment)
- Verify event signature matches agent's public key
- If invalid: log security incident, alert operations team, discard event

**Timestamp Validation:**
- Event timestamp must be within acceptable skew (default: ±5 minutes of central time)
- Timestamps outside range trigger NTP anomaly flag on agent
- Allows for gradual clock drift but catches sudden jumps (compromise indicator)

**Content Parsing:**
- Extract event type (anomaly flag, baseline change, audit log entry, health status, payload execution log)
- Parse structured event content (process details, file access, network flow, timestamps, correlation scores)
- Normalize for storage and querying

### 3. Event Indexing & Storage

**Event Database:**
- Searchable index: timestamp, agent ID, event type, user (if applicable), process, host, severity, status
- Full-text search on event details (command line, file paths, network destinations, etc.)
- Time-series storage (efficient for historical queries)
- Retention policy: configurable per event type (anomalies: indefinite, health checks: 30 days, etc.)

**Indexed Fields:**
- Agent ID, agent mode (host/proxy/trunk/bridge)
- Timestamp, event type, severity level
- User identity (if involved), process name/PID, parent process
- File path (if file access event), network source/destination
- Baseline deviation (if anomaly), confidence score
- Signature validity, proxy agent (if relayed)

**Queryable Examples:**
- "Show all anomalies from user alice in past 7 days"
- "Show all state-modify payload executions on core network"
- "Show all events from agents without NTP corrections in past 24 hours"
- "Show all failed knock attempts across fleet"

---

## Configuration Management

### 4. Agent Configuration Lifecycle

**Configuration Storage:**
- Central stores encrypted agent configs (encrypted with each agent's public key)
- Central cannot decrypt them (only agent can with its private key)
- Configs stored in version control (Git) with audit trail
- Each config version tied to approver, timestamp, change reason

**Configuration Content Categories:**
- **Baseline Parameters:** anomaly thresholds, envelope parameters, learning mode
- **Access Control:** authorized public keys, RBAC mappings (key → role → capabilities + networks)
- **Monitoring Rules:** paths to monitor (inotify), process baselines, expected network destinations
- **Behavior:** which ML features enabled, reporting cadence, cache duration
- **Operational:** deployment mode, TLS cert pinning, central management URL

**Configuration Update Workflow:**
1. Administrator edits config in central Git repo
2. Change includes: reason, target agent(s) or agent class, approver
3. Central system encrypts updated config with target agent's public key
4. Config pushed to agent via TLS or config management system (SALT/CF Engine)
5. Agent receives, decrypts, validates schema, reloads
6. Agent reports success/failure back to central
7. Audit log records: who changed what, when, approver, agent acknowledgment

**Configuration Rollback:**
- Previous versions stored in Git
- Can revert to any prior version
- Rollback triggers re-encryption and re-push
- Audit log shows: original change, rollback reason, timestamp

**Configuration Templates:**
- Pre-built templates for common agent classes (CDN edge, bastion, internal host, etc.)
- Customizable per site/environment
- Allows quick deployment with sensible defaults

### 5. Payload Repository & Signing

**Payload Storage:**
- Centralized repository of approved probes/payloads
- Versioned in Git alongside configs
- Each payload includes: name, description, execution class (READ_ONLY or STATE_MODIFY), parameters, validation rules, approval date, signing key used

**Payload Approval & Signing:**
- New payload submitted by team (security, ops, audit, etc.)
- Reviewed by authorized approver
- If approved: signed with central authority's private key
- If rejected: archived, not signed
- Signature prevents tampering (central authority vouches for payload safety)

**Payload Classes:**
- **READ_ONLY:** Inspection queries, analysis, baseline reads
- **STATE_MODIFY:** Code execution, process management, filesystem writes

**Payload Metadata Example:**
```yaml
name: "Extract-SSH-Keys"
version: "1.2"
class: "STATE_MODIFY"
description: "Enumerate SSH authorized_keys on target host (forensics)"
parameters:
  - target_user: "string"
  - output_format: "enum(json,yaml)"
approver: "security_lead@corp"
approved_date: "2026-05-15T10:30:00Z"
signing_key_id: "central-authority-key-2026"
deprecated: false
```

**Payload Lifecycle:**
- Creation → review → approval → signing → distribution → usage → deprecation → retirement
- Payloads can be marked deprecated (warnings issued on execution) without being removed
- Revoked payloads: signature invalidated, agents reject them

---

## Central RBAC & Access Control

### 6. Administrator/Analyst Access Control

**User Roles (Administrators):**

| Role | Capabilities | Purpose |
|------|--------------|---------|
| Central Admin | All system operations, user management, config approval, payload approval | Full control |
| Config Manager | Edit agent configs, approve config changes, view audit logs | Configuration operations |
| Payload Reviewer | Review and approve payloads, manage payload lifecycle | Security approval |
| Threat Analyst | Execute READ_ONLY payloads, view anomalies, correlate events, query history | Investigation |
| Incident Responder | Execute STATE_MODIFY payloads on incident hosts, approve own forensics requests, escalate incidents | Incident response |
| Auditor | View audit logs, compliance reports, query historical data (read-only) | Compliance/audit |

**Access Control Enforcement:**
- Central authentication: OAuth, LDAP, SAML, or MFA-enabled API keys
- Each user has assigned role(s) and scope (which agents/networks they can access)
- Attempt to exceed scope logged as security incident
- All operations logged with user identity, timestamp, action, result

**Approval Workflows:**
- Config changes require approval from Config Manager or higher
- STATE_MODIFY payloads require execution approval (can be delegated or self-approved based on role)
- Incident escalation requires Incident Responder role
- High-risk operations (disable hardening, revoke signing key) require multi-approval

---

## Policy Enforcement & Correlation

### 7. User-Level Behavioral Baselines

**Building Baselines:**
- Central aggregates auth logs, flow summaries, and process baselines from agents
- Per-user baseline: "Which hosts does user X typically access? From which IPs? At what times? What are typical data volumes?"
- Learned over configurable period (default: 30 days)
- Updated continuously as new data arrives

**Baseline Content:**
- SSH login sources (VPN IPs, bastion IPs)
- SSH login destinations (which internal hosts)
- Typical login times (business hours, specific times of day)
- Data volume patterns (which users typically transfer lots of data)
- Cross-host session chains (typical progression from host A to host B to host C)

**Anomaly Detection:**
- User logs in from unexpected IP → flag
- User accesses host they've never accessed before → flag
- User transfers 10x normal data volume → flag
- User accesses host at 3am when they typically work 9-5 → flag
- User's session chain differs from normal pattern → flag

### 8. Lateral Movement Detection

**Cross-Agent Correlation:**
- Bastion agent sees: SSH from user alice to internal host prod-01
- prod-01 agent sees: SSH inbound from bastion (correlate with source)
- Central correlates: "Alice logged into bastion at 14:00, logged into prod-01 at 14:02, is this normal?"
- If yes: normal activity, log it
- If no: flag as anomalous

**Lateral Movement Indicators:**
- SSH from unexpected internal IP (should come from bastion only)
- SSH from host not in user's baseline
- Rapid SSH to multiple hosts in short time (reconnaissance pattern)
- SSH to host followed immediately by process execution on that host (exploitation pattern)
- Process baseline violation immediately after SSH from new source

**Detection Examples:**
- Normal: User → Bastion → Host-A → Host-B (known progression)
- Anomalous: Compromised Host-C suddenly SSH's to Host-D (Host-C not in bastion's baseline, Host-D not known to be connected to Host-C)
- Anomalous: User SSH's from internal IP (not bastion), to host not in baseline
- Anomalous: SSH login followed by new process on that host not in baseline

### 9. Business Process Mapping

**Data Collection:**
- Flow summaries: src/dst pairs, volume, timing
- Process baselines: which processes talk to which services
- User activity: user A typically interacts with services X, Y, Z

**Dependency Graph:**
- Nodes: hosts, services, VLANs, users
- Edges: communication relationship (flow observed), volume, frequency, criticality
- Annotations: is this edge expected (in baseline) or anomalous (new)?

**Map Generation:**
- Automatic: infer from observed flows
- Manual: admin can define expected dependencies (documenting known good state)
- Comparison: show delta between manual map (intent) and observed map (reality)

**Output Formats:**
- Topology visualization (feeds 3D client)
- JSON/YAML for external systems
- ITSM integration (ServiceNow, etc.)

**Examples:**
- "Service A depends on Service B, communicates on port 443, typical volume 100GB/day"
- "User alice typically works with databases in segment A and reports in segment B"
- "CDN edge typically communicates with origin on port 443, cache on 10.1.1.0/24, management on 22"

---

## Integration & Reporting

### 10. ITSM Integration (ServiceNow, etc.)

**Bi-Directional Integration:**

**Central → ITSM:**
- Service dependencies discovered from network data
- Change impact analysis (if we update service X, what depends on it?)
- Compliance reporting (who accessed what, when, with what approval)
- Incident timeline (user's activity leading up to compromise)
- Anomaly severity and recommendations

**ITSM → Central:**
- Scheduled maintenance windows (suppress anomaly alerts during expected downtime)
- Known incident tickets (correlate alerts to incident ID for context)
- Approved change records (validate that config/deployment change was authorized)
- Service catalog (understand service criticality for risk scoring)

**Payload Approval Integration:**
- STATE_MODIFY payload requests create tickets for approval
- Ticket tracks: who requested, what payload, which agent, approval status
- Approval in ticket triggers payload execution in agent
- Audit trail preserved in both systems

### 11. Compliance & Audit Reporting

**Audit Log Queries:**
- "Which users executed forensic payloads in past 30 days?"
- "Show all failed authorization attempts"
- "Which configs were changed and by whom?"
- "Which agents have never been successfully reached by management?"
- "Show all events where systemd hardening was modified"

**Compliance Reports:**
- User access audit (who accessed what, when, with what authorization)
- Data exfiltration risk (potential unauthorized data movement based on baselines)
- Lateral movement attempts (detected cross-host anomalies)
- Configuration drift (agents running non-approved configs)
- Payload execution log (what forensics operations occurred, when, by whom)

**Retention Policy:**
- Event logs: retention per event type (anomalies: indefinite, operational: configurable)
- Audit trails: indefinite (compliance requirement)
- Payload execution: indefinite (forensics and compliance)
- Config versions: indefinite (Git maintains full history)

---

## Central Management Security

### 12. Central Management Hardening

**Authentication & Authorization:**
- All central API access requires authentication (OAuth, LDAP, SAML, MFA-enabled keys)
- All operations logged with user identity, timestamp, action
- Unauthorized access attempts logged as security incidents
- Privilege escalation requires secondary approval

**Encryption:**
- Agent configs encrypted at rest (using agent public keys, central cannot decrypt)
- TLS for all network communication (agent→central, admin→central, central→ITSM)
- Database encryption at rest (for event logs, audit trails)
- Backup encryption (if central is compromised, backups are not exposed)

**Network Isolation:**
- Central management network segregated from agent networks
- Agents reach central via outbound TLS (agents don't inbound listen)
- Admin access to central: VPN + MFA
- Central doesn't hold agent private keys or user private keys

**Operational Security:**
- Central admin credentials stored in secret management system (Vault, etc.)
- Signing keys (for payloads) stored in HSM or secret manager
- No plaintext keys in config files
- Regular key rotation

**Redundancy & HA:**
- Central should be HA (multiple instances, load balanced)
- Failover should not lose recent events (distributed message queue or replicated DB)
- Backup strategy: regular encrypted backups, tested restore procedures

### 13. Input Validation & Injection Prevention

**Event Processing:**
- All incoming event fields validated against schema before processing
- Reject events with unexpected field types or sizes
- Prevent log injection (sanitize user-controlled strings in audit logs)
- Prevent NoSQL/SQL injection (parameterized queries, input validation)

**Configuration Updates:**
- Config schema strictly validated (YAML/JSON parsing, type checking)
- Reject configs with unknown fields (fail-safe)
- Reject configs that modify hardening parameters in ways that weaken agent

**Payload Definitions:**
- Payload parameters validated (type, range, allowed values)
- Reject payloads with suspicious execution classes or parameters
- Code review for new payloads before approval

---

## Reporting & Visibility

### 14. Dashboard & Alerting

**Operational Dashboard:**
- Fleet overview: agents online/offline, last checkin time, config version
- Anomaly summary: count by severity, type, agent
- User activity: recent logins, privilege escalations, suspicious behavior
- Payload execution log: recent executions, approval status

**Alert Rules:**
- Unexpected agent restart (uptime reset)
- Multiple failed knock attempts on single agent (reconnaissance)
- Lateral movement attempt detected
- User accessing host outside baseline
- Unauthorized payload execution attempt
- Agent loses central connectivity
- Agent NTP drift not corrected

**3D Client Feeds:**
- Real-time anomaly stream (new alerts appear on topology)
- Static data: topology, business process map, baseline envelopes
- Query results: drill-down to flow records, forensic data

---

## Proxy Agent Reporting

### 15. Intermediate Agents as Reporting Relays

**Proxy Architecture:**
- Downstream agents without direct management access send events to intermediate agent (bastion)
- Intermediate agent authenticates to central, establishes TLS session
- Downstream agent sends event with signature to intermediate agent
- Intermediate agent: validates signature, forwards to central with proxy metadata

**Event Flow:**
```
Edge Agent (Event + Signature) 
  → Bastion Agent (validate signature, forward)
    → Central Management (receive, validate both signatures)
```

**Validation at Each Hop:**
- Edge Agent signs event with its private key
- Bastion Agent validates signature with Edge Agent public key (from central registry)
- Central validates: Edge Agent signature authentic, Bastion Agent identity authentic

**Metadata Preservation:**
- Original event signature preserved (proves origin)
- Proxy agent identity recorded (which relay path was taken)
- Timestamps: original event time + relay time (latency visibility)

**Proxy Agent Responsibilities:**
- Do NOT modify event content
- Do NOT re-sign event (would break original signature)
- Do validate signature (reject unsigned or malformed events from downstream)
- Do report forwarding metrics (count of events relayed, latency, failures)
- Do maintain TLS session to central (reconnect on failure)

**Central Processing:**
- Receive event + original signature + proxy identity
- Validate original signature (proves event authentic)
- Record which proxy relayed it (operational visibility, troubleshooting)
- Index event as if it came directly (transparent to analytics)

**Caching During Disconnection:**
- If intermediate agent loses connectivity to central, cache events locally
- Cache signed events as-is (no modification)
- Cache encrypted with local key (if cache is read from disk)
- Resume forwarding when central reachable (replay in order)
- TTL on cached events (old events discarded if central unreachable too long)

---

## Central Management Deployment

### 16. Deployment Models

**Standalone Deployment:**
- Single central management node
- All events collected and processed locally
- Direct TLS connections from agents

**High-Availability Deployment:**
- Multiple central nodes behind load balancer
- Shared database (events, configs, audit logs)
- Shared message queue (event processing distributed)
- Any node can accept admin connections, answer queries
- Failover transparent to agents and clients

**Federated Deployment (Multi-Site):**
- Multiple regional management instances
- Each region has its own event database, configs, RBAC
- Central authority distributes signing keys, ITSM integration, audit policy
- Agents report to nearest regional instance
- Cross-site correlation for global anomalies (TBD: mechanism)

---

## Open Questions & TBD

### Central Architecture
- [ ] Database choice: time-series DB (Prometheus, InfluxDB) vs. traditional RDBMS vs. log store (Elasticsearch)?
- [ ] Event queue: Kafka, RabbitMQ, Redis for decoupling ingestion from processing?
- [ ] How are events deduplicated across multiple central nodes (HA)?
- [ ] Cross-region correlation in federated deployment: how to detect global patterns?

### Event Processing
- [ ] Real-time vs. batch processing: should anomalies be flagged immediately or after aggregation?
- [ ] Correlation window: how long to wait for events before closing a session/correlation?
- [ ] Machine learning on central vs. agent: who learns user baselines, who detects deviations?

### Proxy Reporting
- [ ] How long should intermediate agents cache events if central is unreachable?
- [ ] Should proxy agents validate signatures, or just forward?
- [ ] Should proxies re-sign events (breaks original signature), or pass through unchanged?
- [ ] How many hops of proxying are allowed before events are discarded?

### Integration
- [ ] ITSM API: should central push updates, or should ITSM pull from central?
- [ ] ServiceNow synchronization frequency: real-time or periodic batch?
- [ ] How to handle conflicts (same service mapped differently in central vs. ITSM)?

### Policy & Correlation
- [ ] User baseline learning period: 30 days? Configurable per user?
- [ ] Lateral movement threshold: how many hops before flagging as anomalous?
- [ ] Should baseline deviations auto-escalate based on severity, or all require review?

### Central Security
- [ ] Key rotation for payload signing key: frequency, procedure?
- [ ] Central admin password policy: strength, MFA requirements, rotation?
- [ ] Audit log encryption: at rest only, or in transit too?
- [ ] Who can approve config changes: single approval or multi-approval workflow?

---

## Design Principles (Central Layer)

1. **Central is orchestration, not authority.** Central manages policy and payloads, but agents enforce policy with signatures. Central cannot force compliance.

2. **Never decrypt agent configs.** Central encrypts with agent's public key, cannot decrypt. If central is compromised, agent configs remain protected.

3. **Preserve signature chains.** Events forwarded through proxies maintain original signatures. Never re-sign or modify event content.

4. **Make correlation transparent.** Analysts should see "user → bastion → host" session chains naturally, not have to reconstruct them manually.

5. **Audit everything.** All policy decisions (approvals, config changes, payload executions, user access) logged immutably.

6. **Failover invisibly.** HA central means agent connections don't break, clients don't reconnect, analysis is continuous.

7. **Compartmentalize data.** Different admin roles see different data (auditor doesn't see incident response details, etc.).

---

## Next Steps

1. Choose database/event store architecture
2. Design event correlation pipeline (user sessions, lateral movement detection)
3. Build central API (agent connectivity, config distribution, event ingestion)
4. Implement admin RBAC and audit logging
5. Build payload approval workflow
6. Design 3D client integration (real-time feeds, static data endpoints)
7. Implement ITSM connectors (ServiceNow, etc.)
8. Establish HA/failover strategy
9. Deploy security hardening for central infrastructure
