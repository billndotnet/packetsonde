# packetsonde — A Navigable Spatial View of the Internet

**Whitepaper, 2026-04-27**

---

## Contents

1. Identity, Vision, and Design Philosophy
2. Motivation and Position in the Landscape
3. Use Cases (Detailed Walkthroughs)
4. Conceptual Model
5. System Architecture
6. Service-Architecture Adapters and Extensibility
7. Multi-Agent Remote Connectivity
8. Security and Trust Model
9. Discovery and Pairing
10. C++ / Blueprint Boundary
11. Third-Party Wheels (What We Don't Reinvent)
12. Splash and Launch Experience
13. UI / UX Design
14. Interactive Links and Annotations
15. Visual System
16. Data Model
17. Inference Pipelines
18. Placement
19. Collapse Semantics
20. Anycast Object Model
21. Forensics Overlays
22. Persistence
23. Performance and LOD Policy
24. Build, Run, Package
25. Project Layout
26. Configuration Schemas
27. Open Questions and Risks
28. Roadmap
29. Glossary

---

## 1. Identity, Vision, and Design Philosophy

### 1.1 Identity

**Name:** packetsonde.

**Wordmark:** lowercase `packetsonde`, monospace family. Period-tagline: `· a navigable view of your Internet`.

**Brand mark:** a wireframe sphere — the *sonde* — falling into a horizontal field of monospace `0`s and `1`s. The sonde lands and ripples the field. The image is the project's identity in a single frame: an instrument descending into the substrate of the network to take measurements you can study afterward.

**One-line pitch:** packetsonde turns your network's topology — the actual destinations and routes your traffic uses — into a 3D world you can fly through, study, and develop intuitions about.

**Audience:** four overlapping populations:
- Curious users wanting to understand what their network actually does.
- Security-aware users investigating IoT, ad-tracker, spam, or supply-chain patterns.
- Educators and students using a real-world testbed to teach how the Internet works.
- Network operators wanting an alternate, intuitive view alongside their existing instruments.

### 1.2 Vision

The Internet is a real, geographically-distributed system run by a particular cast of organizations. Most users never see this. They see brand websites and a hidden mass of opaque traffic. packetsonde aims to make that mass *legible* — recognizable, navigable, and over time *familiar* — without flattening it into dashboards or oversimplifying it into colored bars.

The reference frames are two:
- **Cyberpunk literature and games** — Gibson's Sprawl trilogy (Neuromancer, Count Zero, Mona Lisa Overdrive), Stephenson's *Snow Crash* metaverse, the Shadowrun cyberdeck Matrix, Mr. Robot's network montages. The aesthetic premise: treat networks as inhabited 3D spaces with characteristic architecture per operator and a sense of journey between locations.
- **Cartographic tradition** — the Internet has real geography (datacenters, peering exchanges, submarine cables). A map that respects that geography, but stylizes it for recognition rather than survey accuracy, is a useful thing.

### 1.3 Design philosophy

Five principles drive every design decision:

1. **Spatial intuition is a forensic primitive.** The same brain machinery that notices a strange building on a familiar street notices a strange host in a familiar AS-cluster, *if the topology is presented as a place rather than as a list*. We optimize for that recognition.

2. **The world is the primary surface.** Panels are secondary. UI floats, slides in on demand, dismisses easily. There is no chrome-heavy default view. The user lives in the 3D world; the chrome serves it.

3. **Stylize on top of truth, never replacing it.** A Cloudflare citadel looks distinctively like Cloudflare, but one click reveals the actual ASN, IP ranges, hostnames, latency. The art is recognition aid; the data is the truth.

4. **The world remembers.** packetsonde is longitudinal. Every visit, every observation accumulates. A daily destination becomes a known landmark; a one-shot is a faint trail. Familiarity over time is the visual.

5. **Hands-on debugging beats clever abstractions.** Where the user needs to understand or tweak behavior, that behavior lives in Blueprints and is debuggable in the editor. C++ does the heavy lifting and the data plumbing; Blueprints own anything visual, interactive, or policy-shaped. This guides every layer split.

### 1.4 What packetsonde is not

- Not a packet capture tool. Wireshark, tcpdump, mitmproxy keep that role.
- Not a network monitoring dashboard. Grafana, Kibana, PRTG keep that role.
- Not a global Internet visualizer. packetsonde renders *your* observed Internet, not the abstract whole.
- Not an alerting system. We surface anomalies in-world, but we're not paging anyone.
- Not a turnkey commercial product. It's a hobbyist-grade personal tool with an emphasis on craft.

## 2. Motivation and Position in the Landscape

### 2.1 The instrument gap

Network monitoring tools split into two camps that don't serve curiosity well:

**Engineering instruments** (Wireshark, BGP visualizers, NetFlow consoles, pcap analyzers, dashboards) answer queries. They reward expertise and punish browsing. A user who doesn't know what to ask sees columns of hex.

**Provider-portal abstractions** (router admin pages, ISP customer portals, VPN dashboards) hide reality behind a few simplified labels. A user who wants to *see* what's happening gets a sanitized summary with no way to drill in.

Neither makes it easy to *notice* something the user didn't already know to look for. Neither makes the Internet feel like a real, geographically-distributed place. Neither helps a casual user develop intuition about whether a destination is normal, suspicious, or simply unfamiliar.

There are some adjacent tools worth naming explicitly:
- **CAIDA's Skitter / Archipelago** — academic Internet topology measurement. Powerful but research-oriented and not interactive.
- **Hurricane Electric BGP toolkit** — excellent ASN/IP lookups but not visual.
- **PingPlotter / MTR** — single-path visualization. Closest in spirit to packetsonde for a single trace, but one-dimensional.
- **Gephi / Cytoscape** — generic graph visualizers. They draw networks, but the abstractions don't capture "place" or "operator identity" — a graph layout is a pretty chart, not a map.
- **ntopng / nProbe** — flow analysis with maps. Geographic tagging exists but it's a sidebar to dashboards, not the primary view.

packetsonde occupies a space between casual user education and forensics. It draws from cartography (geographic anchoring), cyberpunk aesthetics (territorial archetypes for orgs), graph theory (containers and paths), and game-design instincts (navigation, recognition, accumulation).

### 2.2 What spatial intuition gets you

Concrete examples of patterns that are obvious in 3D space and tedious in queries:

- *"My TV makes 47 connections to 12 ASNs every hour."* In a flow log: a tedious aggregation. In packetsonde: 12 lights pulsing repeatedly in a familiar constellation around the TV's position.
- *"Every page I visit hits the same five ad-tech orgs."* In dev tools: lists per page, mental aggregation across pages. In packetsonde: the same five citadels light up regardless of which webpage you load. Recognition is immediate.
- *"This anycast IP is now being served from Tokyo when it used to be Ashburn."* In monitoring: a needle in a haystack of route changes. In packetsonde: the IP visibly relocates; an anomaly flare fires.
- *"This unfamiliar ASN keeps appearing in IoT traffic at 3am."* In flow data: a query if you know what to search. In packetsonde: an unfamiliar building in a familiar suburb that lights up only at a certain hour.

The common pattern: the user *recognizes* what's wrong before they have a hypothesis to test. That's the value packetsonde delivers.

## 3. Use Cases (Detailed Walkthroughs)

### 3.1 IoT auditing

**Setup:** the user has 23 IoT devices on their home network — smart bulbs, a TV, a thermostat, two voice assistants, three cameras, a few obscure devices from cheap brands.

**Walkthrough:**
1. Open packetsonde. The world is populated from 6 weeks of accumulated traffic.
2. Open the command line (Cmd+K). Type "tv". Select "smart-tv 10.0.0.42" (the device).
3. Activate the "By Device" lens. The world dims to silhouettes; only territories that smart-tv has contacted in the last week light up.
4. Look around. The expected territories light up at expected positions: manufacturer cloud (an AWS region), CDN for app updates (Cloudflare), Netflix/YouTube/Roku stack.
5. One territory in the southern Pacific lights up dimly. The user has never been to it. Click. Inspector: org "AS<unknown>", country JP, hit count 142, first contacted 6 weeks ago.
6. Right-click "Filter to this territory's traffic". Now the world shows only flows touching that specific destination. The smart-tv contacts it at predictable intervals; nothing else does.
7. The user copies the IP into an external WHOIS / Shodan lookup, learns it's a server farm operated by a Chinese cloud provider that resells capacity to several adware operators.

This is exactly the discovery the user couldn't have made with a flow log alone. The territory was unfamiliar in a familiar map.

### 3.2 Ad and tracker mapping

**Setup:** the user is curious whether their reading habits are being tracked the way they suspect.

**Walkthrough:**
1. Activate the "By Org" lens.
2. Open three news websites in three browser tabs.
3. As each loads, a flight of luminous packets streams from Home outward. Lots of orgs. Some big citadels (Cloudflare, AWS, Google) and many small ad-tech mall-archetypes.
4. After 30 seconds, the *same* set of mall-archetypes have lit up across all three site loads. Recognition: "every site I read uses these five ad networks."
5. The user clicks one of the mall-archetypes. Inspector shows org name, IP ranges, recent activity. They flag the org with a personal note: "ad tracker — investigated 2026-04-27".
6. Going forward, that org's territory shows their personal-note glyph; future sessions reinforce or refute the suspicion.

### 3.3 Spam and phishing infrastructure

**Setup:** the user receives a steady trickle of phishing emails. They want to map the infrastructure.

**Walkthrough:**
1. Each phishing message's headers and click-through URLs are imported via a small CLI tool that hands them to packetsonde-agent. (Tool: `packetsonde import-mail <mbox>`. Out of scope for v1 but planned.)
2. Activate the "By Recency" lens limited to mail-source events.
3. The world shows where mail-relays, MX hosts, and link-shortener domains live. Recurring infrastructure across unrelated phishing campaigns becomes obvious — same hosting org, same metro, same edge POP.
4. The user can apply the "By Country" lens to see geographic concentration, or "By Anomaly" to see what changed week-over-week.

### 3.4 State-actor and supply-chain pattern recognition

**Setup:** the user is a hobbyist OSINT researcher curious about state-aligned ASNs.

**Walkthrough:**
1. The org config file has a curated `bStateAligned` flag on relevant orgs.
2. Activate the "By Anomaly" lens with a state-aligned filter.
3. State-aligned orgs glow with a distinctive desaturated red. Connections to them from devices that shouldn't need them surface as clear red glow points in the world.
4. A daily report: "yesterday, 3 of your devices made first-time contact with state-aligned orgs. Click for details." The user reviews and decides what's expected versus suspicious.

### 3.5 Casual education

**Setup:** a parent showing a child how the Internet works.

**Walkthrough:**
1. Casual mode is enabled in Settings. The inspector defaults to hidden; tooltips are friendly.
2. The parent says "let's see what happens when we load gmail.com". They click an action-bar button "load gmail" (a curated example).
3. The world animates: from Home, a packet streaks west. It enters the Comcast compound, threads through to a Level3 spire (Seattle), arrives at Google's Mountain View citadel.
4. The parent says "see, your email lives in California. The packet went there to ask Gmail for new mail."
5. The child asks, "why does it go through Comcast?" The parent clicks the Comcast compound. The inspector shows: "your Internet provider. Every packet that leaves your house goes through them first." Friendly explainer text per inspector field.

### 3.6 Anomaly detection and event correlation

**Setup:** the user wants to know when *anything* unusual happens on their network.

**Walkthrough:**
1. The anomaly side panel runs continuously, showing events in chronological order with severity color.
2. Yesterday, a flare fires: "anycast IP 1.1.1.1 is now being served from LAX (was IAD for the prior 6 weeks)."
3. The user investigates: did their ISP change peering? Are they on a different VPN today? Click the event → world animates back to that moment, showing the topology as it was when the change was detected.

### 3.7 Cross-network forensics with multiple agents (NEW with remote support)

**Setup:** the user has a packetsonde-agent at home, one at their parent's house, and one at their office (deployed via the salt-driven workflow from §8). They suspect their parent's smart appliances are talking to dubious places.

**Walkthrough:**
1. Open packetsonde. Connect to home + parent + office agents simultaneously. Each shows its own Home node + radiating world.
2. The three worlds share a single map projection. The parent's Home is at a distinct origin; the office Home is at a third origin.
3. Apply "By Org" lens. Parent's smart fridge contacts a hosting org in Russia. Office laptops contact mainstream orgs.
4. The user can compare paths: "from parent's network, the path to GitHub goes via Eastern European transit; from my network it goes via Pacific transit." Same destination, different routes — instructive.

## 4. Conceptual Model

### 4.1 The world is built from stable bones

Not every part of the Internet is equally persistent. The user's gateway, their ISP's regional edge POPs, and major destination services are *stable* across days, weeks, months. Middle-mile transit is *transient*: BGP path changes, ECMP reshuffling, peering rebalances, congestion all churn the visible chain trip-to-trip.

packetsonde reflects this. Persistent structures get permanent geographic anchors and accumulated visual identity. Middle-mile transit renders as illuminated routes between persistent structures, not as territories with their own architecture. A transit AS the user traverses lights up as a connecting thread, not a destination to fly to.

This separation is critical for the forensic affordances. The user's mental model is built from stable landmarks; transient things flicker briefly without disturbing the map.

### 4.2 Territory is `(Org × Metro)`, not just Org

Identity in packetsonde is the product of two dimensions:

- **Org** — administrative identity. Google. Cloudflare. Comcast. ASNs roll up into Orgs; multiple ASes can belong to one Org.
- **Metro** — physical place. IAD (Ashburn). LAX. FRA (Frankfurt). NRT (Tokyo). 3-letter IATA-style identifier or sanitized GeoIP city slug.

A territory is `(Org × Metro)`. Google IAD is a territory. Google NRT is a different territory in the same Org family. This granularity is meaningful: the user can fly into Google and arrive at *a specific Google datacenter*, not at "Google" the abstract entity.

Why not just Org? An Org-only model collapses Google's many global POPs into one centroid, producing visually generic and topologically misleading layouts. Org-Metro respects that an east-coast Google datacenter isn't a west-coast Google datacenter (or a British one, or a Tokyo one); they're different *places* even though they share corporate identity.

The Org contributes shared visual identity (color palette, archetype family, branding overlays). The Metro contributes the geographic anchor (lat/lon → world XY).

### 4.3 Anycast as a first-class entity

A single IP address can be served from many physical POPs. Cloudflare 1.1.1.1, Google 8.8.8.8, root DNS — the IP is everywhere; what serves you depends on routing.

packetsonde treats anycast as a separate registry. An `FAnycastEntity` keyed by IP records observations: which metros has this IP been served from, by which upstream, with what latency, when. Over time, multi-session, and (potentially) across-network the registry accumulates evidence about which IPs are anycast and which POPs serve them.

Confirmation requires *both* distinct metros AND distinct last-hop fingerprints — GeoIP jitter alone doesn't imply anycast; a different upstream peer carrying the route does. This is the most data-honest signal available.

### 4.4 Stylize on top of truth

Visual identity makes orgs recognizable. It never hides data. Every structure is one click from an inspector that shows ASN, IP ranges, hostnames, latency stats, observation timestamps. The art is recognition aid; the data is the truth. State-actor flags, role classifications, and visual archetypes are *shortcuts to perception*, not abstractions that conceal.

This matters because packetsonde will inevitably get curation wrong sometimes. An org tagged "AdTracker" might actually be a legitimate analytics provider; an org tagged "state-aligned" might be a research institution. The inspector exposes the underlying data so the user can override our judgment.

### 4.5 The world remembers

packetsonde is longitudinal. A territory contacted 1,000 times is more familiar — brighter, more detailed, more present — than one contacted once. A daily route becomes a known highway; a one-shot is a faint trail.

Decay reduces familiarity over time but doesn't zero it. A destination not visited in a year fades to silhouette but stays in the world, ready to be reilluminated when the user returns. The user can navigate to historically-known places and review their journey through them.

This temporal dimension is what distinguishes packetsonde from a snapshot. The world is *inhabited*; spaces the user has been are different from spaces they haven't.

### 4.6 Hop mode is the inspection backstop

Territory mode is the cyberdeck primary view. Hop mode is the alternate: a ring/topology layout showing every node and edge individually, no collapse. It's not a fallback; it's a tool for hands-on inspection of paths and packet behavior. The two modes share the same data layer; only visualization differs.

## 5. System Architecture

### 5.1 Process model

packetsonde is composed of three cooperating processes connected through Redis (locally) and TLS-WebSocket (remotely).

```
                ┌────────────────────────────────────┐
                │      Unreal Editor / packaged      │
                │      packetsonde client            │
                │                                    │
                │  ┌──────────────────────────────┐  │
                │  │  UPacketsondeWorldSubsystem  │  │
                │  └──────────────────────────────┘  │
                │       │           ▲     ▲          │
                │       ▼           │     │          │
                │  ┌─────────┐ ┌────┴─┐ ┌─┴────────┐ │
                │  │ Adapter │ │ BP   │ │ UMG      │ │
                │  │ Layer   │ │ Viz  │ │ Widgets  │ │
                │  │ (C++)   │ │ (BP) │ │ (BP)     │ │
                │  └────┬────┘ └──────┘ └──────────┘ │
                └───────┼────────────────────────────┘
                        │
                        │ Redis client (local) +
                        │ packetsonde-link (remote, TLS)
                        ▼
        ┌───────────────────────────┐  ┌───────────────────────────┐
        │  Local Redis              │  │  Remote agents (1..N)     │
        │  127.0.0.1:6379           │  │                           │
        │  Authoritative store +    │  │  packetsonde-agent +      │
        │  pub/sub bus              │  │    its own local Redis +  │
        │                           │  │    TLS server             │
        └────────────▲──────────────┘  └─────────────▲─────────────┘
                     │                                │
                     │                                │
        ┌────────────┴──────────────┐                 │
        │  packetsonde-agent        │                 │
        │  (local, C++)             │                 │
        │                           │                 │
        │  • libpcap                │                 │
        │  • libnl / netlink        │                 │
        │  • nmap traceroute        │                 │
        │  • setuid raw helper      │                 │
        │  • mDNS responder         │                 │
        │  • TLS server (for        │─────────────────┘
        │    remote UI clients)     │   (peer agents are reached
        │  • signed-broadcast resp  │    by remote UI through their
        └───────────────────────────┘    own TLS servers)
                     │
                     ▼
              network interfaces
              (eth0, wlan0, ...)
```

### 5.2 Editor module structure

The UE5 project ships these C++ modules:

- **packetsonde** (Core) — data structs, datastore, persistence, inference, world subsystem.
- **packetsondeAdapters** — Redis client, agent IPC (local), TLS WebSocket client (remote), per-source ingestion logic.
- **packetsondeViz** — base C++ classes for visualization actors that BP derives from. Contains lerp helpers, base material wrappers, edge math.
- **packetsondeUI** — base C++ classes for UMG widgets that BP derives from. Contains the inspector data binders, command palette logic, action-bar slot management.

Plus a runtime third-party module wrapping mDNS browsing.

### 5.3 Agent responsibilities (existing, unchanged)

The agent ships in `agent/` and is platform-agnostic from the editor's point of view. The editor never directly touches a network interface. Agent responsibilities:

- Passive packet capture (libpcap) for ARP, NDP, mDNS, DHCP discovery.
- NetFlow listener (UDP 2055) parsing v5 + v9 with template persistence.
- Active probes (ICMP echo, traceroute via nmap or native ICMP-TTL).
- Interface enumeration (libnl on Linux, netlink on Mac, equivalent on FreeBSD).
- Setuid-capable raw-socket helper for privileged operations.
- mDNS responder advertising `_packetsonde._tcp` service.
- TLS WebSocket server listening on a configurable port (default 7891) for remote clients.
- Pub/sub bridge: Redis events relayed to connected TLS clients (and vice versa for client commands).

### 5.4 Redis (existing, scoped)

Local Redis instance per agent. Two roles per agent:
- **Authoritative store** for that agent's observations.
- **Pub/sub bus** between agent and any connected client (local Redis client or remote TLS-bridged client).

Redis is not exposed to the network directly. All remote access goes through the agent's TLS server, which proxies Redis access. This keeps Redis ACL-free and avoids exposing a database port.

### 5.5 Threading model

**Agent:**
- Main thread: event loop, dispatch.
- Capture thread per active interface (libpcap is blocking).
- Probe pool: 4 worker threads handling pings and traceroutes.
- TLS server thread + per-connection coroutine (one async task per remote client).
- Redis thread (hiredis async via the main event loop).

**Editor:**
- Game thread: UE main loop. All BP runs here. All datastore reads from here happen on the game thread (`UPacketsondeWorldSubsystem` enforces this).
- Network thread: Redis client + TLS WebSocket clients. Inbound events queued onto the game thread for processing.
- Background tasks: periodic decay, accumulation updates, anomaly evaluation. Run on a UE `FRunnable` worker thread that posts results back to the game thread.

## 6. Service-Architecture Adapters and Extensibility

### 6.1 The premise

packetsonde started as a network-topology visualizer. The same spatial model — entities, containers, edges, hierarchical containment, accumulation over time — works for visualizing any system whose components have identity, relationships, and state. The user wants packetsonde to also serve as a visualization frontend for service architectures they actually run or operate: Elasticsearch clusters, Proxmox virtualization fleets, Kubernetes clusters, NetBox infrastructure inventories, Docker hosts, Consul service meshes, Hashicorp Nomad, AWS/Azure/GCP resource graphs, OPNsense and OpenWRT devices, Cisco/Juniper boxes via SNMP.

Each of these has its own conceptual taxonomy:
- **Elasticsearch**: cluster → index → shard → replica; cluster → node; cluster → role assignments.
- **Proxmox**: cluster → host → (VM | LXC container | storage pool | virtual network).
- **Kubernetes**: cluster → namespace → (pod | service | ingress | configmap | secret); cluster → node → pod; pod → container.
- **NetBox**: region → site → rack → device → interface; tenant → device; circuit → site.
- **Docker**: engine → container; engine → network; engine → volume.

These taxonomies overlap with packetsonde's `(Org × Metro)` territory model in some places (a Kubernetes node *is* a host with an IP and an ASN) and extend it in others (a Kubernetes pod has no IP of its own from outside the cluster, but it has identity and relationships within the cluster).

The design goal is a uniform extension pattern: an **adapter** is a pluggable component that ingests data from a service-toolset, translates it into packetsonde's data model, and declares any service-specific visual identity and inspector content needed.

### 6.2 The adapter contract

An adapter is a `UPacketsondeAdapter` UObject (C++ base class, BP-subclassable). It declares:

- **Adapter ID** — unique stable string (e.g. `"adapter.elasticsearch"`, `"adapter.proxmox"`, `"adapter.k8s"`, `"adapter.netbox"`).
- **Display name** — human-readable.
- **Capabilities** — `GameplayTagContainer`. Examples: `Adapter.Cap.Read`, `Adapter.Cap.Refresh`, `Adapter.Cap.Subscribe`, `Adapter.Cap.Annotate`, `Adapter.Cap.Command`.
- **Configuration schema** — a struct describing what the adapter needs (endpoints, credentials, refresh intervals).
- **Custom container types** it produces (`"K8sCluster"`, `"K8sNamespace"`, `"K8sPod"`, etc., as `ContainerSubtype` strings under `EContainerType::Custom`).
- **Custom node types** it produces (`"K8sService"`, `"NetboxRack"`, etc., as `EDeviceType::Custom` with subtype strings).
- **Visual archetype hints** — which procedural archetype family each entity should use, and any per-entity visual overrides.
- **Inspector extensions** — UMG widget classes the adapter contributes to the inspector for its entity types.

```cpp
UCLASS(BlueprintType, Blueprintable, Abstract)
class UPacketsondeAdapter : public UObject {
    GENERATED_BODY()
public:
    UFUNCTION(BlueprintNativeEvent, BlueprintCallable)
    FString GetAdapterId() const;

    UFUNCTION(BlueprintNativeEvent, BlueprintCallable)
    FString GetDisplayName() const;

    UFUNCTION(BlueprintNativeEvent, BlueprintCallable)
    FGameplayTagContainer GetCapabilities() const;

    UFUNCTION(BlueprintNativeEvent, BlueprintCallable)
    bool Initialize(const FAdapterConfig& Config);

    UFUNCTION(BlueprintNativeEvent, BlueprintCallable)
    void Refresh();

    UFUNCTION(BlueprintNativeEvent, BlueprintCallable)
    void Subscribe();          // for adapters that support live updates

    UFUNCTION(BlueprintNativeEvent, BlueprintCallable)
    void Shutdown();

    UPROPERTY(BlueprintAssignable) FOnAdapterEntityAdded   OnEntityAdded;
    UPROPERTY(BlueprintAssignable) FOnAdapterEntityUpdated OnEntityUpdated;
    UPROPERTY(BlueprintAssignable) FOnAdapterEntityRemoved OnEntityRemoved;
    UPROPERTY(BlueprintAssignable) FOnAdapterRelationship  OnRelationship;
    UPROPERTY(BlueprintAssignable) FOnAdapterError         OnError;
};
```

Adapters can be:
- **C++ subclasses** for performance-critical or library-heavy adapters (e.g. Elasticsearch using an existing C++ Elasticsearch client; SNMP using net-snmp).
- **BP subclasses** for HTTP-API-driven adapters that fit the BP HTTP node patterns (a Kubernetes adapter could be entirely BP using `HttpRequest` nodes against the K8s API).

### 6.3 Where adapters run

Adapters run in either:

- **The agent process** — when the adapter needs privileged access (raw sockets for SNMP via SNMP traps, kernel netlink for routing tables, packet capture). Agent adapters are C++.
- **The editor process** — when the adapter is HTTP-API-driven and unprivileged. Editor adapters can be BP. Examples: Kubernetes via API, Elasticsearch via HTTP, NetBox via REST API, AWS via SDK.
- **Both** — for adapters with privileged-and-unprivileged components (an SNMP adapter might need privileged trap reception in the agent and unprivileged poll-based queries in the editor).

The choice is made per adapter at config time. Most service-architecture adapters (K8s, ES, Proxmox, NetBox, AWS, Docker) are HTTP/REST and run in the editor.

### 6.4 Hierarchical containment

`FNetworkContainer` already supports parent/child relationships via `ParentContainerId` and `ChildContainerIds`. Adapters use this to model their natural hierarchies. Examples:

**Kubernetes:**
```
Container("k8s.cluster.prod-us-east")
├── Container("k8s.namespace.default")
│   ├── Container("k8s.pod.web-deployment-abc")
│   │   ├── Node("k8s.container.web-app")
│   │   └── Node("k8s.container.sidecar")
│   └── Container("k8s.service.web-svc")
├── Container("k8s.namespace.kube-system")
│   ├── Container("k8s.pod.coredns-xyz")
│   └── ...
└── Container("k8s.node.worker-3")            // physical/VM worker
    └── (cross-references pods scheduled here)
```

**Proxmox:**
```
Container("proxmox.cluster.lab")
├── Container("proxmox.host.pve1")            // physical host
│   ├── Container("proxmox.vm.100")           // KVM VM
│   │   └── Node(IP+OS visible to network discovery)
│   ├── Container("proxmox.lxc.200")          // LXC container
│   │   └── Node(IP+OS visible to network discovery)
│   └── Container("proxmox.storage.local-lvm")
└── Container("proxmox.host.pve2")
    └── ...
```

**NetBox:**
```
Container("netbox.region.us-west")
├── Container("netbox.site.dc-portland")
│   ├── Container("netbox.rack.r12")
│   │   ├── Node("netbox.device.sw-r12-01")   // switch
│   │   ├── Node("netbox.device.sw-r12-02")
│   │   └── Node("netbox.device.srv-r12-04")  // server
│   └── Container("netbox.rack.r13")
└── Container("netbox.site.dc-seattle")
    └── ...
```

`FNetworkContainer.ChildContainerIds` and `ChildNodeIds` (the latter implicitly via `MemberNodeIds` plus a containment-only flag) give the world subsystem everything it needs to walk a hierarchy. The territory-mode collapse model extends naturally: collapsing a Proxmox host hides its VMs; collapsing a Kubernetes namespace hides its pods.

### 6.5 Cross-adapter overlay

A node can carry identity in multiple frames at once. Examples:

- A Linux server discovered by network scan (`192.168.4.10`, MAC `aa:bb:...`) is *also* a Proxmox VM (`proxmox.vm.100`) is *also* a Kubernetes node (`k8s.node.worker-3`).
- An Elasticsearch data node is *also* a Proxmox VM is *also* an Ansible inventory entry.

These are layered identities on the same `FNetworkNode`, recorded via `FNetworkNode.AdapterIdentities`, a map keyed by adapter ID with adapter-specific identifier values:

```cpp
USTRUCT(BlueprintType)
struct FAdapterIdentity {
    UPROPERTY(BlueprintReadOnly) FString AdapterId;        // "adapter.k8s"
    UPROPERTY(BlueprintReadOnly) FString EntityKind;       // "node" | "pod" | "service"
    UPROPERTY(BlueprintReadOnly) FString EntityId;         // "k8s.node.worker-3"
    UPROPERTY(BlueprintReadOnly) TMap<FString, FString> Attributes;
};

// On FNetworkNode:
UPROPERTY(BlueprintReadOnly) TArray<FAdapterIdentity> AdapterIdentities;
```

Inspector tabs render adapter-specific information per identity. Visual identity routing (`BP_OrgArchetypeRouter`) considers all identities — a Proxmox host that's also a Kubernetes worker might display as a Proxmox host with a small Kubernetes overlay glyph.

### 6.6 Built-in adapters (V1 plan)

Each built-in adapter ships with a default config schema, an inspector tab UMG widget, and a recommended archetype mapping.

**Ship priority — Proxmox is the first adapter built.** Proxmox-first because: the HTTP API is well-defined and stable; the hierarchy is shallow enough to validate end-to-end (cluster → host → VM/LXC); the user runs a Proxmox lab to test against; and Proxmox VMs are *also* network hosts with their own IPs (ARP-discoverable by the agent), which immediately exercises the cross-adapter identity overlay (§6.5).

| Adapter | Ship priority | Lives in | Authentication | Polled / streamed |
|---------|---------------|----------|----------------|-------------------|
| **adapter.proxmox** | **1 (first)** | editor | API token, ticket | polled (cluster status every 30s) |
| **adapter.kubernetes** | 2 | editor | kubeconfig context | polled (every 15s) + watch (live) when supported |
| **adapter.elasticsearch** | 3 | editor | API key, basic auth, mTLS | polled (cluster health/state every 10s) |
| **adapter.netbox** | editor | API token | polled (every 5 min) |
| **adapter.docker** | editor or agent | unix socket / TCP | streamed (events API) |
| **adapter.consul** | editor | ACL token | polled + watch |
| **adapter.aws** | editor | IAM role / profile | polled (resource graph every minute) |
| **adapter.snmp** | agent (privileged) + editor | SNMPv3 USM | polled |
| **adapter.lldp** | agent (privileged via libpcap) | none | passive |
| **adapter.opnsense** | editor | API key | polled |
| **adapter.openwrt** | editor (ssh) or agent | ssh keys | polled |

V1 ships scaffolds and one fully-functional adapter (likely Kubernetes, since the BP-implementation pattern proves out the framework). Additional adapters land in V2+.

### 6.7 Adapter SDK / BP authoring path

To make BP-authored adapters approachable, the C++ side provides BP-callable helpers:

- `UFUNCTION(BlueprintCallable) static FNetworkNode MakeAdapterNode(...)` — factory for BP-callable node creation.
- `UFUNCTION(BlueprintCallable) static FNetworkContainer MakeAdapterContainer(...)` — factory for containers.
- `UFUNCTION(BlueprintCallable) static FNetworkLink MakeAdapterLink(...)` — factory for relationships.
- `UFUNCTION(BlueprintCallable) bool CommitToDataStore(const FAdapterEntityBatch& Batch)` — commit a batch of entities atomically.
- `UFUNCTION(BlueprintCallable) FAdapterEntityBatch BeginBatch()` — start a batch.

Plus HTTP request helpers and JSON parsing helpers that handle authentication tokens, retry, paging.

A BP author's typical adapter looks like: timer fires → BP graph builds an HTTP request to the service API → response parsed into adapter entities → `CommitToDataStore` called. The BP debugger steps through every transformation; the user sees exactly what the adapter is doing.

### 6.8 Adapter visual archetype declaration

Each adapter declares visual archetype mappings via a `UDataAsset`:

```
DA_KubernetesArchetypes:
    "k8s.cluster"   → archetype: "kCluster",      mesh: BP_K8sClusterMesh,   color: hue(220)
    "k8s.namespace" → archetype: "kNamespace",    mesh: BP_K8sNamespaceMesh, color: hue(180)
    "k8s.pod"       → archetype: "kPod",          mesh: BP_K8sPodMesh,       color: hue(140)
    "k8s.service"   → archetype: "kService",      mesh: BP_K8sServiceMesh,   color: hue(60)
    "k8s.node"      → archetype: "kNode",         mesh: BP_K8sNodeMesh,      color: hue(200)
    "k8s.container" → archetype: "kContainer",    mesh: BP_K8sContainerMesh, color: hue(160)
```

The `BP_OrgArchetypeRouter` consults the union of registered archetype maps when it routes an entity to a visual. Adapter-specific meshes can be procedural (Geometry Script generated) or hand-modeled.

### 6.9 Adapter configuration

Per-adapter config in `~/.config/packetsonde/adapters.json` (editor-side) and `agent/conf/adapters.<name>.toml` (agent-side, when the adapter runs there). Schema:

```json
{
  "adapters": [
    {
      "id": "adapter.elasticsearch",
      "instance": "lab-cluster",
      "enabled": true,
      "config": {
        "endpoint": "https://es.lab.local:9200",
        "auth": { "type": "apikey", "key": "AAAAB3..." },
        "verify_tls": true,
        "refresh_interval_sec": 10
      }
    },
    {
      "id": "adapter.kubernetes",
      "instance": "prod-us-east",
      "enabled": true,
      "config": {
        "kubeconfig": "~/.kube/prod",
        "context": "prod-us-east",
        "watch_resources": ["pods", "services", "nodes", "namespaces"],
        "refresh_interval_sec": 15
      }
    },
    {
      "id": "adapter.proxmox",
      "instance": "lab-cluster",
      "enabled": true,
      "config": {
        "endpoint": "https://pve1.lab.local:8006",
        "auth": { "type": "token", "user": "monitor@pve", "token": "abc..." },
        "refresh_interval_sec": 30
      }
    }
  ]
}
```

A user can run multiple instances of the same adapter (multiple K8s clusters, multiple ES clusters), each with its own configuration and namespace within the data model.

### 6.10 Inspector extension

When an entity belongs to an adapter, the inspector renders a tab per adapter identity. Each adapter contributes a `WBP_<AdapterId>InspectorTab` widget that knows how to render its specific data:

- Kubernetes pod tab shows: status phase, image, restart count, node assignment, owner controller, mounted volumes.
- Proxmox VM tab shows: state (running/stopped/paused), CPU/RAM allocations, disk images, network interfaces, snapshot list.
- Elasticsearch shard tab shows: state (started/initializing/relocating), primary/replica role, segment count, doc count, size on disk.
- NetBox device tab shows: rack U position, role, manufacturer/model, serial, asset tag, primary IP, interfaces.

The inspector picks up adapter tabs automatically via reflection — when an entity has an `FAdapterIdentity` for `adapter.X`, and the adapter has registered `WBP_XInspectorTab`, the tab appears.

### 6.11 Adapter commands

Adapters can offer commands surfaced in the action bar / function library. Examples:

- Kubernetes: "scale deployment", "drain node", "kubectl logs", "kubectl exec".
- Proxmox: "start VM", "shutdown VM", "migrate VM", "snapshot".
- Elasticsearch: "force merge index", "reroute shard".
- NetBox: "open in NetBox UI" (deep-link), "edit device".

Commands declare authorization requirements; adapters with `Adapter.Cap.Command` capability can offer them. The user's trust level (per-agent, per-adapter) gates which commands are runnable from the editor.

### 6.12 Cross-adapter relationships

Some relationships span adapters:
- A Kubernetes node *is* a Proxmox VM (the same machine).
- A NetBox device *is* a Proxmox host.
- An AWS EC2 instance *runs* a Kubernetes node.

The adapter framework supports cross-adapter linking via the `FAdapterIdentities` map on nodes plus explicit links. When an adapter discovers an entity that already exists (matched by IP, MAC, hostname, or explicit annotation), it appends its `FAdapterIdentity` rather than creating a new node.

A reconciliation pass (run on every adapter refresh) merges identities and emits cross-references. This is how the K8s + Proxmox + NetBox layers compose into a single consistent world.

### 6.13 Adapter render lenses

Aggregation lenses (§21.1) tint and highlight existing visuals — they don't change what's drawn. **Render lenses** are a separate primitive: they take over rendering for an adapter's entities entirely, with their own actor hierarchy, animations, and interaction model. A render lens is the right tool when an adapter's natural visualization is fundamentally different from packetsonde's `(Org × Metro)` territory metaphor.

#### 6.13.1 Why per-adapter render lenses

The territory model is well-suited to "destinations my packets reached." It's not the right model for showing the *internal structure* of a service architecture. A Kubernetes cluster's interesting story is namespaces / pods / services / scheduling, not which metro the cluster's master node sits in. An Elasticsearch cluster's interesting story is indices / shards / replication / cluster health, not Elasticsearch's GeoIP.

Each adapter can ship one or more render lenses that visualize its entities the way operators of *that* technology think about them. Switching to a render lens swaps out the visualization for the adapter's entities while leaving packetsonde's overall world (territories, edges, etc.) intact for everything else.

#### 6.13.2 The render lens contract

A render lens is a UObject (typically BP-subclassable) implementing `IPacketsondeRenderLens`:

```cpp
UINTERFACE(BlueprintType)
class UPacketsondeRenderLens : public UInterface { GENERATED_BODY() };

class IPacketsondeRenderLens {
public:
    UFUNCTION(BlueprintNativeEvent)
    FString GetLensId() const;                                    // "lens.elasticsearch.cluster-health"

    UFUNCTION(BlueprintNativeEvent)
    FText GetDisplayName() const;

    UFUNCTION(BlueprintNativeEvent)
    FString GetTargetAdapterId() const;                           // "adapter.elasticsearch"

    /** Decide whether this lens claims responsibility for an entity. */
    UFUNCTION(BlueprintNativeEvent)
    bool ClaimsEntity(const FAdapterIdentity& Identity) const;

    /** Spawn the actor(s) representing this entity in lens-space.
     *  Replaces the default territory/host visual. */
    UFUNCTION(BlueprintNativeEvent)
    void SpawnEntityVisual(UObject* WorldContext, const FAdapterEntity& Entity, FRenderLensSpawnResult& OutResult);

    /** Update the visual when entity data changes (state, counts, health). */
    UFUNCTION(BlueprintNativeEvent)
    void UpdateEntityVisual(const FAdapterEntity& Entity, AActor* ExistingActor);

    /** Despawn the visual when the entity goes away or the lens deactivates. */
    UFUNCTION(BlueprintNativeEvent)
    void DespawnEntityVisual(AActor* Actor);

    /** Optional: lens contributes its own edges / relationships not present
     *  in the data layer (e.g. "shard P0 is replicating to shard R0"). */
    UFUNCTION(BlueprintNativeEvent)
    void ProduceLensEdges(const FAdapterEntityBatch& Batch, TArray<FLensEdge>& OutEdges);

    /** Optional: lens contributes layout hints — relative positions within
     *  a parent container. The render system applies them. */
    UFUNCTION(BlueprintNativeEvent)
    bool LayoutChildren(const FGuid& ParentContainerId, TArray<FLensChildLayout>& OutLayouts);
};
```

The lens lives in the editor process, claims specific entity types via `ClaimsEntity`, and owns spawn/update/despawn for those. It can spawn arbitrary actors — usually BP actors derived from common base classes — and drive animations through them.

#### 6.13.3 Composition with the territory model

Multiple render lenses can be active simultaneously. Activation is per-adapter-instance. Composition rules:

- The world subsystem maintains a per-entity "owner lens" pointer. When the user activates a render lens, every entity it claims is reassigned to that lens. The lens spawns its visual; the default territory/host visual despawns.
- Entities a lens does NOT claim continue to render via the default territory model.
- An adapter can have multiple lenses — the user picks which is active. Default is "off" (territory model claims everything).
- Lens spawns can place actors inside an existing parent container's volume. The territory super-node platform gets a "drilled-in" view: zoom into a Kubernetes cluster's territory and you see the K8s render lens's namespaces and pods inside it.
- Edges between adapter entities and external entities (e.g. a K8s pod's outbound traffic to an external IP) keep packetsonde's normal edge rendering, retargeting endpoints to whatever the lens spawned.

#### 6.13.4 Animation drivers

A render lens drives animation from adapter-specific data, polled or streamed. Examples:

- **Elasticsearch** — cluster health (green/yellow/red) animates the cluster super-node's ambient lighting; index task data (indexing rate, search rate) animates per-index pulse rates; shard relocation events animate a visible shard glyph traveling from source node to dest node; primary/replica role differences drive shape and color.
- **Kubernetes** — pod phase (Pending/Running/Succeeded/Failed) drives pod state animations; deployment rollouts animate as new pods materializing while old ones fade out; node pressure animates the node mesh straining; service endpoints render as arrows pulsing from service to selected endpoint pods.
- **Proxmox** — VM state (running/stopped/paused) drives interior lighting; resource utilization (CPU, RAM, disk I/O) drives fluid-level visualizations; live migration animates a VM moving between hosts.
- **NetBox** — rack diagrams render in proper 3D rack-unit footprints; cabling renders as physical wires between port locations; rack power draw animates the rack's ambient glow.

Animation primitives provided by the engine:
- **Niagara** for particles, ribbons, sustained effects.
- **UE5 timelines** in BP for keyframed transitions.
- **Material parameter scalars/vectors** updated by the lens for shader-driven effects.
- **Sequencer** for cinematic-quality scripted sequences (e.g. cluster shutdown choreography).

#### 6.13.5 Worked example: Proxmox lens (first to ship)

Proxmox is the first adapter and gets the first polished render lens. The "resource utilization" lens treats hosts as physical buildings, VMs and LXC containers as rooms inside, and animates resource pressure as physically-meaningful fluids and lighting.

**Visual layout:**
- Cluster — a wide foundation slab on the world floor, sized by host count, with the cluster name on a banner along one edge.
- Host — a multi-story building rising from the cluster slab. Number of stories ∝ resource capacity (CPU cores + RAM tier). Roof color reflects host status (green = online, amber = under maintenance, red = offline / unreachable).
- VM (KVM) — a room inside its host. Width ∝ CPU allocation. Height ∝ RAM allocation. Visible through translucent host walls.
- LXC container — a smaller, distinct-shape room (more cubic, less ornate than KVM rooms) inside the host, signaling lighter-weight virtualization.
- Storage pool — a cylindrical silo attached to the host. Fill level ∝ used / total capacity. Tinted by storage type (LVM blue, ZFS green, NFS amber, Ceph purple).
- Virtual network (vmbr0, etc.) — a colored corridor / pipe passing through hosts that share the bridge.

**Animations driven by Proxmox cluster + per-host APIs:**
- VM state — running rooms emit a soft glow; stopped rooms are dim; paused rooms pulse slowly.
- CPU usage — fluid level inside the room rises with CPU pressure (0–100% maps to floor → ceiling). Color shifts from blue (low) → amber (mid) → red (>90% sustained).
- Memory pressure — overlaid mist density inside the room. Heavy mist when memory > 85%.
- Disk I/O — animated streams between the VM room and the connected storage silo. Throughput ∝ stream brightness and speed.
- Live migration — visible animation: source room fades down while a "ghost" room materializes in the destination host, then the ghost solidifies and the source disappears. Trail of light follows the path.
- Backup running — the room's roof briefly opens and a beam of light extracts to the backup target storage silo.
- Snapshot taken — a brief flash + a small floating clone-glyph appears beside the room, persisting until the snapshot is removed.
- Cluster quorum loss — all host roofs flash red in unison; affected hosts dim.

**Data drivers:**
- `/api2/json/cluster/status` poll every 30s — cluster membership, quorum state, host online/offline.
- `/api2/json/cluster/resources?type=vm` poll every 10s — per-VM cpu/mem/disk/net, status.
- `/api2/json/nodes/<node>/status` poll every 10s when the user has selected a host — load average, uptime, memory pressure, root FS usage.
- `/api2/json/nodes/<node>/qemu/<vmid>/rrddata` poll every 30s for selected VMs — historical performance for inspector graphs.
- `/api2/json/cluster/tasks` poll every 5s — running tasks (migrations, backups, snapshots) drive the animations above.

**Inspector tabs when an entity is selected:**
- Cluster: name, version, host count, total cores, total RAM, total storage, quorum state, recent task summary, ceph health if Ceph is in use.
- Host: hostname, kernel, uptime, CPU model + cores, RAM total/used, swap, root FS used/total, hosted VMs/LXCs, IPMI/BMC status if available.
- VM: VM ID, name, OS type, CPU + RAM allocation, current usage, attached disks (per-disk size + storage pool), network interfaces, snapshot list, current task (if any).
- LXC: container ID, OS template, CPU + RAM allocation, current usage, mount points, network interfaces, recent restart history.
- Storage pool: type, total/used, attached hosts, recent I/O rates, content categories (images, ISO, backups, vztmpl).

**Per-entity actions surfaced in the action bar when the lens is active:**
- VM actions: "start", "shutdown", "stop (force)", "reboot", "migrate to…", "snapshot now", "clone…", "console…".
- LXC actions: similar to VM where applicable.
- Host actions: "enter maintenance", "exit maintenance", "reboot host", "open shell".
- Cluster actions: "refresh resources", "force resync".

Authorization gating per the user's trust level on the agent that hosts the adapter — destructive actions (stop, reboot, migrate) require `owner` trust; read-only and snapshot actions are available at `operator` trust.

**Cross-adapter overlay in this lens:** when a Proxmox VM has a network IP that's also been observed by network discovery (ARP, traceroute, NetFlow), the VM room shows a small sub-glyph indicating "this is also network-visible." Clicking the glyph navigates to the network view of that host. Similarly, when a VM also carries a `adapter.kubernetes` identity (a K8s worker on Proxmox, common deployment), the room gets a Kubernetes overlay glyph.

#### 6.13.6 Worked example: Elasticsearch lens

Per the user's specification: nodes are containers of indices, indices are containers of shards, with animations from cluster health and task data.

Visual layout:
- Cluster — a circular base disc on the world floor, sized by node count, color by cluster health (green/yellow/red).
- Each ES node — a vertical stack ("rack of indices") rising from the cluster disc. Sized by node role (master / data / coordinating / ingest), tinted by node load.
- Each index inside a node — a horizontal slab, stacked vertically by creation time. Slab thickness ∝ document count, color by index health.
- Each shard on an index — a small glyph attached to the index slab. Primary shards solid; replica shards semi-translucent. Color by shard state (started / initializing / relocating / unassigned).
- Active relocation — animated shard glyph traveling along an arc from source index slab to destination index slab.
- Active task (indexing/search) — pulse animation along the affected index slab's edges; intensity ∝ task rate.
- Cluster health change — a wave of color propagates through the cluster disc on transition.

Data drivers:
- `_cluster/health` poll every 5s — drives cluster disc color, overall pulse rate.
- `_cluster/state` poll every 15s — drives node and index/shard layout.
- `_tasks` poll every 2s when the user has selected the cluster — drives per-index task animations.
- `_cat/indices?h=index,docs.count,store.size,health` poll every 30s — drives slab dimensions.

Inspector when an entity is selected:
- Cluster: health summary, node count, total docs, total size, pending tasks, recent recovery events.
- Node: role, JVM heap, disk usage, hosted indices, load average.
- Index: doc count, size, shard count, primaries+replicas, refresh interval, recent task summary.
- Shard: state, segments, doc count, recovery progress (if relocating).

Per-entity actions surfaced in the action bar when the lens is active:
- "Force merge this index" — calls `_forcemerge`.
- "Reroute this shard" — calls `_cluster/reroute`.
- "Open Kibana for this index" — deep-link.

#### 6.13.7 Worked example: Kubernetes lens

Visual layout:
- Cluster — a square base platform with the cluster name as a banner.
- Namespaces — colored zones tiled across the cluster platform. Sizing by resource count.
- Pods — small upright cylinders within their namespace zone. Color by phase. Height ∝ resource usage (CPU/memory blend).
- Deployments / StatefulSets — visible as a tinted boundary around a group of pods (the controller's children).
- Services — translucent dome over the pods that match the service's selector. Lines from the dome's apex to each backing pod.
- Nodes (workers) — appear as a parallel rendering: a row of physical-host shapes adjacent to the cluster platform, with translucent lines connecting pods to their host.
- Ingress — gateway shape at the cluster edge with arrows showing external traffic distribution.

Animations:
- Pod creation: pod cylinder fades up from the floor.
- Pod termination: cylinder fades down.
- Rolling update: new pods materialize while old pods animate down in coordinated waves.
- Pod restart: the pod cylinder briefly red-flashes.
- Node drain: node shape's pods glow then animate to their new hosts.
- HPA scale-up: visible "stamping" of new pods.

Data drivers:
- `watch` API streams keep state live with no polling overhead.
- Resource usage from metrics-server is polled every 10s.

#### 6.13.8 Lens UI

In the action bar / lens picker (`L` key by default), the user sees a list of available render lenses grouped by adapter:

```
Render lenses
  ◯ packetsonde — territory (default)
  ◯ packetsonde — hop (debug)
  ▸ adapter.elasticsearch — lab-cluster
      ◯ Cluster health
      ◯ Shards & relocations
  ▸ adapter.kubernetes — prod-us-east
      ◯ Pod fleet
      ◯ Service routing
      ◯ Node pressure
  ▸ adapter.proxmox — lab-cluster
      ◯ Resource utilization
      ◯ Migration view
```

Selecting a lens activates it for that adapter instance. Multiple adapters' lenses can be active simultaneously (each adapter's entities use that adapter's chosen lens; everything else stays in territory mode). The lens pill in the upper-left of the HUD shows currently active lenses.

#### 6.13.9 Lens authoring

Render lenses are a heavyweight feature — a fully-authored lens is a significant chunk of work. The framework supports both:

- **Quick lenses** — BP-only, layout-and-color only, no custom animations. A user can author one in an afternoon: claim the adapter's entities, spawn a basic mesh per entity type, position children inside parents.
- **Full lenses** — the polished examples above. Substantial BP work plus possibly Niagara/Sequencer assets. Shipped with the adapter.

The framework explicitly does not require fully-polished lenses for V1 of any adapter. An adapter can ship without a render lens at all, in which case its entities visualize via the default territory model with adapter-specific archetype hints (§6.8).

#### 6.13.10 Performance considerations

Render lenses can spawn many actors (a Kubernetes cluster might have thousands of pods). The render-lens framework supports level-of-detail similarly to the territory LOD policy:

- Per-lens LOD policy (BP-implemented) can collapse subgroups under load (e.g., collapse a deployment with 50 pods into one "deployment unit" glyph at distance).
- Particle-based rendering for sub-entities at distance (a thousand far-away pods become a single Niagara particle system rather than a thousand actors).
- Lens-specific render budgets configurable per adapter instance.

#### 6.13.11 Adapter command integration

Render lenses can offer commands per entity (the action bar / right-click menu populates from the active lens for the selected entity). Commands invoke the adapter (§6.11). This is how the user goes from "I see this pod is failing" to "drain its node" without leaving the lens.

### 6.14 Adapter testing

Each adapter ships with a fixture set of recorded API responses (`agent/tests/fixtures/<adapter>/`) for offline testing. Adapter unit tests run against fixtures; integration tests run against ephemeral live services where available (kind for K8s, a small Proxmox test cluster, etc.).

Render lenses ship with their own visual regression tests: scripted scenarios (cluster health degraded, shard relocation in progress, deployment rollout) captured as deterministic frames and compared against golden images.

## 7. Multi-Agent Remote Connectivity

### 7.1 Why

Real users of packetsonde frequently want more than one vantage point:

- **Personal** — desktop at home, laptop on the road, vacation home, parent's network.
- **Professional** — multiple offices, multiple campuses, multiple lab segments.
- **Research** — VMs across cloud regions to characterize how an anycast service routes globally.

Single-vantage observations don't reveal anycast (you can't see a single IP being served from multiple metros if you're always in one metro). They don't reveal route diversity (the path home → AWS via Comcast may be entirely different from office → AWS via your campus uplink). They don't help with audit at scale.

### 7.2 Connection model

Each `packetsonde-agent` instance owns a private Redis. Each agent advertises itself via mDNS and accepts TLS WebSocket connections from authorized clients on a configured port (default `7891`).

A single packetsonde editor / client instance can connect to:
- Zero agents (offline mode — view persisted state only).
- One agent (local-only typical usage).
- Multiple agents simultaneously.

Connections are independent. Each connection has its own TLS session, its own subscription set, its own pub/sub stream. The world subsystem aggregates state across all connected agents.

### 7.3 Per-agent namespacing of state

Every entity ID is namespaced by the originating agent. The actual GUIDs the agent generates are globally unique, so namespacing is needed for *attribution*, not collision avoidance. The world subsystem tags each entity with `OriginatingAgentId`, an opaque identifier per agent (the agent's TLS public key fingerprint, see §7).

`bIsSelf` and `bIsGateway` are per-agent, not global. The world contains one Home territory per connected agent. They share a single equirectangular map projection but each has its own anchor.

A remote agent's data does not pollute another agent's data. Two agents that observe the same external IP report two separate observations; the world subsystem can choose to merge them (anycast registry deduplicates by IP across agents) or keep them separate (territory membership is per-agent).

### 7.4 Visualization with multiple agents

Each connected agent gets its own Home territory, drawn at the agent's gateway metro (or origin if unresolved). Other territories — external Orgs the agent has observed — appear at their geographic positions. Two agents that have both observed Cloudflare LAX render edges from each agent's Home to the same Cloudflare LAX territory super-node, but those edges are tinted by the originating-agent color so the user can tell which agent saw which path.

Toggling an agent off in the connection panel removes its Home and its uniquely-attributable edges. Shared territories (those observed by multiple agents) remain as long as at least one agent is connected.

### 7.5 Data flow

```
remote agent's observation        client editor process
        ▼                               ▲
remote agent's local Redis              │
        ▼                               │
remote agent's TLS WebSocket server     │
        ▼                               │
[TLS, mTLS-authenticated channel] ──────┤
                                        │
client's incoming event handler ◀───────┘
        ▼
event queued onto game thread
        ▼
UPacketsondeWorldSubsystem applies the event,
tagging entities with OriginatingAgentId,
and broadcasts BP-visible delegates.
```

A symmetric command path lets the client request actions on a remote agent (run a traceroute from that vantage, ping a host from that vantage). Commands are signed by the client and validated by the agent before execution; see §7.

### 7.6 Agent configuration

Agents are configured in `~/.config/packetsonde/agents.json` (per-user). Schema:

```json
{
  "agents": [
    {
      "name": "home",
      "host": "127.0.0.1",
      "port": 7891,
      "fingerprint": "ed25519:abcd1234...",
      "auto_connect": true,
      "trust_level": "owner"
    },
    {
      "name": "office-edge",
      "host": "edge.office.example.com",
      "port": 7891,
      "fingerprint": "ed25519:9876fedc...",
      "auto_connect": false,
      "trust_level": "operator"
    },
    {
      "name": "vacation-home",
      "host": "vh.dyn.example.com",
      "port": 7891,
      "fingerprint": "ed25519:5566778899aa...",
      "auto_connect": false,
      "trust_level": "operator"
    }
  ]
}
```

`trust_level` is one of `owner` (full read+command), `operator` (read+limited commands like ping/traceroute), `observer` (read-only).

### 7.7 Connection panel UI

Settings → Agents shows the list. Per agent: name, host:port, fingerprint, last-seen, status (connected / disconnected / pairing-pending), trust level, auto-connect toggle, manual connect/disconnect button.

A separate "Discover agents" button launches the mDNS browse and signed-broadcast protocols (§8).

### 7.8 Failure modes

- **Network partition** — connections retry with exponential backoff (1s, 2s, 4s, ..., capped at 60s). Disconnected agents' data persists in the editor's view (snapshot from last connection) until the user explicitly clears it.
- **Agent restart** — agents persist Redis to disk. After restart, reconnecting clients receive the post-restart state. Anomaly detection notes "agent restarted at <time>" as an event.
- **Trust loss** — if an agent's TLS cert no longer validates against its fingerprint (key rotation without prior coordination), the connection is refused and a "trust expired" event surfaces. The user can re-pair via the connection panel.

## 8. Security and Trust Model

### 8.1 Threat model

We protect against:

- **Eavesdropping on the network path** between editor and remote agent.
- **Active interception / MITM** between editor and remote agent.
- **Unauthorized clients** connecting to an agent and accessing observed network data.
- **Unauthorized agents** posing as a trusted agent.
- **Replay** of recorded commands.

We do *not* protect against:

- **Malicious agent code itself** (the user runs the agent on their own hardware; if it's compromised, they have bigger problems).
- **OS-level compromise of the editor host.**
- **Side-channel observation** (timing, bandwidth) of an authenticated TLS session.

### 8.2 Identity primitives

Each agent and each editor client owns a long-lived **Ed25519 keypair**. Key generation happens once at first run; private keys are stored in OS-appropriate secure storage:

- macOS: Keychain, accessed via `Security.framework`.
- Linux: `~/.local/share/packetsonde/keys/` with mode 0600. Optional libsecret/kwallet integration for desktop environments that have it.
- Windows: DPAPI-protected files in `%APPDATA%\packetsonde\keys\`.

Public keys derive a **fingerprint**: lower-case hex SHA-256 of the public key's raw bytes, prefix `ed25519:`. Example: `ed25519:abcd1234...`.

### 8.3 Transport: TLS 1.3 with mutual auth

Agent ↔ client communication uses TLS 1.3. Self-signed X.509 certs derived from the long-lived Ed25519 keypairs (the cert binds the key fingerprint to a hostname/IP for SAN matching).

Mutual TLS: the agent's TLS server requires a client cert; the client requires the server cert. Both ends validate the peer's cert against the locally-stored expected fingerprint. The validation logic short-circuits the standard PKI chain — we don't trust public CAs, we trust *this specific fingerprint*.

This is functionally TOFU+pinning at the transport layer.

### 8.4 Application-layer signing

Some command messages must additionally be signed by the client at the application layer. Examples: "run a traceroute to 8.8.8.8", "kill an active probe", "modify trust level". The agent verifies the signature before executing.

This redundancy with mTLS is intentional: it means a recorded session cannot be replayed if the client's keys later change, and it lets the agent log who specifically issued each command (if multiple clients with multiple keys connect).

Signing scheme: Ed25519 over a serialized command payload that includes a monotonic nonce + timestamp. Replay protection.

### 8.5 Wire protocol

WebSocket over TLS as the carrier. JSON messages framed by WebSocket frames. Binary opcode for large blobs (e.g. pcap exports), text opcode for normal messages.

Why WebSocket and not raw TLS framing? Two reasons:
1. Standardized framing means existing libraries handle low-level bits.
2. JSON message inspection is easy during development.

A future v2 may move hot-path streaming to a binary CBOR or MessagePack channel for efficiency. Not v1.

### 8.6 Encrypted-at-rest

Agent-side: Redis dumps (RDB) are not encrypted by default. For deployments where this matters, the agent supports a passphrase-protected RDB via `redis-cli` config; the agent has a `--encrypt-rdb` flag wiring this up.

Client-side: persisted UI state (recent searches, action-bar bindings) is not sensitive; stored in plain JSON. The trust list (`agents.json`) contains only public fingerprints and is not sensitive.

### 8.7 Privacy

The user's network observations live in *their* Redis on *their* hardware. packetsonde never phones home, has no telemetry, and emits no traffic outside the user's configured agents.

Users explicitly opt in to any data export (session recording, anycast registry export, future cross-user pooling).

## 9. Discovery and Pairing

Two parallel mechanisms. mDNS for the typical case; signed broadcast for harder networks.

### 9.1 mDNS / DNS-SD

The agent advertises a service of type `_packetsonde._tcp.local`. TXT record fields:

- `version=<semver>`
- `fingerprint=<ed25519:hex>`
- `name=<friendly-host-name>`
- `cap=<comma-separated-capabilities>` (e.g. `read,probe,capture`)

The client's "Discover agents" action runs an mDNS browse for that service type. Discovered agents appear in the discovery panel with their friendly name, fingerprint, and capabilities.

Library choices:
- **macOS:** native Bonjour (`dns_sd.h`). Already on the system.
- **Linux:** Avahi client library. Standard on most distros.
- **Windows:** Bonjour Print Services (Apple) or built-in mDNS in Win10+.
- **Cross-platform fallback:** a single-file mDNS library (e.g., `mjansson/mdns`) embedded if platform native isn't available.

We don't reinvent mDNS. We integrate.

### 9.2 Signed broadcast (for non-mDNS networks)

mDNS isn't available everywhere — corporate networks may filter multicast, some routers don't bridge mDNS across VLANs. Signed broadcast is a fallback.

Protocol:

1. The client constructs a **discovery beacon**:
   ```
   Magic:    "psonde-disco-v1"
   ClientPub: <Ed25519 public key>
   Nonce:    <16 bytes random>
   Timestamp: <UTC seconds>
   Sig:      Ed25519(ClientPriv, Magic || ClientPub || Nonce || Timestamp)
   ```
2. The client UDP-broadcasts the beacon to `255.255.255.255:7892` (and to all configured interfaces' broadcast addresses; IPv6: `ff02::1`).
3. Agents on the broadcast domain receive the beacon. Each agent:
   - Validates the magic and timestamp (must be within 30s of agent's clock to prevent replay).
   - Verifies the signature against `ClientPub`.
   - Constructs a **discovery reply**:
     ```
     Magic:    "psonde-disco-r-v1"
     AgentPub: <Ed25519 public key>
     AgentName: <friendly name>
     Capabilities: <bitmask>
     Port:      <TLS port>
     Nonce:    <copy of client's nonce>
     Sig:      Ed25519(AgentPriv, all of the above || ClientPub)
     ```
   - Sends the reply via UDP unicast to the source IP and port of the client's beacon.
4. The client validates each reply (signature, nonce match) and surfaces the agent in the discovery panel.

The beacon's `ClientPub` field is the trust seed: when the client offers to add the agent, it shows the agent's fingerprint AND the fact that the agent successfully validated the client's signature. The user confirms.

### 9.3 Salt/automation deployment scenario

The motivating scenario: an organization has dozens of packetsonde-agent instances deployed via Salt, Ansible, or Puppet across campus subnets. The user has admin rights but doesn't know the agents' fingerprints individually.

With signed broadcast, the user can browse to each subnet from their workstation and discover the local agents. The user adds them one at a time (or batch-adds with a confirmation dialog showing all fingerprints). Salt-deployed agents share a common `cap` profile that the user can recognize, simplifying decisions.

Alternatively, the deployment automation can pre-write the fingerprints into the user's `agents.json` via a config-management drop. Then the discovery step is just confirming the agents are reachable.

### 9.4 Pairing UX

The discovery panel shows:

```
┌─ Discover Agents ─────────────────────────────────────────┐
│ Source ▼                                                  │
│ [✓] mDNS browse                                           │
│ [✓] Signed broadcast (UDP 7892)                           │
│                                                           │
│ Found 5 agents:                                           │
│                                                           │
│ ┌───────────────────────────────────────────────────────┐ │
│ │ home-router                                           │ │
│ │ 192.168.1.1:7891  ed25519:abcd1234...  cap: r,p,c     │ │
│ │ trust: NEW   [ Add ▼ ]                                │ │
│ └───────────────────────────────────────────────────────┘ │
│ ┌───────────────────────────────────────────────────────┐ │
│ │ rack4-mon                                             │ │
│ │ 10.0.4.42:7891  ed25519:9876fedc...   cap: r          │ │
│ │ trust: TRUSTED  [ Disconnect ]                        │ │
│ └───────────────────────────────────────────────────────┘ │
│ ...                                                       │
└───────────────────────────────────────────────────────────┘
```

Per-agent actions:
- **Add** — opens a confirmation dialog: "trust this agent? fingerprint: ed25519:...". Choose trust level (owner / operator / observer). Saves to `agents.json`.
- **Connect / Disconnect** — manual control.
- **Remove** — drops from `agents.json`.

A first-launch onboarding bumps the user through this if no agents are configured.

### 9.5 Out-of-band pairing

For paranoid scenarios, the agent supports an out-of-band pairing token:

```
$ packetsonde-agent --print-pair-token
psonde-pair: 9z3a-bh4f-72mq-...
```

The user types the token in the client's pairing dialog. The token encodes the agent's fingerprint + a single-use challenge. This bypasses discovery entirely — useful when the agent is behind NAT or on a network where neither mDNS nor signed broadcast work.

## 10. C++ / Blueprint Boundary

This is a hands-on visual-debuggable project. The split is explicit and documented.

### 10.1 Principles

- **C++ owns data and integration.** Anything that talks to OS APIs, the network, the data layer, or the cache lives in C++. Performance-critical loops (BFS, geometry, parsing) live in C++.
- **Blueprint owns visuals, interactions, and policy.** Anything you'd want to see step-by-step in a debugger when it goes wrong lives in BP. Anything you'd want to tweak without a rebuild lives in BP.
- **Every C++ datatype is `BlueprintType`-exposed.** No private structs that BP has to copy or mirror.
- **Every read pattern has a `BlueprintCallable` accessor.** BP doesn't traverse `TMap`s or `TArray`s directly through opaque handles; the world subsystem returns concrete copies or const refs.
- **Every event has a multicast delegate.** BP listens to data changes via `UPROPERTY(BlueprintAssignable)` delegates on the world subsystem.

### 10.2 What is C++

| Layer | Examples |
|-------|----------|
| Data structs | `FNetworkNode`, `FNetworkLink`, `FNetworkContainer`, `FOrgIdentity`, `FMetroDescriptor`, `FAnycastEntity`, `FNetworkFlow` |
| Datastore + persistence | `UPacketsondeDataStore` (game-instance subsystem), Redis client, RDB sync |
| Inference | metro / org / anycast resolution namespaces |
| Adapter integration | NetFlow listener stub, traceroute orchestration request/response, Redis ↔ entity translation |
| Remote agent transport | TLS WebSocket client, mTLS handshake, mDNS browse, signed-broadcast |
| Heavy compute | BFS, force-directed layouts (if needed), batched edge geometry, hostname airport-code parser |
| Cache singletons | IATA airport table, country flag texture cache, archetype mesh cache |
| World subsystem | `UPacketsondeWorldSubsystem` — the BP API surface |

### 10.3 What is Blueprint

| Layer | Examples |
|-------|----------|
| Actor logic | `BP_TerritoryPlatform`, `BP_HostMember`, `BP_Edge`, `BP_FlagBillboard`, `BP_SplashBobber`, `BP_AnomalyFlare` |
| UMG widgets | every panel — `WBP_Inspector`, `WBP_CommandPalette`, `WBP_ActionBar`, `WBP_QueueMonitor`, `WBP_FilterToolbar`, `WBP_Settings`, `WBP_Splash`, `WBP_DiscoveryPanel` |
| Mode state machine | `BP_ModeStateMachine` — territory ↔ hop, expand/collapse, focus modes |
| Camera | `BP_OrbitCamera`, `BP_FlyToCamera`, `BP_FrameWorldCamera` |
| Layout policy | `BP_TerritoryLODPolicy`, `BP_AccumulationVisualScaler` |
| Visual identity routing | `BP_OrgArchetypeRouter` — given Org+Role, return mesh+material+color |
| Forensics overlays | `BP_LensByOrg`, `BP_LensByRole`, `BP_LensByDevice`, `BP_LensByRecency`, `BP_LensByAnomaly` |
| Animation curves | timeline-driven transitions in BP |
| Splash sequence | `BP_SplashController` |
| Discovery / pairing UX | `BP_DiscoveryFlow`, `BP_PairingDialog` |

### 10.4 The contract

C++ side guarantees:
1. Every datatype is BP-readable.
2. Every read pattern has a BP-callable accessor on `UPacketsondeWorldSubsystem`.
3. Events that BP needs to react to are `BlueprintAssignable` multicast delegates.
4. C++ never positions actors directly in territory mode — it produces target positions in the data layer (`Container.Position`, `Node.MetroId`); BP-driven actors observe data changes and animate themselves.
5. C++ never instantiates a visualization actor directly — it provides factories that BP can override.

BP side guarantees:
1. All visual choices (mesh, material, color, scale, animation, label) live in BP.
2. All UMG widgets are BP-implemented (deriving from C++ base classes only for binding helpers).
3. All input is routed through Enhanced Input action mappings, dispatched to BP graphs.
4. All policy decisions (LOD, mode toggle, layout fitting) live in BP.

### 10.5 Why this split

- BP debugger can step every frame's worth of visual decision-making.
- Hot-reload editing without C++ build cycles for the things we change most.
- Adapter/data bugs are rare and well-isolated; visual/UX bugs are frequent and now BP-debuggable.
- C++ stays clean and testable; doesn't accumulate band-aid fixes for UI issues.

## 11. Third-Party Wheels (What We Don't Reinvent)

Explicit list of where we lean on existing libraries, plugins, and patterns.

### 11.1 UE5 plugins / engine modules

- **Common UI** — UI framework. Used for layered UI (modal vs non-modal panels), focus management, input routing across layers, keybinding management. Saves us from rewriting all of that.
- **Enhanced Input** — modern input mappings. Used for all keyboard/gamepad/mouse routing. Action contexts let mode switches enable/disable groups of bindings cleanly.
- **GameplayTags** — hierarchical tag taxonomy. Used for entity categorization (e.g. `Org.Role.Hyperscaler`, `Anomaly.NewMetro`, `Lens.ByOrg`, `Capability.Ping`, `Capability.Capture`). BP nodes consume tags directly; new tags don't need C++.
- **Niagara** — particle effects. Used for flow packets traveling along edges, splash ripples, anomaly flares, accumulation glow. Replaces the previous procedural-mesh-per-flow approach.
- **Geometry Script** — runtime procedural mesh generation. Used for generating archetype variants (citadel sub-towers, mesh lattice density, spire height) at runtime based on Org metadata, rather than hand-modeling every variant.
- **Subsystems** — `UEngineSubsystem`, `UGameInstanceSubsystem`, `UWorldSubsystem`, `ULocalPlayerSubsystem`. Used for the world subsystem (per-world game-thread API surface), game-instance subsystem for per-process state (datastore), local-player subsystem for per-user UI state.
- **Async loading / soft refs** — for visual identity assets that load lazily as territories appear.
- **JSON / HTTP / WebSockets module** — built-in. Used for config loading, agent communication.
- **HTTP / SSL / OpenSSL bindings** — built-in. Used for TLS transport.

### 11.2 Third-party C++ libraries (agent + editor)

- **libpcap** — packet capture. Already in agent.
- **libnl** — Linux netlink for routing tables, interface state. Already in agent.
- **OpenSSL** — TLS transport, X.509 cert handling, Ed25519 signing. UE bundles a version; agent links its own.
- **hiredis** (or **cpp_redis**) — Redis client for the agent. Async with libuv loop. Already in agent.
- **nlohmann::json** — JSON parsing for config files. Header-only; agent uses it. Editor uses UE's built-in JSON.
- **Avahi client / Bonjour / mjansson-mdns** — mDNS browsing/responding per platform. We pick what's available; we don't write an mDNS implementation.
- **libwebsockets** (agent) — TLS WebSocket server. Battle-tested, mature.
- **libuv** — event loop in agent for async networking. Standard.
- **nmap** — invoked as subprocess for traceroute. Existing pattern.

### 11.3 What we choose NOT to use (and why)

- **Mass framework (UE5)** — entity/component/system. Overkill for a few thousand network nodes; UE Actors + lightweight `UStruct`s are fine. Adds learning curve without commensurate benefit.
- **gRPC** — heavier than WebSocket-JSON for our scale, adds proto-gen step. Reconsider in v2 if message volume warrants.
- **WireGuard for transport** — more secure but operationally heavier than TLS for LAN-scale use. mTLS gives equivalent security at our threat model.
- **Redis Cluster / Sentinel** — distributed Redis is overkill. Each agent has its own local Redis.
- **Common Conversation / Common Save / Common UI Editor extensions** — Common UI core is what we want; the higher-level extensions add scope we don't need.

### 11.4 Configuration data we ship

- **IATA airport reference table** (~200 entries) — `agent/conf/iata-airports.json`. Reference data, we maintain it.
- **Curated Org metadata** — `agent/conf/asn-orgs.json`. Hand-curated catalog of major orgs with role taxonomy, color, archetype, state-aligned flag. Open to community contributions; we maintain it.
- **Country flag PNGs** — `assets/flags/<iso2>.png`, 254 files. Public-domain or CC-licensed flag assets.

## 12. Splash and Launch Experience

### 12.1 Brand mark

A wireframe sphere — the "sonde" — falls into a horizontal plane of monospace `0`s and `1`s. The plane ripples on impact. Below the splash, the wordmark `packetsonde · a navigable view of your Internet` appears in lowercase monospace.

The visual is designed to read as: an instrument descending into the substrate, taking a measurement, becoming part of the world.

### 12.2 Splash sequence (BP-driven)

`BP_SplashController` is a single UMG widget. It owns a timeline that drives every frame of the sequence. Asset dependencies: one mesh (the sonde wireframe), one font (monospace), one Niagara system for the digit plane and ripple, one shader for the wireframe edges.

| Time | Event |
|------|-------|
| 0–500ms | Black screen. Single monospace cursor blinks once at center. |
| 500–1500ms | Sonde wireframe sphere descends from off-camera. Slow motion. Solid green silhouette against black. |
| 1500–1700ms | Sonde reaches the plane position. The plane is invisible until impact. |
| 1700–2200ms | Impact. Plane materializes as a Niagara digit field — rows of `0`s and `1`s, dim green, slow drift left-right. |
| 2200–3500ms | Concentric ripples expand outward from impact point, displacing the digits in a sinusoidal wave. Amplitude decays with distance. |
| 3500–4500ms | Wordmark fades in below the sonde. "Connecting…" indicator pulses to the right of the wordmark. |
| Throughout | Background: agent connection probe. As soon as Redis pub/sub establishes and the first heartbeat arrives, the splash advances. |
| Completion | Digit plane fades to black; camera zooms through the sonde into the world. |

### 12.3 Connection states during splash

`Connecting…` text reflects what's actually happening:

- "discovering agents…" while mDNS browse is in progress.
- "connecting to home-router…" while TLS handshake is in progress.
- "validating fingerprint…" while peer cert is being verified.
- "subscribing to topology…" while initial Redis state is being fetched.

If something fails during splash, the sequence holds at the current frame and an error banner appears with a Retry button. Examples:

- "agent unreachable — is `packetsonde-agent` running?"
- "trust validation failed for home-router — fingerprint mismatch."
- "no agents configured — open Settings → Agents to add one."

### 12.4 First-run onboarding

If `~/.config/packetsonde/agents.json` doesn't exist or is empty:

1. Splash completes faster (no agents to connect to).
2. Welcome panel appears: "no agents configured. would you like packetsonde to scan your local network for one?"
3. On Yes: discovery flow runs. mDNS browse + signed broadcast. Found agents are listed for trust + add.
4. On No: empty world view; the user can manually add agents from Settings.

### 12.5 Subsequent runs

Subsequent launches skip the welcome and proceed directly to splash → world. If `auto_connect: true` agents are configured, they're contacted in parallel during splash. World materializes when at least one connection succeeds (or after a 5s timeout, in which case a "no agents reachable" banner appears).

## 13. UI / UX Design

All UI is UMG widgets driven by Blueprints, derived from Common UI's activatable widget classes for layered presentation.

### 13.1 Principles

- The world is the primary surface. Panels float, slide in on demand, dismiss easily.
- Two display modes — territory (collapsed AS-path view) and hop (full ring/topology view). Toggleable any time via `T`.
- Minimal HUD when idle. Mode pill upper-left, breadcrumb upper-center, mini-map lower-right.
- One-keystroke access to everything important. No hunting through menus.
- Panels pin / unpin. Inspector pinned-right is common.
- Forensics is overlay, not separate view.

### 13.2 Persistent HUD

| Element | Position | Behavior |
|---------|----------|----------|
| **Mode pill** | upper-left | Shows `TERRITORY` / `HOP`. Click cycles. Hotkey `T`. |
| **Breadcrumb** | upper-center | `Google › IAD › 142.250.65.78` — selection path. Empty when nothing selected. Click any segment to navigate up. |
| **Mini-map** | lower-right | 2D top-down view. Territories as dots, camera frustum as triangle. Click to teleport. |
| **Time clock** | lower-left | Wall clock + live pulse. Click → time scrubber. |
| **Help glyph** | upper-right | `?`. Click → context-sensitive help overlay. |
| **Agent indicator** | upper-right (left of help) | Status pip per connected agent, color-coded. Tooltip lists active agents. |
| **Anomaly badge** | upper-left (below mode) | Count of unread anomalies. Click → anomaly side panel. |

### 13.3 Inspector

Slide-in panel on right edge. Pin / unpin via icon. Tabbed:

| Tab | Content |
|-----|---------|
| **Identity** | display name, IPs, MAC, role, GeoIP, ASN, OrgId, MetroId, hit count, first/last seen |
| **Activity** | recent traffic, flow volumes, active probes, time-series sparkline |
| **Path** | traceroutes involving this entity, recent and historical |
| **Notes** | user-attached notes, tags, custom annotations (saved to Redis) |
| **Anomalies** | events involving this entity |

For territories, the Identity tab shows OrgId, metro, member count, ASN list, role. For edges, source/dest, latency, traffic, boundary type.

### 13.4 Command palette

`Cmd+K` (Mac) / `Ctrl+K` opens a centered floating search. Unified across:

- Hosts (hostnames, IPs, MACs).
- Orgs (curated + auto-generated).
- Metros (IATA codes, city names).
- ASN numbers.
- Functions (commands like `ping`, `traceroute`, `frame world`, `toggle flows`, `connect agent <name>`).
- Saved queries (`@last-week`, `@iot-devices`, etc.).

Results ranked by relevance + recency. Keyboard-driven: arrow to navigate, Enter to select/execute. Escape to dismiss.

### 13.5 Action bar

Bottom-center hotbar with 12 slots (`1`–`9`, `0`, `-`, `=`). Each slot binds a function. Default bindings:

| Slot | Binding |
|------|---------|
| `1` | Ping selected |
| `2` | Traceroute to selected |
| `3` | Toggle flow visualization |
| `4` | Toggle territory mode |
| `5` | Frame world |
| `6` | Focus selection |
| `7` | Filter to selection's path |
| `8` | Clear filter |
| `9` | Show queue monitor |
| `0` | Show settings |
| `-` | Show function library |
| `=` | Toggle host visibility |

Slots re-pinnable from function library. Slot color: green for stateful-on, dim grey for off, transparent for non-stateful.

### 13.6 Function library

`Shift+Option` or action-bar `-`. Lists every function with description, current binding, Run/Pin buttons. Discovery surface for what packetsonde can do.

### 13.7 Filter toolbar

Floating along upper edge. Active when any aggregation lens or filter is engaged. Shows active filter, clear button, lens switcher. Hidden when no filter active.

### 13.8 Queue monitor

Floating panel from action-bar `9`. Shows:
- Counts: nodes / edges / containers / pending probes / active flows / active connections.
- Active probes with cancel buttons.
- Recent events log.
- Per-agent stats (events/sec, last-seen, message backlog).

### 13.9 Settings

Tabbed panel from action-bar `0`. Tabs:

| Tab | Contents |
|-----|----------|
| **General** | language, time format, camera defaults, accessibility, casual mode toggle |
| **Agents** | list of configured agents, add/remove, trust levels, auto-connect, discovery |
| **Discovery** | which adapters are on, scan interval, NetFlow listening port, traceroute frequency |
| **Forensics** | anomaly thresholds, recency window, accumulation half-life, decay aggressiveness |
| **Visual** | identity overrides, color customization, label density, mini-map scale, archetype variant preferences |
| **Performance** | render budget, LOD aggressiveness, max edge count, distance culling |
| **Privacy** | data retention, anycast registry export controls, agent allowlist |
| **Advanced** | debug overlays, log verbosity, Redis address override, BP debug mode |

### 13.10 Time scrubber

Click time clock → enables forensics replay mode. Bottom-edge timeline appears showing events over time, color-coded. Drag playhead to scrub. World reflects state-at-time, smooth interpolation.

### 13.11 Casual mode

Settings → General. Hides inspector default. Replaces function library with curated overlays ("show me ad networks", "what did loading gmail.com touch?"). Guided tour first run. Friendly tooltips.

### 13.12 Discovery panel

Settings → Agents → Discover, or a dedicated dialog from first-run. Per §8.4.

### 13.13 Pairing dialog

Modal. Shows fingerprint of agent being added. User chooses trust level. Optional friendly name override. Optional "remember this fingerprint for future hosts" checkbox (allows wildcard host SAN matching — useful for cloud-deployed agents that may rotate hostnames).

### 13.14 Notification system

Common UI's notification toast for transient events:
- Connection state changes ("connected to home-router").
- Anomaly events ("new anycast metro for 1.1.1.1: NRT").
- Agent activity ("home-router started a traceroute").

Toasts stack lower-right, auto-dismiss after 8s, click to navigate to the event source.

### 13.15 Keyboard shortcuts (default)

| Key | Action |
|-----|--------|
| `T` | Toggle territory / hop mode |
| `F` | Frame world |
| `Cmd/Ctrl+K` | Command palette |
| `Cmd/Ctrl+,` | Settings |
| `Esc` | Close panel / clear selection |
| `Space` | Pause/resume live updates |
| `1`–`=` | Action-bar slot |
| `Shift+Option` | Function library |
| `?` | Context-sensitive help |
| `[`, `]` | Cycle connected agents (focus their Home in turn) |
| `\` | Toggle anomaly side panel |
| WASD + mouse | Camera orbit / pan |
| Mouse wheel | Zoom |
| Mouse drag | Pan / orbit (mode-dependent) |

### 13.16 Accessibility

- Color-blind safe palettes available (Settings → General → Color profile: Default / Deuteranopia / Protanopia / Tritanopia).
- High-contrast UI mode for low-vision users.
- Screen-reader labels on every UMG element.
- Keyboard-only navigation (Common UI focus management makes this work).
- Adjustable text size in panels.

### 13.17 Internationalization

UI text is fully localizable via UE's localization framework. v1 ships English; community translations welcome. Country names in the inspector come from the IATA / ISO data. Org names are from curation; we don't translate them.

## 14. Interactive Links and Annotations

### 14.1 Why links are first-class

In most network visualizations, edges are passive geometry — lines drawn between nodes that the user can read but not interact with. packetsonde treats links as **first-class entities** the user can select, inspect, annotate, and enrich. The path between two hosts often carries more useful information than the hosts themselves: latency over time, AS-path stability, errors and resets, MTU mismatches, switch-port identity, peering policy. None of that lives on a node; it lives on the *connection*.

Making links interactive also unlocks a class of forensic queries — "tell me about *this* path right here" — that complement entity-centric ones.

### 14.2 Selection and interaction

Edges are clickable. Cursor over an edge highlights it (subtle glow + thickness boost); click selects it. Clicking a different edge transfers selection. Right-click opens a context menu (annotate, filter to this path, copy IDs, run probe along this link, etc.).

The selection breadcrumb (§13.2) shows the link's endpoints: `Comcast Pacific NW › lga02-be-3.bb.example.net ↔ Level3 SEA › ae-2.cr1.sea1.example.net`. Either endpoint is clickable to navigate.

Edge selection is mutually exclusive with node selection — selecting one deselects the other. A planned multi-select mode (Shift+click) lets the user assemble a path of interest; the inspector then aggregates statistics over the selection.

### 14.3 The link inspector

The same right-side inspector panel shows link details when an edge is selected. Tabs:

| Tab | Content |
|-----|---------|
| **Identity** | source / destination, link type, discovery source, AS pair, country pair, boundary type, link IDs |
| **Performance** | latency time-series sparkline, jitter, packet loss (when measured), throughput estimates, MTU |
| **Path Context** | full traceroute path this edge participates in, BGP AS-path (when known), routing policy hints |
| **Notes** | user-attached notes, tags, custom name, severity classification |
| **Enrichment** | per-source enrichment data (LLDP, SNMP, CDP, BFD, sFlow, NetFlow templates) |
| **Anomalies** | events that have fired on this link |
| **History** | every version of this link's data we've recorded; lets the user scrub through how the link has changed over time |

### 14.4 Annotations

Users can attach data to a link. Annotation types in V1:

- **Free-text note** — markdown-friendly, supports inline tags (`#vlan10`, `#flaky`).
- **Tag** — categorical labels backed by GameplayTags. Examples: `Link.Status.Flaky`, `Link.Class.Backbone`, `Link.Investigated.True`.
- **Custom name** — overrides the auto-generated edge label.
- **Severity** — Normal / Watch / Concerning / Critical. Drives edge tinting in the world.
- **Pinned screenshots / panels** — attach a captured snapshot of inspector data at this moment for "this is what this link looked like when I noticed the problem."

Annotations are stored separately from the auto-discovered link state — the system never overwrites a user's annotation. Schema:

```cpp
USTRUCT(BlueprintType)
struct FLinkAnnotation {
    UPROPERTY(BlueprintReadOnly) FGuid LinkId;
    UPROPERTY(BlueprintReadOnly) FString Note;
    UPROPERTY(BlueprintReadOnly) FString CustomName;
    UPROPERTY(BlueprintReadOnly) ELinkSeverity Severity;
    UPROPERTY(BlueprintReadOnly) FGameplayTagContainer Tags;
    UPROPERTY(BlueprintReadOnly) double CreatedSec;
    UPROPERTY(BlueprintReadOnly) double UpdatedSec;
    UPROPERTY(BlueprintReadOnly) FString CreatedByAgentId;     // ed25519 fingerprint of the editor user
    UPROPERTY(BlueprintReadOnly) TArray<FString> AttachmentRefs;
};
```

Persisted in `~/.local/share/packetsonde/link-annotations.json` (per user). Cross-agent annotations are personal — they don't get pushed to a remote agent's Redis.

### 14.5 Link enrichment sources

Beyond what the agent observes via traceroute / NetFlow, links can be enriched from several optional sources. Each enrichment source is implemented as an adapter (§6) that produces *link facts* rather than node facts.

| Source | Produces | Lives in |
|--------|----------|----------|
| **LLDP** | switch-port-to-switch-port adjacency: chassis ID, port ID, system name/description, capabilities | agent (passive libpcap) |
| **CDP** | Cisco's LLDP equivalent: device ID, port ID, platform, IOS version | agent (passive libpcap) |
| **SNMP** (interface MIB) | per-port counters, errors, discards, MTU, duplex, speed, neighbor table | editor or agent (per device credentials) |
| **BFD state** | bidirectional forwarding detection: tx/rx interval, missed packets | agent or device polling |
| **BGP** | AS-path, communities, MED, local-pref, next-hop, peer state | external BGP collector or RIPEstat / RouteViews HTTP query |
| **sFlow / IPFIX / NetFlow v9+** | per-flow octets/packets, ToS/DSCP, TCP flags summary | NetFlow listener (already in agent) |
| **PathPing / mtr** | per-hop loss%, latency stats over a sliding window | agent on demand |
| **OpenFlow / OVS stats** | per-port packet/byte counters from OVS bridges | agent (Unix socket) or controller polling |
| **Cable plant** (NetBox cable model) | physical patch-panel and fiber connectivity | NetBox adapter |

Enrichment data attaches to `FNetworkLink.EnrichmentSources`:

```cpp
USTRUCT(BlueprintType)
struct FLinkEnrichment {
    UPROPERTY(BlueprintReadOnly) FString SourceId;             // "lldp", "snmp", "bgp", ...
    UPROPERTY(BlueprintReadOnly) double ObservedSec;
    UPROPERTY(BlueprintReadOnly) TMap<FString, FString> Fields; // arbitrary key-value
    UPROPERTY(BlueprintReadOnly) FString ObservingAgentId;
};

// On FNetworkLink:
UPROPERTY(BlueprintReadOnly) TArray<FLinkEnrichment> EnrichmentSources;
```

The inspector's Enrichment tab renders one sub-panel per source, with the source-specific schema (e.g. an LLDP panel that shows chassis ID prominently, an SNMP panel that shows interface counter graphs).

### 14.6 Link history and time-series

For metrics that change over time (latency, errors, traffic), packetsonde records a sliding-window time-series per link:

```cpp
USTRUCT(BlueprintType)
struct FLinkMetricSample {
    UPROPERTY(BlueprintReadOnly) double Sec;
    UPROPERTY(BlueprintReadOnly) FName MetricKey;             // "latency", "loss", "errors_rx", ...
    UPROPERTY(BlueprintReadOnly) double Value;
};
```

Stored in Redis as a sorted set keyed by `packetsonde:link-metrics:<linkid>:<metric>`. The agent prunes samples older than the configured retention (default 7 days for fine-grained, downsampled retention beyond).

The Performance tab in the link inspector renders these as sparkline charts with adjustable time range. Hovering plots the value at the cursor.

### 14.7 Anomalies on links

Events that fire on links (in addition to the entity-level events from §21.2):

| Event | Trigger |
|-------|---------|
| `LinkLatencySpike` | latency exceeds rolling baseline by N stddev for M seconds |
| `LinkLossEvent` | packet loss > threshold |
| `LinkFlapped` | link state transitioned up→down→up within window |
| `LinkPathChanged` | the AS-path or hop sequence on a logical destination shifted |
| `LinkMTUMismatch` | observed packet drops consistent with MTU mismatch |
| `LinkUnreachable` | probe to either endpoint failing for > T seconds |

Each anomaly's link-context shows in the inspector's Anomalies tab and in the global anomaly side panel.

### 14.8 Link visualization styles

Selected link gets thickness boost + additive glow.
Annotated links carry a small glyph at the midpoint matching their severity.
Pinned/named links display the user's custom name as a label rather than auto-generated text.
Links with active anomalies pulse in their severity color (yellow / orange / red).

In aggregation lenses (e.g. "By Recency"), link visual weighting follows the lens's evaluation per §21.1.

### 14.9 Link-centric commands

Surfaced via right-click context menu and the action bar when a link is selected:

- **Probe** — run a path probe (mtr-style) along this link/path.
- **Filter to this path** — filter the world to nodes/links on this path.
- **Annotate** — open annotation editor.
- **Run LLDP refresh** — request the agent re-scan LLDP neighbors at this hop.
- **Snapshot** — capture link state for later comparison.
- **Compare** — side-by-side comparison with another link or with a historical version of this link.
- **Open external** — deep-link to an external tool keyed off the link's AS pair (Hurricane Electric BGP toolkit, RIPEstat, etc.).

### 14.10 Multi-agent links

When multiple agents observe the same logical edge (e.g. both home and office agents traverse `Comcast → Level3 → Google`), each agent's observation is recorded separately and tagged with `OriginatingAgentId`. The link inspector shows per-agent observations side-by-side. Differences (different latencies, different upstreams) are visible at a glance.

### 14.11 Future directions (not V1)

- **Live packet sampler** — sFlow/IPFIX/PCAP sampling on a selected link, with packet-level inspection.
- **Active probing** — schedule continuous mtr / iperf / TCP-handshake probes from one or more agents along selected paths.
- **AS-path diff visualization** — when a path's AS sequence changes, animate the transition with old vs new in side-by-side.
- **Crowd-sourced link annotations** — opt-in pooling so users can share labels for known-flaky paths or known-good peering relationships.

## 15. Visual System

### 15.1 Org × Role archetype catalog

Visual identity is a function of `(Role, Org-specific overlay)`.

| Role | Archetype | Form description |
|------|-----------|------------------|
| **Hyperscaler** (Google, AWS, Azure, Meta, Oracle Cloud) | Citadel | Large rectangular massing, glowing roof spire, multiple sub-towers. Dominant verticality. |
| **CDN** (Cloudflare, Akamai, Fastly, BunnyCDN) | Mesh | Distributed lattice; low-profile horizontal cage; nodes connected by light tubes. Suggests distributed presence. |
| **Tier1 transit** (Lumen/Level3, Cogent, NTT, Telia, Zayo) | Spire | Tall, narrow, beacon-like. Communication-tower silhouette. Animated pulse along the height. |
| **ResidentialISP** (Comcast, Verizon, AT&T, Charter, BT) | Compound | Sprawling low-profile, perimeter walls, residential-scale architecture. Suggests neighborhood. |
| **AdTracker / AdvertisingNetwork** | Ad-mall | Flashing signage, conspicuous, commercial archetype. Designed to look slightly garish. |
| **Government / state-aligned** | Bunker | Angular, hardened, isolated; minimal surface area. Desaturated red lighting. |
| **Hosting** (Vultr, OVH, Hetzner, DigitalOcean, Linode) | Warehouse | Utilitarian, modular, repeating bays. Suggests rented capacity. |
| **Email** (Mailchimp, SendGrid, Postmark, Mailgun) | Postal | Distinct mailing-station archetype: chimney + loading bays. |
| **DNS** (Cloudflare DNS, Google DNS, Quad9) | Lighthouse | Tall slender beacon with rotating light. Suggests directory service. |
| **Analytics** (Google Analytics, Mixpanel) | Observatory | Dome with telescopes. Suggests data collection. |
| **PaaS** (Vercel, Netlify, Heroku) | Workshop | Open-walled industrial space. Suggests build/deploy. |
| **VPN / Tor** | Tunnel mouth | Dark portal, suggests obscured destination. |
| **Storage** (S3-style providers) | Vault | Stacked-cube structure, suggests bulk capacity. |
| **Unknown** | Slab | Neutral default. Plain rectangular volume. |

V1 archetypes are procedural meshes generated via Geometry Script in `BP_TerritoryArchetype`. Per-Org branding overlays apply via material/decal — Cloudflare's mesh has Cloudflare's specific colors and emblem decals; Akamai's has Akamai's. Long-tail orgs share role-default appearance.

V2+ swaps in hand-modeled meshes for famous orgs as art track allows.

### 15.2 Color palette by role

| Role | Primary | Accent |
|------|---------|--------|
| Hyperscaler — Google | `#4285F4` blue | white spire |
| Hyperscaler — AWS | `#FF9900` orange | dark roof |
| Hyperscaler — Azure | `#0089D6` light blue | white |
| Hyperscaler — Meta | `#1877F2` royal blue | white |
| CDN — Cloudflare | `#F38020` orange | black mesh |
| CDN — Akamai | `#0066CC` blue | white mesh |
| CDN — Fastly | `#FF282D` red | white mesh |
| Tier1 — Lumen | `#0078A4` teal | white pulse |
| Tier1 — Cogent | `#E40521` red | white pulse |
| ResidentialISP | desaturated blues `#4A6FA5`, `#5A7B9F` | warm interior glow |
| AdTracker | bright magenta `#FF00CC` | flashing yellow |
| State-aligned | desaturated red `#9C3434` | angular shadow |
| Hosting | dark olive `#5D6B45` | utilitarian grey |
| Email | brick `#8B4513` | white |
| DNS | sky `#87CEEB` | rotating warm light |
| Unknown | desaturated grey `#666666` | (none) |
| Home | cyan `#00CCFF` | always familiar |

Palette curation lives in `agent/conf/asn-orgs.json`. Long-tail orgs auto-generate via golden-angle hue + slab archetype.

### 15.3 Country flags at boundary markers

When an edge crosses a country boundary, two flag billboards straddle the orange perpendicular boundary tick at the edge midpoint. Source country flag on upstream side, destination country flag on downstream side. Flag textures load from `assets/flags/<iso2>.png` via `NetrunnerCountryFlag::LoadFlagTexture` (renamed `PacketsondeCountryFlag::LoadFlagTexture`).

The base material for flag billboards is a custom unlit translucent material `M_FlagBillboard` with `Texture` and `Tint` parameters. (`/Engine/BasicShapes/BasicShapeMaterial` doesn't have a Texture parameter — a lesson learned in the prior project.)

Flags scale-fade with camera distance: full-size and opaque when the edge is in close camera focus, smaller and translucent when distant.

### 15.4 Edge styles

| State | Visual |
|-------|--------|
| Routing edge, normal | Ribbon mesh, role-pair color blend, thickness ∝ traffic volume |
| Routing edge, traceroute backbone | Brighter, slightly thicker |
| ASN boundary | Perpendicular orange tick at midpoint |
| Country boundary | Country flags straddle the tick |
| Active flow | Niagara packet traveling along the edge from src to dst, brief glow |
| Stale | Dim grey, kept for context |
| Filtered out | Translucent or hidden depending on filter mode |
| Selection-highlighted | Additive bright glow + thickness boost |

### 15.5 Selection and focus

Selected entity gets `[ ]` brackets-style indicator around its mesh. Path highlighting illuminates every edge on a selected path with additive glow; the rest of the world dims slightly. `F` key frames the selection.

### 15.6 Accumulation visual scaling

Territory's visual presence scales with `CumulativeHitCount`:

| Tier | Threshold | Appearance |
|------|-----------|------------|
| Silhouette | < 10 | Dim outline, no internal detail, no decals |
| Familiar | 10–100 | Base archetype, full color, no extras |
| Detailed | 100–1000 | Base + sub-feature decals, full lighting, label always visible |
| Landmark | > 1000 | Base + decals + ambient particle effects + Niagara accents |

Decay reduces count over time using configurable half-life (default 30 days). Decay never zeros — historical territories remain as silhouettes.

Edges accumulate similarly: faint trail → known route → highway-bright.

### 15.7 Splash / launch UI

Per §11.

### 15.8 Time-scrubbing visual

When the user scrubs time, the world animates between historical states. Niagara handles smooth interpolation of node positions and edge appearances. Anomaly events highlight on the timeline as colored tick marks.

## 16. Data Model

All structs are C++ `USTRUCT(BlueprintType)`, all fields `UPROPERTY` with `BlueprintReadWrite` or `BlueprintReadOnly`. Field names follow UE conventions (PascalCase, no `m_` prefix).

### 16.1 FNetworkNode

Core ingestion type. Identifies a host, router, hop, or service endpoint.

```cpp
USTRUCT(BlueprintType)
struct FNetworkNode {
    UPROPERTY(BlueprintReadOnly) FGuid NodeId;
    UPROPERTY(BlueprintReadOnly) FString DisplayName;
    UPROPERTY(BlueprintReadOnly) TArray<FString> Hostnames;
    UPROPERTY(BlueprintReadOnly) TArray<FString> IPAddresses;
    UPROPERTY(BlueprintReadOnly) FString MAC;
    UPROPERTY(BlueprintReadOnly) EDeviceType DeviceType;
    UPROPERTY(BlueprintReadOnly) int32 Capabilities;          // bitmask
    UPROPERTY(BlueprintReadOnly) FASInfo ASInfo;
    UPROPERTY(BlueprintReadOnly) FGeoLocation GeoLocation;

    UPROPERTY(BlueprintReadOnly) FString MetroId;
    UPROPERTY(BlueprintReadOnly) FString OrgId;
    UPROPERTY(BlueprintReadOnly) FString LastHopHostname;
    UPROPERTY(BlueprintReadOnly) double LastObservedSec;

    UPROPERTY(BlueprintReadOnly) bool bIsSelf;
    UPROPERTY(BlueprintReadOnly) bool bIsGateway;
    UPROPERTY(BlueprintReadOnly) bool bDiscoveredViaTraceroute;

    UPROPERTY(BlueprintReadOnly) int32 CumulativeHitCount;
    UPROPERTY(BlueprintReadOnly) double FirstSeenSec;
    UPROPERTY(BlueprintReadOnly) double LastSeenSec;

    UPROPERTY(BlueprintReadOnly) FString OriginatingAgentId;  // ed25519 fingerprint of source agent
    UPROPERTY(BlueprintReadOnly) TMap<FString, FString> Custom;
    UPROPERTY(BlueprintReadOnly) FGameplayTagContainer Tags;

    // Adapter-layered identities (§6.5). One node may simultaneously be a
    // K8s pod + a Proxmox VM + a NetBox device + an SNMP-polled router.
    UPROPERTY(BlueprintReadOnly) TArray<FAdapterIdentity> AdapterIdentities;
};

USTRUCT(BlueprintType)
struct FAdapterIdentity {
    UPROPERTY(BlueprintReadOnly) FString AdapterId;             // "adapter.kubernetes"
    UPROPERTY(BlueprintReadOnly) FString AdapterInstanceId;     // e.g. "prod-us-east"
    UPROPERTY(BlueprintReadOnly) FString EntityKind;            // "node" | "pod" | "vm" | "device" ...
    UPROPERTY(BlueprintReadOnly) FString EntityId;              // adapter-specific stable key
    UPROPERTY(BlueprintReadOnly) TMap<FString, FString> Attributes;
    UPROPERTY(BlueprintReadOnly) double LastObservedSec;
};
```

### 16.2 FNetworkLink

```cpp
USTRUCT(BlueprintType)
struct FNetworkLink {
    UPROPERTY(BlueprintReadOnly) FGuid LinkId;
    UPROPERTY(BlueprintReadOnly) FGuid SourceNodeId;
    UPROPERTY(BlueprintReadOnly) FGuid DestNodeId;
    UPROPERTY(BlueprintReadOnly) FGuid SourceInterfaceId;
    UPROPERTY(BlueprintReadOnly) FGuid DestInterfaceId;
    UPROPERTY(BlueprintReadOnly) ELinkType LinkType;
    UPROPERTY(BlueprintReadOnly) FString LinkSubtype;           // adapter-specific (e.g. "k8s.service-to-pod")
    UPROPERTY(BlueprintReadOnly) bool bDiscoveredViaTraceroute;
    UPROPERTY(BlueprintReadOnly) float LatencyMs;
    UPROPERTY(BlueprintReadOnly) FString BoundaryType;          // "ASN" | "Country" | ""
    UPROPERTY(BlueprintReadOnly) double LastObservedSec;
    UPROPERTY(BlueprintReadOnly) FString OriginatingAgentId;
    UPROPERTY(BlueprintReadOnly) FGameplayTagContainer Tags;

    // Per-source enrichment (LLDP, SNMP, BGP, BFD, sFlow, etc.). See §14.5.
    UPROPERTY(BlueprintReadOnly) TArray<FLinkEnrichment> EnrichmentSources;

    // User-attached annotations are stored separately to preserve them
    // across automated updates of the link state (§14.4).
    UPROPERTY(BlueprintReadOnly) FLinkAnnotation Annotation;
};

USTRUCT(BlueprintType)
struct FLinkEnrichment {
    UPROPERTY(BlueprintReadOnly) FString SourceId;              // "lldp", "snmp", "bgp", ...
    UPROPERTY(BlueprintReadOnly) double ObservedSec;
    UPROPERTY(BlueprintReadOnly) TMap<FString, FString> Fields; // arbitrary key-value
    UPROPERTY(BlueprintReadOnly) FString ObservingAgentId;
};

USTRUCT(BlueprintType)
struct FLinkAnnotation {
    UPROPERTY(BlueprintReadOnly) FGuid LinkId;
    UPROPERTY(BlueprintReadOnly) FString Note;                  // markdown
    UPROPERTY(BlueprintReadOnly) FString CustomName;
    UPROPERTY(BlueprintReadOnly) ELinkSeverity Severity;        // Normal/Watch/Concerning/Critical
    UPROPERTY(BlueprintReadOnly) FGameplayTagContainer Tags;
    UPROPERTY(BlueprintReadOnly) double CreatedSec;
    UPROPERTY(BlueprintReadOnly) double UpdatedSec;
    UPROPERTY(BlueprintReadOnly) FString CreatedByClientId;
    UPROPERTY(BlueprintReadOnly) TArray<FString> AttachmentRefs;
};
```

### 16.3 FNetworkContainer

```cpp
USTRUCT(BlueprintType)
struct FNetworkContainer {
    UPROPERTY(BlueprintReadOnly) FGuid ContainerId;
    UPROPERTY(BlueprintReadOnly) EContainerType ContainerType;
    UPROPERTY(BlueprintReadOnly) FString ContainerSubtype;       // adapter-specific subtype string
    UPROPERTY(BlueprintReadOnly) FString Name;
    UPROPERTY(BlueprintReadOnly) FString DisplayName;
    UPROPERTY(BlueprintReadOnly) TArray<FGuid> MemberNodeIds;
    UPROPERTY(BlueprintReadOnly) int32 MemberCount;
    UPROPERTY(BlueprintReadWrite) bool bIsCollapsed;
    UPROPERTY(BlueprintReadWrite) FVector Position;

    // Hierarchy (used by adapters with nested concepts like K8s, Proxmox, NetBox)
    UPROPERTY(BlueprintReadOnly) FGuid ParentContainerId;
    UPROPERTY(BlueprintReadOnly) TArray<FGuid> ChildContainerIds;

    // Adapter source — which adapter created/owns this container (empty for
    // packetsonde-native containers like OrgTerritory).
    UPROPERTY(BlueprintReadOnly) FString AdapterSourceId;
    UPROPERTY(BlueprintReadOnly) FString AdapterInstanceId;

    // OrgTerritory-specific
    UPROPERTY(BlueprintReadOnly) FString OrgId;
    UPROPERTY(BlueprintReadOnly) FString MetroId;
    UPROPERTY(BlueprintReadOnly) FLinearColor TerritoryColor;
    UPROPERTY(BlueprintReadOnly) TArray<int32> ObservedASNs;
    UPROPERTY(BlueprintReadOnly) int32 CumulativeHitCount;
    UPROPERTY(BlueprintReadOnly) double FirstSeenSec;
    UPROPERTY(BlueprintReadOnly) double LastSeenSec;

    UPROPERTY(BlueprintReadOnly) TArray<FString> ContributingAgentIds;
    UPROPERTY(BlueprintReadOnly) FGameplayTagContainer Tags;

    // Adapter-supplied state (a JSON blob the adapter keeps fresh; the
    // inspector tab interprets it). Allows render lenses to drive animations
    // from arbitrary adapter-specific health/activity data.
    UPROPERTY(BlueprintReadOnly) FString AdapterStateJson;
};
```

### 16.4 FMetroDescriptor

```cpp
USTRUCT(BlueprintType)
struct FMetroDescriptor {
    UPROPERTY(BlueprintReadOnly) FString MetroId;
    UPROPERTY(BlueprintReadOnly) FString DisplayName;
    UPROPERTY(BlueprintReadOnly) FString CountryCode;
    UPROPERTY(BlueprintReadOnly) FString Continent;
    UPROPERTY(BlueprintReadOnly) float Latitude;
    UPROPERTY(BlueprintReadOnly) float Longitude;
    UPROPERTY(BlueprintReadOnly) int32 Population;
};
```

### 16.5 FOrgIdentity

```cpp
USTRUCT(BlueprintType)
struct FOrgIdentity {
    UPROPERTY(BlueprintReadOnly) FString OrgId;
    UPROPERTY(BlueprintReadOnly) FString DisplayName;
    UPROPERTY(BlueprintReadOnly) TArray<int32> ASNs;
    UPROPERTY(BlueprintReadOnly) FString Role;                // open taxonomy
    UPROPERTY(BlueprintReadOnly) FLinearColor Color;
    UPROPERTY(BlueprintReadOnly) FString StyleArchetype;
    UPROPERTY(BlueprintReadOnly) bool bStateAligned;
    UPROPERTY(BlueprintReadOnly) FGameplayTagContainer Tags;  // e.g. Org.Role.Hyperscaler, Org.Region.US
};
```

### 16.6 FAnycastEntity and FAnycastObservation

```cpp
USTRUCT(BlueprintType)
struct FAnycastObservation {
    UPROPERTY(BlueprintReadOnly) FString MetroId;
    UPROPERTY(BlueprintReadOnly) int32 ASN;
    UPROPERTY(BlueprintReadOnly) int32 HitCount;
    UPROPERTY(BlueprintReadOnly) double FirstSeenSec;
    UPROPERTY(BlueprintReadOnly) double LastSeenSec;
    UPROPERTY(BlueprintReadOnly) float MedianRTTMs;
    UPROPERTY(BlueprintReadOnly) TArray<FGuid> LastHopNodeIds;
    UPROPERTY(BlueprintReadOnly) TArray<FString> LastHopHostnames;
    UPROPERTY(BlueprintReadOnly) FString ObservingAgentId;    // which agent saw this
};

USTRUCT(BlueprintType)
struct FAnycastEntity {
    UPROPERTY(BlueprintReadOnly) FString Address;
    UPROPERTY(BlueprintReadOnly) FString OrgId;
    UPROPERTY(BlueprintReadOnly) TArray<FAnycastObservation> Observations;
    UPROPERTY(BlueprintReadOnly) bool bConfirmedAnycast;
    UPROPERTY(BlueprintReadOnly) float Confidence;
    UPROPERTY(BlueprintReadOnly) FGameplayTagContainer Tags;
};
```

### 16.7 FAgentDescriptor

```cpp
USTRUCT(BlueprintType)
struct FAgentDescriptor {
    UPROPERTY(BlueprintReadOnly) FString AgentId;             // ed25519 fingerprint
    UPROPERTY(BlueprintReadOnly) FString FriendlyName;
    UPROPERTY(BlueprintReadOnly) FString Host;
    UPROPERTY(BlueprintReadOnly) int32 Port;
    UPROPERTY(BlueprintReadOnly) EAgentTrustLevel TrustLevel;
    UPROPERTY(BlueprintReadOnly) bool bAutoConnect;
    UPROPERTY(BlueprintReadOnly) EAgentStatus Status;         // disconnected | connecting | connected | trust_failed
    UPROPERTY(BlueprintReadOnly) double LastSeenSec;
    UPROPERTY(BlueprintReadOnly) FString Version;
    UPROPERTY(BlueprintReadOnly) FGameplayTagContainer Capabilities;
};
```

### 16.8 Subsystem layout

Three subsystems collaborate:

```
UPacketsondeEngineSubsystem      (UEngineSubsystem)
  - process-wide singletons
  - IATA airport table
  - flag texture cache
  - shared archetype mesh cache

UPacketsondeGameInstanceSubsystem  (UGameInstanceSubsystem)
  - the datastore (UPacketsondeDataStore)
  - all agent connections (UPacketsondeAgentLink instances)
  - configuration (loaded from agents.json)
  - persistent UI state (recent searches, action-bar bindings)

UPacketsondeWorldSubsystem        (UWorldSubsystem)
  - the BP-callable API surface
  - mode state
  - lens / filter state
  - per-world transient state

ULocalPlayerSubsystem subclasses    (one per local player)
  - per-user UI preferences
  - selection state
  - camera state
```

### 16.9 The world subsystem API

```cpp
UCLASS(BlueprintType)
class UPacketsondeWorldSubsystem : public UWorldSubsystem {
public:
    // ----- read API -----
    UFUNCTION(BlueprintCallable, BlueprintPure)
    FNetworkNode GetNode(const FGuid& NodeId) const;

    UFUNCTION(BlueprintCallable, BlueprintPure)
    TArray<FGuid> GetAllNodeIds() const;

    UFUNCTION(BlueprintCallable, BlueprintPure)
    TArray<FGuid> GetNodeIdsForAgent(const FString& AgentId) const;

    UFUNCTION(BlueprintCallable, BlueprintPure)
    FNetworkContainer GetContainer(const FGuid& ContainerId) const;

    UFUNCTION(BlueprintCallable, BlueprintPure)
    TArray<FGuid> GetContainersForNode(const FGuid& NodeId) const;

    UFUNCTION(BlueprintCallable, BlueprintPure)
    FOrgIdentity GetOrg(const FString& OrgId) const;

    UFUNCTION(BlueprintCallable, BlueprintPure)
    FMetroDescriptor GetMetro(const FString& MetroId) const;

    UFUNCTION(BlueprintCallable, BlueprintPure)
    FAnycastEntity GetAnycastEntity(const FString& Address) const;

    UFUNCTION(BlueprintCallable, BlueprintPure)
    FVector GetEffectiveLocationForNode(const FGuid& NodeId, FGuid& OutCollapseContainer) const;

    UFUNCTION(BlueprintCallable, BlueprintPure)
    bool IsNodeInsideCollapsedContainer(const FGuid& NodeId, FGuid& OutContainerId) const;

    UFUNCTION(BlueprintCallable, BlueprintPure)
    TArray<FAgentDescriptor> GetConnectedAgents() const;

    UFUNCTION(BlueprintCallable, BlueprintPure)
    bool ShouldShowNode(const FGuid& NodeId) const;          // single-source-of-truth visibility check

    // ----- mode -----
    UFUNCTION(BlueprintCallable, BlueprintPure)
    EPacketsondeMode GetMode() const;

    UFUNCTION(BlueprintCallable)
    void SetMode(EPacketsondeMode NewMode);

    // ----- write hooks -----
    UFUNCTION(BlueprintCallable)
    void SetContainerCollapsed(const FGuid& ContainerId, bool bCollapsed);

    UFUNCTION(BlueprintCallable)
    void SetActiveLens(FGameplayTag LensTag);

    UFUNCTION(BlueprintCallable)
    void RequestPing(const FGuid& NodeId, const FString& AgentId);

    UFUNCTION(BlueprintCallable)
    void RequestTraceroute(const FGuid& NodeId, const FString& AgentId);

    // ----- agent management -----
    UFUNCTION(BlueprintCallable)
    void ConnectAgent(const FString& AgentId);

    UFUNCTION(BlueprintCallable)
    void DisconnectAgent(const FString& AgentId);

    UFUNCTION(BlueprintCallable)
    void StartDiscovery();

    UFUNCTION(BlueprintCallable)
    void AddAgent(const FAgentDescriptor& Descriptor);

    // ----- events -----
    UPROPERTY(BlueprintAssignable) FOnPacketsondeNodeAdded OnNodeAdded;
    UPROPERTY(BlueprintAssignable) FOnPacketsondeNodeUpdated OnNodeUpdated;
    UPROPERTY(BlueprintAssignable) FOnPacketsondeNodeRemoved OnNodeRemoved;
    UPROPERTY(BlueprintAssignable) FOnPacketsondeContainerAdded OnContainerAdded;
    UPROPERTY(BlueprintAssignable) FOnPacketsondeContainerUpdated OnContainerUpdated;
    UPROPERTY(BlueprintAssignable) FOnPacketsondeContainerRemoved OnContainerRemoved;
    UPROPERTY(BlueprintAssignable) FOnPacketsondeLinkAdded OnLinkAdded;
    UPROPERTY(BlueprintAssignable) FOnPacketsondeLinkUpdated OnLinkUpdated;
    UPROPERTY(BlueprintAssignable) FOnPacketsondeAnycastUpdated OnAnycastUpdated;
    UPROPERTY(BlueprintAssignable) FOnPacketsondeAnomaly OnAnomaly;
    UPROPERTY(BlueprintAssignable) FOnPacketsondeModeChanged OnModeChanged;
    UPROPERTY(BlueprintAssignable) FOnPacketsondeAgentConnected OnAgentConnected;
    UPROPERTY(BlueprintAssignable) FOnPacketsondeAgentDisconnected OnAgentDisconnected;
    UPROPERTY(BlueprintAssignable) FOnPacketsondeAgentDiscovered OnAgentDiscovered;
};
```

This subsystem is the *only* way BP touches the data layer.

## 17. Inference Pipelines

### 17.1 Metro inference

Pipeline: `PacketsondeMetro::Resolve(Node)`. Precedence chain:

1. **Reverse-DNS hostname airport-code.** Scan reverse-DNS hostnames for 3-letter sub-sequences bounded by non-alphabetic characters (digit, dot, dash). Validate each candidate against the IATA table. First match wins. Rationale: backbone operators commonly bake codes into hostnames (`iad17s44`, `lga02-`, `ae15.mpr1.sea1.us.zip.zayo.com`), and this signal is more reliable than GeoIP for routers.

2. **GeoIP city → IATA reverse lookup.** Normalize GeoIP city name (lowercase, strip whitespace and punctuation). Look up in a reverse map of the IATA table. First matching airport code wins. The reverse map is built lazily from the IATA table at first use.

3. **Latency cluster.** When a node has no airport code and no resolvable GeoIP, but has multiple traceroute observations: cluster by RTT-from-gateway. Nodes with similar RTT and similar AS are likely co-located; assign the same `MetroId` (a sentinel like `"cluster-<id>"` until/unless a better signal arrives).

4. **Parent metro inheritance.** A traceroute hop with no signals can inherit its metro from its parent hop in the trace, with a confidence penalty.

5. **Sentinel `"unknown"`.** When no signal resolves.

When a metro resolves, side effect: `UPacketsondeDataStore::UpsertMetro` self-populates the registry from observation.

### 17.2 Org inference

Pipeline: `PacketsondeOrg::Resolve(Node)`.

1. **Curated lookup.** Read `agent/conf/asn-orgs.json` and look up the node's ASN. If the ASN belongs to a curated Org, that's the OrgId. The curated entry also provides Role, Color, archetype, state-aligned flag.
2. **Auto-generated fallback.** Otherwise, OrgId = `"AS<num>"`. A new `FOrgIdentity` is auto-generated with a slab archetype, a golden-angle hue color, and Role = `"Unknown"`.
3. **Heuristic role classification (V1+).** Apply pattern matching to the org name and ASN to guess role: hostnames containing `mail`, `mx`, `smtp` → `Email`; hostnames containing `cdn`, `edge` → `CDN`; ASN size (very large == hyperscaler-likely); etc. This is a fallback — curation always wins.

Idempotent: subsequent observations merge ASNs into the existing `FOrgIdentity.ASNs` set.

### 17.3 Anycast confirmation

Triggered in `MergeNode` for any node whose IP is currently in the anycast registry, OR for IPs matching a curated anycast list (1.1.1.1, 8.8.8.8, etc.).

Pipeline:
1. Look up or create the `FAnycastEntity` for the IP.
2. Find the matching `FAnycastObservation` for current `(MetroId, ObservingAgentId)` — agents observe independently. If absent, create.
3. Increment `HitCount`, refresh `LastSeenSec`, update `MedianRTTMs` (rolling-median over last 50 observations).
4. If `LastHopHostname` is new for this observation, append.
5. Recompute `bConfirmedAnycast`:
   ```
   distinct_metros = count of unique MetroIds across all observations
   distinct_fingerprints = count of unique LastHopHostnames across all observations
   median_inter_metro_distance = pairwise great-circle distance, median
   bConfirmedAnycast = distinct_metros > 1
                    && distinct_fingerprints > 1
                    && median_inter_metro_distance > 500_km
   ```
6. Recompute `Confidence` (0..1):
   ```
   recency_factor = exp(-Δt / 30_days_in_sec)
   metros_factor  = min(distinct_metros / 4, 1)
   fingerprints_factor = min(distinct_fingerprints / 3, 1)
   asn_factor     = min(distinct_asns_observed / 2, 1)
   Confidence = 0.4 * metros_factor + 0.3 * fingerprints_factor + 0.2 * asn_factor + 0.1 * recency_factor
   ```
7. Emit `OnAnycastUpdated` event for BP.
8. If `MetroId` is new (no prior observation in this metro), emit `OnAnomaly` with type `NewAnycastMetro`.
9. If a fingerprint shifts within an existing metro (same IP, same metro, new upstream), emit `OnAnomaly` with type `NewLastHopFingerprint`.

### 17.4 Performance

Inference is `O(1)` per node observation in the hot path:
- IATA table lookup: hash map.
- GeoIP city normalize+lookup: hash map.
- Org lookup: hash map.
- Anycast confirmation: append to `Observations`, recompute confidence over recent.

For 10,000-node ingest at 100 nodes/sec, inference adds < 1ms total per second on modern hardware.

## 18. Placement

### 18.1 Geographic projection

`PacketsondeMetro::ProjectLatLon(Lat, Lon, DegreesPerUnit=200) → FVector2D`.

Equirectangular: `(X = Lon * DegreesPerUnit, Y = ClampedLat * DegreesPerUnit)`. North = +Y, east = +X. Latitude clamped to ±85° to bound polar territories.

World extent at default scale: ~72,000 units across. Default camera framing must expose this on territory mode entry. `DegreesPerUnit` is configurable in Settings → Visual; reducing it shrinks the world.

### 18.2 Why equirectangular and not Mercator or globe

- **Equirectangular** preserves area weighting at the cost of polar distortion. For navigation purposes that's a fair trade.
- **Mercator** would produce extreme polar distortion that interferes with the limbo zone visualization.
- **3D globe** would require the camera and UI to handle spherical geometry, which is a substantial scope expansion. Defer to v3+.

### 18.3 Home territory placement

Home is anchored at the gateway's resolved metro. If multiple agents are connected, each agent has its own Home territory at its own gateway's metro. If a gateway has no resolvable metro (no airport code AND no GeoIP city), Home stays at world origin as a "you are here" anchor.

When multiple agents share a metro (rare but possible — two agents on different LANs in the same building), their Home territories are jittered apart by ~500 units along golden-angle directions to avoid overlap.

### 18.4 Limbo zone

Territories with `MetroId="unknown"` cluster in a small fog disc near origin. Center: `(-2500, +1500)`. Per-territory deterministic offset from the territory id hash, radius 1500–2300u. Tight enough to stay in the world frame; distinct enough to be visually grouped.

Visual treatment for limbo (V2): distinct fog volume, dim ambient lighting, "?" marker glyphs at the edges. Currently a blank disc, planned aesthetic upgrade.

### 18.5 Same-metro org spread

When multiple territories share a metro (Google IAD + AWS IAD + Cloudflare IAD), they overlap exactly at the projected lat/lon. Same-metro org spread (V2) jitters them by 200–400 units along golden-angle directions around the metro centroid, sized by member count. Until V2, multi-territory metros visually coincide.

### 18.6 Position writers

`UPacketsondeWorldSubsystem` writes `Container.Position` once per topology change. BP-driven actor classes observe `OnContainerUpdated` and animate themselves to the new position. C++ never moves an actor in territory mode.

## 19. Collapse Semantics

### 19.1 Container is the collapse unit

Every node belongs to zero or more containers. A node is "inside a collapsed container" if any of its containers has `bIsCollapsed=true`. When inside one, the node is hidden and edges with that node as endpoint redirect to the container's super-node actor.

### 19.2 Container preference

Multiple collapsed containers is possible (an OrgTerritory and a Subnet, both collapsed). Redirect target is chosen by priority:

1. `OrgTerritory` — always has a spawned super-node platform.
2. Other types — may not have spawned platforms.

This is critical: a Subnet container that's collapsed but has no platform actor would produce orphan edges that anchor to hidden node positions.

### 19.3 Edge retargeting

`UPacketsondeWorldSubsystem::GetEffectiveLocationForNode(NodeId)` returns the redirected position. BP edge actors call this every tick (or on `OnContainerUpdated`) and update endpoints.

### 19.4 The visibility rule (single source of truth)

`UPacketsondeWorldSubsystem::ShouldShowNode(NodeId)` is the single function that determines node visibility. Implementation:

```
ShouldShowNode(NodeId) returns false if any of:
  - Node is inside a collapsed container.
  - Node's owning agent is disconnected and the user has not opted to retain the snapshot.
  - User-applied filter excludes this node.
  - Node has been explicitly hidden via inspector "hide".

Otherwise returns true.
```

Every visibility-affecting code path calls `ShouldShowNode` first and respects the answer. This is the rule that prevented multi-month band-aid accumulation in the prior project.

The flow-activity un-hide, the stray-detection un-hide, the distance culling, the host-hide toggle, the terminus rule (now retired in territory mode) — all of them go through this single check. C++ enforces it at every visibility-write site.

### 19.5 Mode toggle

- **Entering territory mode:** every `OrgTerritory` container set `bIsCollapsed=true`. Other container types unchanged.
- **Exiting territory mode:** every `OrgTerritory` container set `bIsCollapsed=false`. Member nodes reappear at hop-mode positions.
- **Per-territory expand during territory mode:** user clicks a territory super-node → BP toggles `bIsCollapsed` on that container only. Members fade in around the centroid via local force-directed scatter.

### 19.6 Multi-agent collapse semantics

A territory observed by multiple agents has each agent's contribution to its membership listed in `MemberNodeIds`. Collapsing the territory hides all members regardless of originating agent. Expanding the territory shows members from all connected agents (filterable by agent if the user activates the "By Agent" lens).

## 20. Anycast Object Model

### 20.1 Lifecycle

Per §15.3.

### 20.2 Visual presentation

In territory mode, an anycast entity is rendered at the metro of its most-recent observation (per the observing agent), behaving like any other member of that territory. When selected, the inspector shows all observations chronologically, grouped by agent.

An optional ghost-presence overlay (toggleable per-entity in the inspector) renders dim mirror copies at every other observed metro, illustrating "this exists in N places." When the user enables ghosts, edges to/from this entity also draw dim ghosts to all the alternate metros, visually representing the multi-presence.

### 20.3 Persistence

Anycast registry persists to Redis (`packetsonde:anycast:<address>`) and accumulates across sessions. Across multiple agents, each contributes observations.

### 20.4 Anomaly events

- **`NewAnycastMetro`** — anycast IP gained a new metro that no agent had previously observed.
- **`NewLastHopFingerprint`** — same IP, same metro, new upstream fingerprint. Could indicate BGP shift, peering change, or interception.
- **`AnycastConfidenceShift`** — confidence crossed a notable threshold (e.g. 0.5 boundary).

Each emits `OnAnomaly` with structured payload for the side panel.

### 20.5 Forensic queries

Through the inspector or command palette:

- **"Show all confirmed anycast IPs."** Lists registry entries where `bConfirmedAnycast=true`, sorted by `Confidence`.
- **"IoT contacts that are anycast."** Joins device traffic with anycast registry.
- **"Anycast IPs whose served metro changed in the last 24h."** Time-bounded query.
- **"Anycast IPs observed in metros that don't make sense for their org."** Geographic-outlier detection.

### 20.6 Cross-user pooling (deferred)

Out of scope for v1. Schema is ready (registry is keyed by IP, observations carry ObservingAgentId), but the privacy and protocol questions for multi-user pools are non-trivial.

## 21. Forensics Overlays

All overlays are BP-implemented using the world subsystem's read API.

### 21.1 Aggregation lenses

Each lens is a BP class implementing `BPI_AggregationLens`:

```cpp
UINTERFACE(BlueprintType)
class UBPI_AggregationLens : public UInterface { GENERATED_BODY() };

class IBPI_AggregationLens {
    UFUNCTION(BlueprintImplementableEvent)
    void EvaluateTerritory(const FGuid& TerritoryId, FLinearColor& OutTint, float& OutIntensity);

    UFUNCTION(BlueprintImplementableEvent)
    void EvaluateNode(const FGuid& NodeId, FLinearColor& OutTint, float& OutIntensity);

    UFUNCTION(BlueprintImplementableEvent)
    void EvaluateEdge(const FGuid& LinkId, FLinearColor& OutTint, float& OutIntensity);
};
```

Lenses provided in v1:

- `BP_LensByOrg` — color-tint by Org's curated color.
- `BP_LensByRole` — color-tint by Role taxonomy.
- `BP_LensByDevice` — heatmap of which territories a chosen device contacts.
- `BP_LensByRecency` — recency gradient.
- `BP_LensByAnomaly` — territories newly seen, fingerprint shifts, anycast metro changes.
- `BP_LensByCountry` — color-tint by destination country.
- `BP_LensByConfidence` — anycast confidence overlay.
- `BP_LensByAgent` — color-tint by originating agent (multi-agent setups).

Switching lenses is a single BP call. Adding a new lens is a new BP class implementing the interface — no C++ change needed.

### 21.2 Anomaly events

Surfaced in side panel and as in-world flares (Niagara-driven).

| Event type | Trigger |
|------------|---------|
| `NewTerritory` | First-ever contact with `(Org, Metro)` |
| `NewAnycastMetro` | Anycast IP started serving from a new metro |
| `NewLastHopFingerprint` | Same IP from same network now via new upstream |
| `UnexpectedRoleCluster` | Device's contacts disproportionately in a role it shouldn't need |
| `GeographicOutlier` | Contact in a metro/country the device's expected service profile shouldn't reach |
| `ASPathChange` | Path to a stable destination changed AS sequence |
| `AgentLost` | Connected agent unreachable for > N minutes |
| `AgentTrustExpired` | Agent's cert no longer validates against fingerprint |

### 21.3 Session recording

Optional: record a user session. Sequence of events, cursor moves, mode toggles, traversed territories. Replay (camera flythrough) or compare against another session ("how did this page-load differ from yesterday's?"). Stored in `~/.local/share/packetsonde/sessions/`.

### 21.4 Time scrubbing

Per §12.10. Timeline shows event ticks color-coded by severity. Drag the playhead and the world animates to the historical state — actor positions, edge appearances, lens colors all interpolated.

## 22. Persistence

### 22.1 Redis schema

Each agent has its own Redis. Schema:

| Key | Type | Purpose |
|-----|------|---------|
| `packetsonde:node:<guid>` | hash | `FNetworkNode` |
| `packetsonde:link:<guid>` | hash | `FNetworkLink` |
| `packetsonde:flow:<guid>` | hash | `FNetworkFlow` |
| `packetsonde:container:<guid>` | hash | `FNetworkContainer` |
| `packetsonde:metro:<id>` | hash | `FMetroDescriptor` |
| `packetsonde:org:<id>` | hash | `FOrgIdentity` |
| `packetsonde:anycast:<address>` | hash | `FAnycastEntity` |
| `packetsonde:territory-history:<orgid>:<metroid>` | hash | accumulation stats |
| `packetsonde:agent-info` | hash | this agent's name, fingerprint, version, capabilities |
| `packetsonde:event:node-added` | pub/sub | broadcast `<guid>` |
| `packetsonde:event:node-updated` | pub/sub | broadcast `<guid>` |
| `packetsonde:event:link-added` | pub/sub | broadcast `<guid>` |
| `packetsonde:event:flow-update` | pub/sub | broadcast `<guid>` |
| `packetsonde:event:container-added` | pub/sub | broadcast `<guid>` |
| `packetsonde:event:container-updated` | pub/sub | broadcast `<guid>` |
| `packetsonde:event:anomaly` | pub/sub | broadcast `<json>` |
| `packetsonde:event:agent-heartbeat` | pub/sub | agent liveness |

### 22.2 Schema versioning

Each hash includes a `_schema` field with the schema version (integer, monotonic). Load-time migrations handle older schemas; current minimum supported version is recorded.

When the agent starts, it reads the `_schema` of one hash; if older than its current code, it runs the migration script for that key type. Migrations run once and are idempotent.

### 22.3 RDB / AOF

Default config: AOF enabled with `appendfsync everysec`. Survives crashes within the last second. RDB snapshots every hour for backup.

Optional encrypted RDB via `--encrypt-rdb` flag (passphrase prompted on agent start).

### 22.4 Decay and trimming

Background task on the agent (every 5 min):
- Walk all entities, apply decay to `CumulativeHitCount` per configured half-life (default 30 days).
- Drop entities below `(LastSeenSec older than 90 days) AND (HitCount < 3)`.
- Compact RDB.

Decay is BP-tunable through Settings → Forensics.

### 22.5 Cross-agent reconciliation

When the editor is connected to multiple agents, the world subsystem maintains a unified view in memory. It does not write back to any agent's Redis (agents are write-authoritative for their own observations). When the user adds a personal note or tags an entity in the editor, the note is stored in a *separate* personal-notes store (`~/.local/share/packetsonde/notes.json`), not pushed to the agent.

Anycast registry is the exception: anycast observations from all connected agents are merged in the editor's in-memory view, but each agent's local registry is its own. A future v2 may add a synchronized anycast registry across agents the user controls.

## 23. Performance and LOD Policy

### 23.1 Targets

| Scenario | FPS target |
|----------|------------|
| Typical home (200 nodes, 500 edges, 50 territories) | 60+ |
| Heavy single-user (5,000 nodes, 20,000 edges, 500 territories) | 30+ |
| Multi-agent (10 agents, 50,000 nodes aggregate) | 30+ |
| Cold launch (editor) → splash | < 5s |
| Splash → interactive world | < 5s |
| Agent observation → editor visualization | < 100ms |

### 23.2 LOD policy

Visible-node budget configurable in Settings → Performance. Default 250.

Algorithm (every 1.5s, BP-implemented in `BP_TerritoryLODPolicy`):

```
1. Score every territory:
     priority = 0 if Home or pinned by user
     priority = 1 if has activity in last RecencyWindow
     priority = 2 if within camera frustum + camera distance
     priority = 3 otherwise
   tied scores: prefer higher CumulativeHitCount

2. Compute current visible-node count.
   For each expanded territory: contribute its member count.
   For each collapsed territory: contribute 1.

3. If visible_count > budget:
     Sort territories by descending priority.
     Walk from priority 3 → 1, collapsing expanded territories until under budget.

4. If visible_count < budget * hysteresis (default 0.7):
     Sort territories by ascending priority.
     Walk from priority 1 → 3, expanding collapsed territories while staying under budget.

5. Apply hysteresis to prevent flicker.
```

### 23.3 Edge rendering

Single global `ULineBatchComponent` for all edges (or Niagara ribbons for active flows). Reduces per-frame overhead substantially compared to one mesh per edge.

Edge cull distances are NOT applied in territory mode (geographic world is intentionally large; cull distances designed for the ring layout would swallow continental edges).

### 23.4 Texture caching

Country flags, archetype materials, favicons all cached process-globally via a `UEngineSubsystem`. First load may stall briefly; subsequent loads are O(1).

### 23.5 Profiling

Built-in profiling overlay (`Settings → Advanced → Profiler overlay`) shows:
- Frame time + breakdown.
- Per-agent message rate + latency.
- BP graph hot spots (top 10 BP graphs by execution time).
- Memory usage per subsystem.

For deeper profiling, UE's Insights / `stat unit` / `stat scenerendering` are the standard tools.

## 24. Build, Run, Package

### 24.1 Prerequisites

- macOS 14+ Apple Silicon (primary), Linux x86_64/aarch64 (secondary), Windows 11+ (tertiary).
- Unreal Engine 5.7+.
- Redis 7.0+ on `127.0.0.1:6379` (per agent host).
- CMake 3.20+ for the agent.
- libpcap, libnl (Linux), or platform equivalents for the agent.
- OpenSSL 3.0+ for the agent's TLS server.

### 24.2 Build

```bash
git clone <repo> ~/packetsonde
cd ~/packetsonde

# Build agent
cd agent
cmake -B build && cmake --build build -j8
cd ..

# Open UE5 project
open packetsonde.uproject     # macOS
# or click in Epic Games Launcher
```

### 24.3 Run

```bash
# Start Redis if not already running
redis-server

# Start the agent (typically setuid for ARP/raw)
sudo ./agent/build/packetsonde-agent &

# Launch the editor
./rebuild.sh
```

### 24.4 Package

For distribution:
- **macOS** — `.app` bundle via UE5 packaging; agent installed as launchd daemon (`com.packetsonde.agent.plist`).
- **Linux** — `.deb`/`.rpm` for the agent (existing scripts in `agent/debian/`, `agent/freebsd/`); Flatpak / AppImage for the client.
- **Windows** — single installer registering the agent as a Windows service.

Distribution is out of scope for v1. v1 target: editor-only personal use.

## 25. Project Layout

```
packetsonde/
├── agent/                              # C++ daemon (existing)
│   ├── conf/                           # asn-orgs.json, iata-airports.json, packetsonde.conf.default
│   ├── include/, src/, tests/
│   ├── debian/, freebsd/
│   ├── CMakeLists.txt
│   └── ...
├── assets/                             # Static assets imported by UE
│   ├── flags/                          # 254 country flags by ISO 3166-1 alpha-2
│   ├── splash/                         # Splash sonde mesh, digit-plane shader
│   └── packetsonde.png                 # Brand mark
├── docs/
│   ├── specs/
│   │   └── whitepaper.md               # This document
│   └── plans/
│       └── master-plan.md              # Implementation plan
├── Source/                             # UE5 C++ modules (added in Phase 0)
│   ├── packetsonde/                    # Core: data + datastore + Redis bridge
│   ├── packetsondeAdapters/            # Discovery, NetFlow, traceroute, packet capture, remote agent link
│   ├── packetsondeViz/                 # Visualization C++ base classes
│   └── packetsondeUI/                  # UI C++ base classes
├── Content/                            # UE5 content (added in Phase 0)
│   ├── Blueprints/
│   │   ├── Actors/                     # BP_TerritoryPlatform, BP_HostMember, BP_Edge, etc.
│   │   ├── Widgets/                    # WBP_Inspector, WBP_CommandPalette, etc.
│   │   ├── Modes/                      # BP_ModeStateMachine
│   │   ├── Lenses/                     # BP_LensByOrg, BP_LensByRole, etc.
│   │   ├── Cameras/                    # BP_OrbitCamera, BP_FlyToCamera, etc.
│   │   └── Discovery/                  # BP_DiscoveryFlow, BP_PairingDialog
│   ├── Materials/                      # M_FlagBillboard, archetype materials, edge materials
│   ├── UI/Flags/                       # Country flag textures (imported from assets/)
│   ├── Splash/                         # Splash assets
│   └── Niagara/                        # FX systems for flows, anomalies, splash ripple
├── Config/                             # UE5 project config
│   ├── DefaultEngine.ini
│   ├── DefaultGame.ini
│   ├── DefaultInput.ini                # Enhanced Input mappings
│   └── Tags/                           # GameplayTags definitions
├── packetsonde.uproject                # UE5 project file
├── rebuild.sh                          # Convenience build/launch script (existing pattern)
├── .gitignore
├── README.md
└── LICENSE
```

## 26. Configuration Schemas

### 26.1 `agent/conf/asn-orgs.json`

```json
[
  {
    "Name": "Cloudflare",
    "DisplayName": "Cloudflare",
    "ASNs": [13335, 209242, 14789, 132892],
    "Color": [0.95, 0.50, 0.13, 1.0],
    "Role": "CDN",
    "StyleArchetype": "mesh",
    "bStateAligned": false,
    "Tags": ["Org.Role.CDN", "Org.Region.Global"],
    "WebsitePrefix": "cloudflare.com"
  },
  {
    "Name": "Google",
    "DisplayName": "Google",
    "ASNs": [15169, 36040, 36384, 36492, 36561, 43515, 19527, 396982],
    "Color": [0.27, 0.45, 1.0, 1.0],
    "Role": "Hyperscaler",
    "StyleArchetype": "citadel",
    "bStateAligned": false,
    "Tags": ["Org.Role.Hyperscaler", "Org.Region.US"],
    "WebsitePrefix": "google.com"
  }
]
```

### 26.2 `agent/conf/iata-airports.json`

```json
[
  {"code":"IAD","city":"Ashburn","country":"US","lat":38.9445,"lon":-77.4558,"continent":"NA"},
  {"code":"NRT","city":"Tokyo","country":"JP","lat":35.7647,"lon":140.3863,"continent":"AS"}
]
```

### 26.3 `agent/conf/packetsonde.conf.default`

(Existing format, extended for new features.)

```ini
[agent]
listen_port = 7891
listen_host = 0.0.0.0
log_level = info
log_destination = syslog

[redis]
host = 127.0.0.1
port = 6379
db = 0

[discovery]
mdns_advertise = true
mdns_service_type = _packetsonde._tcp
udp_broadcast_listen = true
udp_broadcast_port = 7892

[capture]
interfaces = all
bpf_filter = ip
buffer_size_mb = 16

[netflow]
listen_port = 2055
v9_template_persist = true

[traceroute]
backend = nmap
default_max_hops = 30
default_concurrent = 3
```

### 26.4 `~/.config/packetsonde/agents.json` (per-user, editor-side)

Per §6.6.

### 26.5 `~/.local/share/packetsonde/keys/`

```
~/.local/share/packetsonde/keys/
├── client-private.pem    # Ed25519 private key (mode 0600)
├── client-public.pem     # Ed25519 public key
└── trusted-agents.json   # cache of validated agent fingerprints
```

### 26.6 `~/.local/share/packetsonde/notes.json`

Per-user personal annotations, tags, custom names. Not pushed to any agent. Schema:

```json
{
  "notes": {
    "<entity-id>": {
      "text": "ad tracker — investigated 2026-04-27",
      "tags": ["adtracker.confirmed"],
      "created_sec": 1714237200,
      "updated_sec": 1714240800
    }
  }
}
```

### 26.7 `~/.config/packetsonde/adapters.json`

Per-user, editor-side. Schema:

```json
{
  "adapters": [
    {
      "id": "adapter.kubernetes",
      "instance": "prod-us-east",
      "enabled": true,
      "config": {
        "kubeconfig": "~/.kube/prod",
        "context": "prod-us-east",
        "watch_resources": ["pods", "services", "nodes", "namespaces", "deployments"],
        "refresh_interval_sec": 15,
        "default_lens": "lens.kubernetes.pod-fleet"
      }
    },
    {
      "id": "adapter.elasticsearch",
      "instance": "lab-cluster",
      "enabled": true,
      "config": {
        "endpoint": "https://es.lab.local:9200",
        "auth": { "type": "apikey", "key_ref": "keychain://es.lab.local/apikey" },
        "verify_tls": true,
        "ca_cert": "~/.config/packetsonde/ca/lab.pem",
        "refresh_interval_sec": 10,
        "task_refresh_interval_sec": 2,
        "default_lens": "lens.elasticsearch.cluster-health"
      }
    },
    {
      "id": "adapter.proxmox",
      "instance": "lab-cluster",
      "enabled": true,
      "config": {
        "endpoint": "https://pve1.lab.local:8006",
        "auth": { "type": "token", "user": "monitor@pve", "token_ref": "keychain://pve1.lab.local/token" },
        "refresh_interval_sec": 30,
        "default_lens": "lens.proxmox.utilization"
      }
    },
    {
      "id": "adapter.netbox",
      "instance": "main",
      "enabled": true,
      "config": {
        "endpoint": "https://netbox.example.com",
        "auth": { "type": "token", "token_ref": "keychain://netbox.example.com/token" },
        "refresh_interval_sec": 300,
        "include_devices": true,
        "include_circuits": true,
        "include_cables": true
      }
    }
  ]
}
```

`*_ref` fields point to OS keychain entries rather than embedding secrets in the file.

### 26.8 `~/.local/share/packetsonde/link-annotations.json`

Per-user link annotations. Schema:

```json
{
  "annotations": {
    "<link-guid>": {
      "Note": "Flaky during peak hours — investigated 2026-04-27",
      "CustomName": "Comcast east transit (problematic)",
      "Severity": "Watch",
      "Tags": ["Link.Status.Flaky", "Link.Class.Transit"],
      "CreatedSec": 1714237200,
      "UpdatedSec": 1714240800,
      "CreatedByClientId": "ed25519:abcd...",
      "AttachmentRefs": []
    }
  }
}
```

### 26.9 GameplayTag taxonomy

Tags defined in `Config/Tags/Default.ini` (UE GameplayTag system).

```
Org.Role.Hyperscaler
Org.Role.CDN
Org.Role.Tier1
Org.Role.ResidentialISP
Org.Role.AdTracker
Org.Role.Email
Org.Role.DNS
Org.Role.Hosting
Org.Role.Government
Org.Role.Unknown
Org.Region.US
Org.Region.EU
Org.Region.APAC
Org.Region.Global

Anomaly.NewTerritory
Anomaly.NewAnycastMetro
Anomaly.NewLastHopFingerprint
Anomaly.UnexpectedRoleCluster
Anomaly.GeographicOutlier
Anomaly.ASPathChange
Anomaly.AgentLost

Capability.Read
Capability.Probe
Capability.Capture
Capability.Configure

Lens.ByOrg
Lens.ByRole
Lens.ByDevice
Lens.ByRecency
Lens.ByAnomaly
Lens.ByCountry
Lens.ByConfidence
Lens.ByAgent

Adapter.Cap.Read
Adapter.Cap.Refresh
Adapter.Cap.Subscribe
Adapter.Cap.Annotate
Adapter.Cap.Command

Container.Type.OrgTerritory
Container.Type.K8sCluster
Container.Type.K8sNamespace
Container.Type.K8sPod
Container.Type.K8sService
Container.Type.K8sNode
Container.Type.ProxmoxCluster
Container.Type.ProxmoxHost
Container.Type.ProxmoxVM
Container.Type.ProxmoxLXC
Container.Type.ESCluster
Container.Type.ESNode
Container.Type.ESIndex
Container.Type.ESShard
Container.Type.NetboxRegion
Container.Type.NetboxSite
Container.Type.NetboxRack
Container.Type.NetboxDevice

Link.Severity.Normal
Link.Severity.Watch
Link.Severity.Concerning
Link.Severity.Critical
Link.Status.Flaky
Link.Status.Stable
Link.Class.Backbone
Link.Class.Transit
Link.Class.Peering
Link.Class.LastMile
Link.Investigated.True
Link.Investigated.False
```

## 27. Open Questions and Risks

- **Long-tail org coverage** — uncurated orgs render as slabs with golden-angle hue. If the long tail dominates, the world looks generic. Mitigation: heuristic role classification on import, optional crowd-curated catalog.
- **Anycast ambiguity for stationary single-agent users** — single-vantage observation can't distinguish anycast from route changes. Mitigation: multi-agent setups, longitudinal accumulation, eventual cross-user pooling.
- **Privacy** — packetsonde records every destination contacted; the data is the user's own but exposure is sensitive. Mitigation: explicit data ownership, no telemetry, opt-in pooling, encrypted transport between agents and editor.
- **Visual identity scope creep** — per-Org branded archetypes can absorb arbitrary art effort. Mitigation: ship simple procedural archetypes first, defer hand-crafted assets.
- **Geographic scale tuning** — 200 u/° puts the world at 72k across; might be cumbersome. Mitigation: settings-tunable, smart frame-world camera.
- **Limbo aesthetic** — currently a blank disc; should be visually distinctive. Planned V2.
- **Multi-agent UX clarity** — when 10 agents are connected, the world is busy. Mitigation: per-agent toggle, "By Agent" lens, agent-aware filtering.
- **BP performance ceiling** — heavy BP logic on the game thread can stutter. Mitigation: BP profiler discipline, push hot paths to C++ when needed, async BP nodes for slow operations.

## 28. Roadmap

Indicative phases. Each gets a separate plan document in `docs/plans/`.

1. **Phase 0** — UE5 project scaffolding. Module structure. Stock UE5 plugin imports (Common UI, Enhanced Input, GameplayTags, Niagara, Geometry Script). World subsystem skeleton with empty implementations. Splash widget shell. Goal: launchable editor with a working splash and an empty world.

2. **Phase 1** — Local agent connectivity. Redis client. Agent IPC. Datastore populates from agent observations. Verify the data flow in BP debugger using stub visualizations.

3. **Phase 2** — Hop-mode visualization MVP. `BP_HostMember` actors at simple positions, `BP_Edge` actors connecting them, basic camera orbit. Verify data flow.

4. **Phase 3** — Inference (metro, org). Nodes carry MetroId/OrgId. Inspector reads them.

5. **Phase 4** — Territory mode V1. `OrgTerritory` containers, geographic placement, `BP_TerritoryPlatform` spawn, mode-toggle state machine in BP, collapse hides members, edge retargeting works.

6. **Phase 5** — Country flag billboards (custom material with `Texture` parameter), accumulation visual scaling.

7. **Phase 6** — Anycast object model. Registry, observation pipeline, anomaly events.

8. **Phase 7** — Visual identity V1. Archetype meshes per role via Geometry Script. Org overlays via material parameters. Long-tail heuristic role classification.

9. **Phase 8** — Interactive links. Edge selection. Link inspector with Identity / Performance / Path Context tabs. Link annotation persistence.

10. **Phase 9** — Forensics overlays. Aggregation lenses, anomaly side panel, time scrubber.

11. **Phase 10** — UI polish. Action bar, command palette, queue monitor, settings, casual mode. Common UI integration.

12. **Phase 11** — Performance. LOD policy, render-budget enforcement.

13. **Phase 12** — Service-architecture adapter framework. `UPacketsondeAdapter` base, adapter registry, configuration loader, generic inspector tab support, BP authoring helpers.

14. **Phase 13** — First built-in adapter (Proxmox). Demonstrates the framework end-to-end. Cluster / host / VM / LXC / storage-pool / virtual-network entities flow into the data model with hierarchy (cluster → host → VM/LXC). Default-archetype rendering only. Proxmox-first because: (a) HTTP API is well-defined and stable, (b) the hierarchy is shallower and easier to validate than K8s, (c) the user has a Proxmox lab to test against, (d) Proxmox VMs cleanly demonstrate the adapter-identity overlay (a VM is *also* a network host with its own IP, ARP-discoverable by the agent, so the K8s-like cross-adapter pattern surfaces immediately).

15. **Phase 14** — Render lens framework. `IPacketsondeRenderLens` interface, lens registry, lens picker UI, per-entity owner-lens routing, composition with territory mode.

16. **Phase 15** — Proxmox render lens (resource-utilization view). Hosts as buildings, VMs/LXCs as rooms inside, fluid-level animations for CPU/RAM/disk, live migrations animated as VMs moving between hosts. Validates the render-lens framework with a polished example.

17. **Phase 16** — Additional adapters in priority order: Kubernetes, Elasticsearch, NetBox, Docker. Each ships with at least default-archetype rendering. Polished render lenses follow as art-track allows.

18. **Phase 17** — Link enrichment sources. LLDP (passive, agent), SNMP (poll-based), BGP (external collector), sFlow / IPFIX (NetFlow listener extension). Enrichment surfaces in the link inspector.

19. **Phase 18** — Remote agent connectivity. TLS WebSocket client. mTLS. Discovery (mDNS + signed broadcast). Pairing flow.

20. **Phase 19** — Multi-agent visualization. Per-agent Home territories, "By Agent" lens, agent-aware filtering.

21. **Phase 20** — Packaging and distribution.

22. **Phase 21+** — Visual identity V2 (hand-crafted meshes for famous orgs), session recording, cross-user pooling, mobile companion, plugin SDK, additional service-architecture adapters (Consul, Nomad, AWS/Azure/GCP cloud assets, OPNsense, OpenWRT).

## 29. Glossary

- **Adapter** — a pluggable component that ingests data from a service-toolset (K8s, Proxmox, ES, NetBox, etc.) and translates it into packetsonde's data model. Implements `UPacketsondeAdapter`.
- **Adapter identity** — one of possibly several identifiers a node carries — e.g. a Linux box may simultaneously be a Proxmox VM, a K8s node, and a NetBox device. Stored as `FAdapterIdentity` per overlay.
- **Adapter render lens** — see *render lens*.
- **Agent** — a `packetsonde-agent` instance. Owns a Redis. Observes a network from one vantage point. May be local or remote.
- **Aggregation lens** — visualization filter that tints/highlights existing visuals based on some attribute (org, role, recency, anomaly, etc.). Distinct from a render lens.
- **Anycast** — a single IP served from multiple physical POPs; routing fabric decides which serves a given client.
- **AS / ASN** — Autonomous System; a routing domain with a globally-unique 32-bit Autonomous System Number.
- **BFD** — Bidirectional Forwarding Detection; sub-second link-failure detection protocol.
- **BGP** — Border Gateway Protocol; how ASes announce reachability.
- **BP** — Blueprint; UE5's visual scripting system.
- **CDN** — Content Delivery Network.
- **CDP** — Cisco Discovery Protocol; Cisco's proprietary equivalent of LLDP.
- **Common UI** — UE5 plugin providing layered UI, focus management, themes.
- **Cyberdeck mode / Territory mode** — the collapsed AS-path-style spatial view.
- **DNS-SD** — DNS Service Discovery; service-advertising layer over mDNS.
- **ECMP** — Equal-Cost Multi-Path; routers selecting between equivalent paths per-flow.
- **Ed25519** — modern elliptic-curve signature scheme. Used for identity keys.
- **Enhanced Input** — UE5's modern input system.
- **Enrichment** — additional data attached to a node or link from sources beyond the primary discovery (LLDP, SNMP, BGP, BFD, sFlow, etc.).
- **Equirectangular** — a simple map projection where lat/lon become orthogonal Y/X axes.
- **Fingerprint** — SHA-256 hash of an Ed25519 public key, hex-encoded with `ed25519:` prefix.
- **GameplayTags** — UE5's hierarchical tag system.
- **Geometry Script** — UE5's runtime procedural mesh generation framework.
- **GeoIP** — a database mapping IP address ranges to approximate geographic locations.
- **Hop mode** — alternate display mode showing every node and edge individually.
- **IATA code** — a 3-letter airport identifier maintained by IATA. Hostname conventions in operators' reverse-DNS often embed IATA codes for the colocation city.
- **IPC** — Inter-Process Communication.
- **IPFIX** — IP Flow Information Export; IETF-standardized flow record protocol successor to NetFlow.
- **Lens** — see *aggregation lens*, *render lens*.
- **LLDP** — Link Layer Discovery Protocol; vendor-neutral link adjacency discovery for Ethernet devices (IEEE 802.1AB).
- **LOD** — Level of Detail.
- **mDNS** — Multicast DNS; local-network service discovery.
- **Metro** — in packetsonde, a coarse geographic centroid; usually a city. A territory's place.
- **mTLS** — mutual TLS; both ends of a TLS connection authenticate each other.
- **Niagara** — UE5's particle effects system.
- **Org** — in packetsonde, an administrative network entity. A territory's identity.
- **POP** — Point of Presence; a physical site where a network operator has equipment.
- **Render lens** — per-adapter visual *replacement* for that adapter's entities — e.g. the Elasticsearch lens drawing nodes as racks of indices, with shard relocations animated. Distinct from aggregation lens, which only tints.
- **sFlow** — packet sampling protocol for traffic flow visibility.
- **SNMP** — Simple Network Management Protocol; widely-deployed network device polling protocol.
- **Sonde** — a probe or scout. The bobber that drops onto the binary water surface in the splash.
- **Subsystem** — UE5's `UEngineSubsystem` / `UGameInstanceSubsystem` / `UWorldSubsystem` / `ULocalPlayerSubsystem`. Process- / game-instance- / world- / player-scoped singletons exposed to BP.
- **Territory** — a `(Org × Metro)` grouping that becomes one super-node in territory mode.
- **TLS** — Transport Layer Security.
- **TOFU** — Trust On First Use; accept a key on first sight, then pin it.
- **UMG** — Unreal Motion Graphics; UE5's UI framework.
- **WebSocket** — bidirectional message protocol over a single TCP connection, often run over TLS.

---

*End of whitepaper.*
