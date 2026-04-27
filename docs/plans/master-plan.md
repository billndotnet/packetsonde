# packetsonde — Master Implementation Plan

This document sequences every phase of the build, with each phase getting its own detailed task plan in `docs/plans/phase-NN-*.md`. The whitepaper (`docs/specs/whitepaper.md`) is the source of truth for what we're building; this document is the source of truth for the order in which we build it.

## Guiding rules

- **The whitepaper drives.** When this plan and the whitepaper disagree, the whitepaper wins; this plan gets corrected.
- **Each phase ends with something a user can hold.** No phase is "internal scaffolding only" — every phase ends with a visible artifact in the editor that the user can interact with.
- **Lean BP for visuals, UX, policy. Lean C++ for data, integration, performance.** §10 of the whitepaper codifies the boundary.
- **Don't reinvent wheels.** Common UI, Enhanced Input, GameplayTags, Niagara, Geometry Script are standard. Mass and gRPC are not (decided in §11).
- **Verify in the BP debugger.** Every phase exercises the BP debugger somewhere visible. We pay the cost of BP-heavy architecture to get this affordance; we use it.
- **Frequent commits.** Each task in each phase ends with a commit; phases end with a tag.

## Phase order (matches §28 of the whitepaper)

| Phase | Title | Outcome |
|-------|-------|---------|
| **0** | UE5 project scaffolding | Launchable editor + splash + empty world |
| **1** | Local agent connectivity | Datastore populates from agent observations; verifiable in BP |
| **2** | Hop-mode visualization MVP | Nodes + edges spawn as BP actors; basic camera |
| **3** | Inference (metro, org) | Inspector shows MetroId/OrgId |
| **4** | Territory mode V1 | OrgTerritory containers, geographic placement, mode toggle |
| **5** | Country flag billboards + accumulation visual scaling | Flags at boundary markers, familiarity tiers |
| **6** | Anycast object model | Registry, observation pipeline, anomaly events |
| **7** | Visual identity V1 | Archetype meshes per role via Geometry Script |
| **8** | Interactive links | Edge selection, link inspector, annotations |
| **9** | Forensics overlays | Aggregation lenses, anomaly side panel, time scrubber |
| **10** | UI polish | Action bar, command palette, queue monitor, settings |
| **11** | Performance | LOD policy, render-budget enforcement |
| **12** | Adapter framework | UPacketsondeAdapter base + registry + BP authoring helpers |
| **13** | First adapter (Proxmox) | End-to-end adapter validation |
| **14** | Render lens framework | IPacketsondeRenderLens, lens registry, lens picker |
| **15** | Proxmox render lens | Polished resource-utilization view |
| **16** | Additional adapters (K8s, ES, NetBox, Docker) | Default-archetype rendering each |
| **17** | Link enrichment | LLDP, SNMP, BGP, sFlow integration |
| **18** | Remote agent connectivity | TLS WebSocket + mTLS + discovery + pairing |
| **19** | Multi-agent visualization | Per-agent Home, By-Agent lens |
| **20** | Packaging and distribution | Mac/Linux/Windows installers |
| **21+** | Visual identity V2, session recording, cross-user pooling, more adapters | Polish and breadth |

## Per-phase plan template

Every phase plan follows this structure:

1. **Goal** — one sentence.
2. **Architecture** — 2–3 sentences describing the approach.
3. **Reference** — which whitepaper sections drive this phase.
4. **Pre-flight checks** — environment / dependencies needed.
5. **Tasks** — bite-sized (5–10 min each), TDD-shaped where possible, every task ends with a commit.
6. **Manual verification** — concrete checklist the user runs at the end.
7. **Lessons baked in** — failure modes from earlier work that this plan pre-empts.

## Open questions before Phase 0 starts

A few choices need user confirmation before scaffolding:

1. **UE5 project template.** Empty C++ vs Games > Blank vs Visualization > Architecture. Recommend: `Games > Blank` (gives us the standard `GameInstance` / `GameMode` / `PlayerController` machinery; we do non-game things on top but the framework is well-understood).
2. **Renderer.** Forward shading vs deferred. Recommend: deferred for the visual-identity work, forward if we hit perf walls. Default for `Games > Blank` is deferred.
3. **Target platforms.** Mac (primary), Linux, Windows. v1 focus: Mac first since that's the user's daily driver.
4. **Module count.** §10.2 named four modules (`packetsonde`, `packetsondeAdapters`, `packetsondeViz`, `packetsondeUI`). Confirm or simplify to three.
5. **Plugin selection.** Confirm: Common UI, Enhanced Input, GameplayTags, Niagara, Geometry Script. Skip: Mass, Common Conversation, Common Save.

These decisions are captured in the Phase 0 plan.
