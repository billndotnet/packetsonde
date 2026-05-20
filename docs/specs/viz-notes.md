# Visualization design notes

**Purpose:** Capture observations during toolkit work that should inform the eventual visualization layer. The whitepaper at `docs/specs/whitepaper.md` describes a visualization vision from before the toolkit existed; this file accumulates evidence-based corrections.

**Discipline:** When you find yourself wishing you could *see* something while using the toolkit — a relationship, a pattern, a comparison — write it down here. When you spot a query / aggregation that you ran by hand more than once, write it down. When a finding kind feels under- or over-represented in the data, write it down.

**What this file is not:** a design. It's a notebook. The next visualization design will be written from this notebook (and whatever else has accumulated), not from the whitepaper.

---

## Entries

*(Add dated entries below. Format: `## YYYY-MM-DD — short title` then a paragraph or two. Concrete observations, not speculation.)*

---

## 2026-05-19 — file created

Toolkit work just shipped v1. No real usage data yet. First real entries should appear after the first sustained use against an actual network (engagement, lab, home).

A few things I already suspect from the toolkit design that will matter for visualization:

- **Time is implicit in everything.** Findings carry `ts`, `run_id`, and the agent stream is continuous. Any viz that flattens time (just "what's there now") is throwing away information. The visual model needs to natively represent "this thing was true at time T."
- **Relationships are sparse but rich.** Each finding has a target; many findings share a `host` or `via_agent`; the agent's observation pipeline produces flows that link hosts to other hosts. The visual model needs to express "these N findings all attach to the same logical thing" without becoming a hairball.
- **Severity matters more than kind for first-glance.** Five severity levels, dozens of kinds (and growing). On a dashboard the operator wants to see "is there anything critical here" before they see "what kinds of things are there."

None of these are conclusions, only hypotheses to test against real data.
