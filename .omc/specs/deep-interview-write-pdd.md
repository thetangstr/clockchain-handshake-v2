# Deep Interview Spec: write-pdd (Product Design Document skill)

## Metadata
- Interview ID: di-writeprd-20260805
- Rounds: 7 + Round 0 topology
- Final Ambiguity: 19%
- Type: brownfield
- Threshold: 0.2 (source: default)
- Generated: 2026-08-05
- Status: PASSED

## Clarity Breakdown
| Dimension | Score | Weight | Weighted |
|-----------|-------|--------|----------|
| Goal | 0.85 | 0.35 | 0.298 |
| Constraints | 0.75 | 0.25 | 0.188 |
| Success Criteria | 0.78 | 0.25 | 0.195 |
| Context | 0.85 | 0.15 | 0.128 |
| **Total Clarity** | | | **0.808** |
| **Ambiguity** | | | **0.192** |

## Topology
| Component | Status | Coverage |
|-----------|--------|----------|
| Artifact identity & disposition | active | Replace write-prd, rename to write-pdd across 3 symlinks |
| Document structure | active | Spine + 12 sections; UX/AX/Arch always separate; AX sub-parts encoded |
| Interview design | active | Hybrid: spine-interview → draft w/ ASSUMPTION → score → gap-fill |
| Scoring rubric | active | Layered: L1 product-bet (13) + L2 design surface (~6); two scores, both pass |

## Goal
Redesign the canonical `write-prd` skill into **`write-pdd`**, which produces a **Product Design Document (PDD)** — a single artifact merging product requirements, architecture, and experience design (UX + AX), parameterized by user-type. Built for AI/harness-era products where the experience design and architecture are as load-bearing as the product thesis, and where the document is read by humans but pre-read by an AI that should recommend the human read it themselves.

## The Writing Rules (prose contract — governs the skill AND every PDD it produces)
1. **Concise** on concepts, situations, requirements.
2. **Example for every concept** — human-sounding, easy to understand.
3. **Maximally readable** — formatting, bullets, color where the medium allows; no long paragraphs; not an essay. Scannable in ~5 minutes.
4. **Always focus on user impact** — human or agent.
5. **Always tie back** to the product's overall goal and the metrics that measure it.
6. **Every requirement ties to a success criterion/metric. Every non-goal also ties to a criterion** — that is *why* it's cut, not "out of room."
7. **Clear-cut, sharp, to the point.**
8. **Sound human, not machine.** The doc is a **joy to read** — so much so that the AI pre-reader actively recommends the human read it themselves rather than accept a summary. Two audiences: the human reader and the AI pre-reader; satisfy both (plain human prose + AI-parseable headings/labels/metrics).

## Document Structure — the PDD
**Spine:** the **Audience & user-type** section is declared first and sets the mode for everything below it: **human / agent / both.**

Sections (drop any that don't apply; mark N/A rather than pad):
1. **The bet** — one-sentence thesis; why this should exist.
2. **Audience & user-type** *(spine)* — human / agent / both, declared up front.
3. **Problem** — the recalled instance; current alternatives by name; why they fail.
4. **Critical journeys** — per journey: trigger / today / after / decision-changed / evidence-or-ASSUMPTION.
5. **Experience** — branches on user-type:
   - **UX** (human): surfaces, flows, the moment it feels right.
   - **AX** (agent) — expected sub-parts (generalized from clockchain practice): **tool surface** (`contract_*` / API the agent consumes) · **schema** (inputs/outputs/types) · **error strings + retry/token/cost semantics** · **failure catalog** (modes + handling) · **cold-agent harness** (how a fresh, context-free agent succeeds) · **golden transcripts** (examples that define correct behavior).
6. **Architecture** — the system behind the experience (services, data, model selection, eval infra). **Always a separate section**, even for pure-agent products (the Agent Contract is the surface; this is the system).
7. **Metrics & kill criteria** — every metric tied to a threshold + a decision.
8. **Requirements** — each tied to a metric; no metric → cut.
9. **Non-goals** — each tied to the metric it doesn't serve.
10. **Risks** — incl. agent-specific: model dependency, eval coverage, autonomy boundary, failure modes.
11. **Launch & distribution** — how it reaches users (for agents: registry / MCP / API discovery).
12. **Scope** — in / out / later.

## Interview Design — hybrid
1. **Spine-interview** (bounded, ~5 questions, one at a time): bet → audience/user-type → the 2-3 critical journeys. Never ask what context already answers.
2. **Draft** the full PDD with `ASSUMPTION:` markers on everything inferred.
3. **Score** each section against the layered rubric.
4. **Gap-fill**: interrogate only the weakest sections; stop when the done-bar (below) is met.

## Scoring Rubric — layered
**Layer 1 — Product bet (13 dims, 0-5, max 65):** audience precision · problem pull · non-obvious insight · wedge & mechanism · PMF path · market & upside · strategic alignment · GTM & distribution · business model · defensibility · evidence & metrics · scope discipline · risk honesty. *(drops former "product excellence" — folds into Layer 2 experience.)*
- Critical dims (must be ≥4): audience, problem, insight, PMF, market, GTM, evidence.
- Pass: 52/65 AND no critical dim below 4.

**Layer 2 — Design surface (~6 dims, 0-5, max 30):** architecture soundness · UX completeness · AX / Agent-Contract quality · launch & distribution credibility · metric-binding (every req AND non-goal tied to a metric) · joy-to-read.
- Critical dims (must be ≥4): AX/Agent-Contract quality, metric-binding.
- Pass: 22/30 AND no critical dim below 4.

**Both layers must pass.** Output is a **short scorecard** (not a 19-row essay — honors writing rule 3).

## Done-bar (lean-but-rigorous)
A PDD is "done" when:
- bet, audience, critical journeys, and metrics are **evidenced** (not assumed);
- every requirement AND every non-goal is metric-bound;
- the design surface passes a credible/not check (full sub-scorecard optional);
- the scorecard output is a short table;
- remaining unknowns carry explicit `ASSUMPTION:` labels.

## Diagrams & Flows
The PDD's architecture, journeys, and Agent Contract need real diagrams. No portable diagramming skill exists across all three tools, so `write-pdd` does not hard-depend on one:

- **Default: Mermaid** for flowcharts and sequence diagrams (journey flows, Agent Contract interaction sequences). Plain text in the PDD → renders in all three tools' markdown viewers, AI-parseable, editable. Honors the "structure for the AI" rule with zero skill dependency.
- **Delegate up** when a richer diagram earns its place (architecture, complex interaction): use the best available skill in the *current* tool — `artifact-diagramming` (Claude sessions), `architecture-diagram` / `excalidraw` (Hermes) — falling back to Mermaid or inline SVG when none is available.
- **Apply the earn-its-place principle everywhere**: a picture is included only when it shows the real mechanism (not decoration); keep diagrams legible in both light and dark themes; every diagram carries a one-line caption stating what it proves.

## Constraints
- Lives in the canonical repo `/Volumes/home/Projects_Hosted/Canonical_Agent_Skills/skills/write-pdd/` and symlinks into `~/.claude/skills`, `~/.codex/skills`, `~/.hermes/skills` via `bin/link.sh`.
- **Rename**, not add: remove `skills/write-prd/`, create `skills/write-pdd/`, re-link. Update README + memory pointer.
- File layout (default): `SKILL.md` + `references/rubric-map.md` (restructured into Layer 1 + Layer 2) + `references/templates.md` (the PDD template, parameterized by user-type). Drop the `agents/openai.yaml` harness-specific config (not portable).
- Save location for produced PDDs: detect and follow an existing repo convention (e.g. `.context/prds/`, `docs/prd/`); default `docs/pdd/YYYY-MM-DD-<slug>.md`.
- Inherits the migrated rubric content from the deleted `review-prd` (currently in `write-prd/references/rubric-map.md`) — restructure, don't lose it.

## Non-Goals
- Not a PRD reviewer/critic — that was `review-prd`, deleted; write-pdd self-scores only, no separate review handoff.
- Not idea validation (use office-hours) and not general requirements crystallization (use deep-interview).
- Not harness-specific: one portable skill, no per-tool agent configs.
- Does not force every PDD through all 12 sections — drop N/A sections rather than pad.

## Acceptance Criteria
- [ ] `skills/write-pdd/SKILL.md` exists, in the writing rules' voice, documenting the hybrid interview + layered rubric + done-bar.
- [ ] `references/rubric-map.md` restructured into Layer 1 (13) + Layer 2 (~6) with anchors, thresholds, and critical dims.
- [ ] `references/templates.md` contains the PDD template, spine-first, with UX/AX/Arch separate and AX sub-parts encoded.
- [ ] SKILL.md prose + template obey the 8 writing rules (spot-check: example per concept, no long paragraphs, metric-bound requirements).
- [ ] Old `skills/write-prd/` removed; symlinks in all 3 stores point to `write-pdd`; `bin/doctor.sh` reports healthy, 0 broken.
- [ ] README + memory pointer updated from write-prd → write-pdd.
- [ ] Propagation verified: edit canonical SKILL.md, confirm all 3 stores see it.
- [ ] Diagram guidance present: default Mermaid for flows/sequences; delegate to the tool's best diagram skill when a richer diagram earns its place; earn-its-place + dual-theme legibility rule stated.

## Assumptions Exposed & Resolved
| Assumption | Challenge | Resolution |
|---|---|---|
| AI-native concerns need their own section | User: it comes down to who the user is — human UX vs agent UX, case by case | Merged into document structure; UX/AX branch on declared user-type |
| The doc should be parseable so humans can skip it | User: the opposite — a joy to read, AI recommends the human read it | Captured as writing rule 8; AI is a pull-recommender, not a skip-layer |
| AX and Architecture collapse for agent products | User: keep them always separate | Separate sections always; Agent Contract = surface, Architecture = system |
| Full upfront interview across 12 sections | Contrarian: that's the 40-question slog you hate | Hybrid: spine-interview → draft → gap-fill weakest only |
| 19-dim scorecard | Simplifier: violates the "not an essay" rule | Layered into two short scores; output is a short table |
| Section count / done-bar | Simplifier: what's minimal viable | Lean-but-rigorous: evidenced on load-bearing parts, light elsewhere |

## Technical Context
- Brownfield: `write-prd` authored this session at `Canonical_Agent_Skills/skills/write-prd/`, symlinked into 3 stores. Full contents in context.
- The deleted `review-prd` rubric (14 product dims, CUJ score, moat falsifiers) was preserved into `write-prd/references/rubric-map.md` — that content carries forward as Layer 1.
- Clockchain practice (`.context/prds/`, AX-led design, Agent Contract focus) is the concrete reference for the AX sub-parts.
- Canonical repo is on an SMB share; symlink mechanics proven this session via `bin/link.sh`.

## Ontology (Key Entities)
| Entity | Type | Fields | Relationships |
|--------|------|--------|---------------|
| PDD | core artifact | 12 sections, spine=audience | produced by write-pdd |
| Audience/user-type | spine | human / agent / both | determines UX vs AX content |
| UX | experience (human) | surfaces, flows | part of Experience |
| AX | experience (agent) | tool surface, schema, failure catalog, cold-agent harness, golden transcripts | part of Experience; surface to Architecture's system |
| Agent Contract | AX core | contract_* tools, schema, error/retry semantics | the agent-facing surface |
| Architecture | system | services, data, model selection, eval infra | backs the Experience |
| Layer 1 rubric | scoring | 13 product dims | product-bet score |
| Layer 2 rubric | scoring | ~6 design dims | design-surface score |

## Interview Transcript
<details>
<summary>Full Q&A (7 rounds + Round 0)</summary>

**Round 0 — Topology:** 5 components proposed → user collapsed "AI-native dimensions" into document-structure ("it comes down to who the users are"). Locked 4 active components.

**R1 — Document structure / Goal:** user-type goes to the top-level spine, declared first, reshapes everything.

**R2 — Voice:** user rejected literary-voice rewrite (5× "try again"); supplied the real spec — 8 writing rules + joy-to-read bar.

**R3 — Artifact identity:** replace write-prd + rename to write-pdd (PDD).

**R4 — Document structure:** UX/AX/Arch always separate.

**R5 — Interview design (Contrarian):** hybrid — spine-interview, then draft, then gap-fill.

**R6 — Rubric:** layered, product + design, two scores both-pass.

**R7 — Done-bar (Simplifier):** lean-but-rigorous. AX sub-parts encoded.
</details>
