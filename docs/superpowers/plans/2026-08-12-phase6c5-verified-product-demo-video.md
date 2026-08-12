# Phase 6C5 Verified Product Demo Video Implementation Plan

> **For agentic workers:** REQUIRED SKILL: Use `product-demo-video` after Phase 6C4 has produced a verified presentation feed. Build two options in parallel, run business and technical critics in parallel, and iterate to the documented quality gate.

**Goal:** Produce a polished two-minute homepage-ready Clockchain demonstration showing two independently controlled agents establishing a verifiable business handshake, with every factual on-screen claim traceable to completed mechanics-proof evidence.

**Audience:** Business stakeholders first, technical evaluators second.

**Tone:** Professional, concrete, and restrained. Show what was proved; do not call the mechanics proof production-ready, secure without qualification, autonomous beyond the demonstrated mandate, or a payment flow.

**Primary format:** 1920x1080, 30 fps, H.264 MP4 plus VP9 WebM and a poster frame. Use Remotion for the final composited option because it is HTML/React-native, deterministic, reviewable, and suitable for later homepage variants. Also build a simpler browser-capture/ffmpeg option for comparison.

**Evidence gate:** No script number, identity, receipt, certificate, runtime-isolation claim, or cleanup claim may enter the render unless it is selected from the canonical Phase 6C3/6C4 proof bundle. Synthetic company names and non-sensitive business terms are permitted only when clearly labeled as the demonstration scenario.

---

### Task 1: Freeze the evidence-backed story contract

**Files:**
- Create: `video/verified-proof-schema.mjs`
- Create: `video/demo-story.mjs`
- Test: `test/video-verified-proof-schema.test.mjs`
- Test: `test/video-demo-story.test.mjs`

- [ ] Require a completed matrix proof, one selected representative run, exact public identity/receipt/certificate/runtime/cleanup fields, and source/image/helper/MCP pins.
- [ ] Reduce those facts into a seven-scene story model with timestamps and citations to proof-field JSON pointers.
- [ ] Reject missing/contradictory proof, model prose, raw logs, private paths, credentials, prompts, transcripts, or unverifiable marketing superlatives.
- [ ] Commit with Lore intent `Bind every demo claim to verified mechanics evidence`.

### Task 2: Write the two-minute script and storyboard

**Files:**
- Create: `video/script.md`
- Create: `video/storyboard.json`
- Test: `test/video-script-contract.test.mjs`

- [ ] Use the product-demo seven-scene structure and target 260-300 spoken words:
  1. Problem: agents from different companies need bounded agreement without sharing control.
  2. Solution: Clockchain provides the mandate, identity, ordering, and independent certificate boundary.
  3. Two fresh agents appear in distinct runtimes and register fresh ERC-8004 identities.
  4. Initiator proposes; Responder independently evaluates its local policy and accepts.
  5. Direct agent-to-agent messages and Clockchain commitment checkpoints establish ordered agreement.
  6. Show three receipts, one verified certificate, distinct workload identities, and teardown evidence.
  7. CTA: run the mechanics proof or schedule a live stakeholder demonstration.
- [ ] Keep sentences under 20 words, distinguish party identity from AWS workload identity, say explicitly that no payment or external business action occurred, and avoid implying Clockchain decided for either party.
- [ ] Commit with Lore intent `Explain the verified handshake without overselling it`.

### Task 3: Build two visual options in parallel

**Files (Option A):**
- Create: `video/remotion/` project and scene components
- Create: `video/remotion/render.mjs`

**Files (Option B):**
- Create: `video/browser-capture/capture.mjs`
- Create: `video/browser-capture/render.mjs`

- [ ] Option A uses the preserved research-site visual language and deterministic Remotion scenes. It animates the two party columns, direct peer path, Clockchain observation/checkpoint path, ERC-8004 registration detail, receipts, certificate, and teardown proof.
- [ ] Option B records the verified research-site presentation route in a fixed browser viewport and composites proof callouts with ffmpeg.
- [ ] Generate voiceover scene-by-scene from the approved script using the configured voice provider. If no voice credential is available, render a captioned silent review cut and leave voice generation as the only explicit external-input blocker.
- [ ] Export review MP4s and machine-readable frame/timing manifests. Do not use live production requests during rendering.

### Task 4: Run parallel business and technical critics

**Files:**
- Create: `video/reviews/business-option-a.md`
- Create: `video/reviews/technical-option-a.md`
- Create: `video/reviews/business-option-b.md`
- Create: `video/reviews/technical-option-b.md`

- [ ] Business critic scores Clarity, Professionalism, and Business Value using the product-demo rubric.
- [ ] Technical critic scores Accuracy, Credibility, and Completeness and verifies every on-screen proof claim against the bundle.
- [ ] Reject any option with a critical issue, any dimension below 7.0, or weighted score below 7.5. Select the stronger option only after both reviews.

### Task 5: Iterate and finalize homepage assets

**Files:**
- Create: `video/output/clockchain-handshake-demo.mp4`
- Create: `video/output/clockchain-handshake-demo.webm`
- Create: `video/output/clockchain-handshake-demo-poster.webp`
- Create: `video/output/manifest.json`

- [ ] Apply all critical/important fixes, re-render affected scenes, and rerun both critics for up to three loops.
- [ ] Verify 1080p/30fps, audio sync, captions, color contrast, legibility at laptop width, no secret/path leakage, and deterministic proof-field use.
- [ ] Manifest includes duration, resolution, checksums, selected proof bundle digest, source commit, renderer versions, critic scores, and known caveats.
- [ ] Commit with Lore intent `Render the stakeholder story from verified proof`.

### Task 6: Integrate the approved asset into the homepage safely

**Files:**
- Modify only the homepage component and asset manifest in the approved website repository after visual approval.
- Test: route/component test, reduced-motion test, mobile viewport test, performance budget, and link/caption checks.

- [ ] Use native `<video>` with MP4/WebM sources, poster, captions, muted inline preview, explicit controls, and `prefers-reduced-motion` behavior. Do not ship the Remotion runtime to the browser.
- [ ] Keep the full verified demo page as the evidence drill-down target.
- [ ] Verify visual regression and Lighthouse budgets before deploy.
- [ ] Commit with Lore intent `Show the verified demo without burdening the homepage`.

---

Phase 6C5 is complete only when both critics pass at 7.5 or higher with no critical issues, the final files validate, and every factual claim resolves to the retained proof bundle. A slick render without the mechanics evidence is not a valid Clockchain demo.
