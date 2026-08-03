# Infographic prompt

Paste into an image generator (Midjourney, DALL·E, Ideogram) or hand to a designer.
Ideogram and DALL·E handle the embedded text best; Midjourney will need the text
added afterwards.

---

## The prompt

> A clean, modern business infographic on a light background, wide 16:9 landscape,
> corporate consulting style — the visual language of a McKinsey or Stripe explainer,
> not a crypto or sci-fi illustration. Flat vector, generous white space, one accent
> colour (deep emerald green) against neutral greys, thin confident lines, no gradients,
> no glow, no 3D, no blockchain clichés (no chains, no cubes, no glowing hexagons, no
> Bitcoin symbols).
>
> Title across the top: "Two AI agents agree on permission to pay — and prove it"
>
> The layout has four horizontal bands.
>
> Band 1, across the top: two rounded rectangles far apart, one on the left labelled
> "Payer's agent — wants proof before paying", one on the right labelled "Requestor's
> agent — wants to be paid". Each sits above a small laptop icon with a caption
> underneath: "runs on one machine" and "runs on a different machine". Between them, a
> smaller dashed-outline rectangle labelled "Mailbox — passes sealed messages, cannot
> read or change them", with thin arrows running both ways between the three boxes.
> A small padlock icon sits on each arrow.
>
> Band 2, the middle: three numbered cards left to right, evenly spaced, each with a
> short quoted line beneath the heading —
> 1. "The offer" — "Here are my exact terms."
> 2. "The acceptance" — "I accept those exact terms."
> 3. "The acknowledgement" — "Agreed. On the record."
> A thin arrow flows from card 1 to 2 to 3 to show the order matters.
>
> Band 3: a wide horizontal bar labelled "Public ledger", with three small green
> circular check marks sitting on it, one under each card above, connected by short
> vertical lines. Caption inside the bar: "Each step written down as it happens, in
> order, where anyone can look it up."
>
> Band 4, the bottom: a single wide rounded rectangle outlined in the emerald accent,
> containing "An independent checker re-reads all three receipts from scratch" with a
> smaller line under it: "It took no part in the conversation. Only it decides."
>
> A footer strip across the very bottom, emerald text, larger than the captions:
> "No money moves at any point. What is agreed is permission — and the proof of it."
>
> Professional, calm, uncluttered. Legible when projected on a screen from the back of
> a room.

---

## If the generator mangles the text

Most do, at this much copy. Two reliable fallbacks:

1. **Generate the layout only.** Strip every label from the prompt, keep the shapes
   and bands, then set the text yourself in Figma, Keynote or Google Slides.
2. **Use the SVG already built.** `/handshake/claude-v6` on the research site renders
   this exact flow as a real diagram with selectable text. Screenshot it, or lift the
   SVG from `src/components/ClaudeV6FlowDiagram.tsx` and restyle it.

## Getting the wording right

If a viewer takes away only one thing, it should be the footer line. The demo's whole
claim is that permission was *established and proven* without anything being paid — so
if a draft makes it look like a payment pipeline, the design is fighting the message
and the layout should change rather than the caption.

Two labels worth keeping verbatim, because they are doing real work:
- **"cannot read or change them"** on the mailbox — this is what makes the untrusted
  middle acceptable, and it is the first thing a technical person in the room will
  probe.
- **"It took no part in the conversation"** on the checker — this is the difference
  between an audit trail and a self-assessment.
