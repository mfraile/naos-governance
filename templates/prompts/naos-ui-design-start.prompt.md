# UI/UX Design Workflow Starter

**Version**: 2.0.0
**Purpose**: Interactive workflow for designing or adding UI screens

> **Standards reference**: [UI/UX Design Guidelines](../instructions/ui-design.instructions.md)
>
> **[ADAPT]**: Replace the screen catalog reference below with your project's UI catalog path.
> Screen catalog: `[ADAPT: your screen catalog path, e.g., docs/ui/screen-catalog.md]`

---

## Step 1: Screen Inventory

```bash
# [ADAPT: find your UI pages/screens]
find [ADAPT: your frontend pages dir] -name "page.tsx" | sort

# Check your screen catalog
cat [ADAPT: your screen catalog path] | grep -E "Screen|screen|route" | head -20
```

**Screen status legend**: ✅ Implemented | 📐 Designed | 🔵 In Progress | 🔴 Planned

---

## Step 2: Interactive Selection

Prompt the user:

```
What would you like to do?
1. [NEW]    — Design a new screen from scratch
2. [MODIFY] — Modify an existing implemented screen
3. [ENHANCE]— Convert a designed screen to implementation
4. [CANCEL] — Exit workflow
```

---

## Step 3: Design

When designing a new or enhanced screen:

1. **Stage**: Classify the work as `concept_exploration`, `wireframe_or_prototype`, `implementation_ready_design`, or `post_implementation_review`
2. **Brief**: Describe the screen — user persona, goals, components needed
3. **Dependencies**: Identify FR/NFR/task/AC refs, data/API/state refs, privacy/accessibility constraints, and open dependency questions appropriate for the stage
4. **Brand**: Use your project's design system guidelines (see `.github/instructions/ui-design.instructions.md`)
5. **Evidence**: Plan token refs, screenshot/state refs, accessibility/performance refs, generator provenance, and human review refs before implementation-ready handoff
6. **Iterate**: Until branding ✓, accessibility ✓, privacy (if customer-facing) ✓

**[ADAPT] Design tool prompt template**:
```
Design a professional [screen type] for [Your Product Name].
Tech: [ADAPT: your frontend stack, e.g., Next.js 16, React 19, TypeScript, Radix UI, Tailwind]
User: [persona]
Goals: [3-5 goals]
Brand: [ADAPT: your primary color, accent color, font, spacing, accessibility standard]
Similar to: [ADAPT: existing screens if any]
```

---

## Step 4: Document & Handoff

1. Create spec: `docs/ui/screens/[screen-name]-spec.md`
2. Create implementation task in `naos/TASK_REGISTRY.yaml` (if not already listed)
3. Update `[ADAPT: your screen catalog path]` with new screen entry
4. Optional: if the project uses `naos/design_traceability.yaml`, assign stable `object_id` values for key screens/components and run `naos design-traceability --profile [ADAPT: profile]`
5. Optional: if the project uses `naos/ui_experience_quality.yaml`, add or update screen evidence entries and run `naos ui-experience-quality --profile [ADAPT: profile]`

---

## Step 5: Validation Checklist

```markdown
- [ ] Design spec in docs/ui/screens/[name]-spec.md
- [ ] Branding: [ADAPT: your brand colors/fonts/assets] applied
- [ ] Accessibility: WCAG 2.1 AA, keyboard nav, ARIA labels
- [ ] Privacy: Data minimization pattern if customer-facing
- [ ] Optional design traceability updated if enabled; design refs are references only, not sync or quality proof
- [ ] Optional UI experience quality updated if enabled; quality refs are review evidence only, not design approval or quality proof
- [ ] [ADAPT: TypeScript types from your types file]
- [ ] [ADAPT: UI primitives from your component library — no new libs without approval]
```

---

**[ADAPT] Notes for your project**:
- Replace all `[ADAPT]` markers with your project's actual values
- Update `.github/instructions/ui-design.instructions.md` with your brand guidelines
- Track your UI screens in a catalog file (e.g., `docs/ui/screen-catalog.md`)
