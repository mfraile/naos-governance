---
name: "cookbook-ui"
description: "If-then recipes for UI/UX design. Invoke when designing screens, choosing colors, adding interactive elements, or displaying user-supplied content."
parameters: []
---

# Cookbook: UI Design

## When to Use

Use this skill when designing screens, choosing colors, adding interactive
elements, or displaying user-supplied content.

> Extracted from `.github/instructions/ui-design.instructions.md`. See that file for full domain rules.

### If: Designing a new screen or redesigning an existing one
**Then**: Classify the design stage first, then use the project's approved design workflow or generator; keep prompt/output provenance when using v0.dev or another generator before writing code
**Example**:
```
# [ADAPT: replace with your project's v0.app prompt catalog or design brief template]
# See your active task card for the v0.app prompt format used in this project
```

### If: The project enables optional design traceability
**Then**: Assign stable `object_id` values for key screens/components in `naos/design_traceability.yaml` and run `naos design-traceability`; treat design references as review metadata, not design-tool sync or quality proof
**Example**:
```yaml
object_id: "checkout.payment_form"
screen_spec_path: "docs/ui/screens/checkout-spec.md"
implementation_paths:
  - "frontend/components/checkout/PaymentForm.tsx"
```

### If: The project enables optional UI experience quality review
**Then**: Add stage-aware screen evidence in `naos/ui_experience_quality.yaml` and run `naos ui-experience-quality`; treat reason codes as human-review triggers, not design approval or quality proof
**Example**:
```yaml
object_id: "checkout.payment_form"
design_stage: implementation_ready_design
fr_refs:
  - "FR-123"
task_refs:
  - "T-123"
data_model_refs:
  - "specs/04-architecture.md#payment-model"
api_contract_refs:
  - "specs/05-api.md#post-payments"
state_coverage:
  - loading
  - empty
  - error
  - focus
accessibility_evidence_refs:
  - "naos/evidence/ui/checkout-axe.md"
human_design_review:
  required: true
  reviewer: "product-design"
  disposition: "changes_requested"
  review_refs:
    - "docs/ui/reviews/checkout-review.md"
```

### If: Using v0, Lovable, Bolt, Figma, Penpot, screenshots, or AI critique as design input
**Then**: Import only local prompt logs, screenshots, exported tokens, review notes, or critique refs as evidence; never treat the tool output as NAOS authority
**Example**:
```yaml
external_generator_refs:
  - ref: "docs/ui/generator-prompts/checkout-v0.md"
    tool: "v0"
    prompt_log_ref: "docs/ui/generator-prompts/checkout-v0.md"
    reviewed: true
    reuse_boundary: "human-reviewed inspiration only"
advisory_ai_critique_refs:
  - ref: "docs/ui/reviews/checkout-ai-critique.md"
    provider_role: "ui_advisory"
    data_exposure: "synthetic screenshots only"
    human_disposition: "accepted_selected_findings"
```

### If: Choosing a color for a UI element
**Then**: Use brand tokens only — never introduce new palette colors outside the design system
**Example**:
```typescript
// WRONG — arbitrary color not in the brand palette
<Button style={{ backgroundColor: '#4A90E2' }}>

// RIGHT — use brand CSS variable or Tailwind token
// [ADAPT: replace with your project's brand tokens]
<Button className="bg-primary">  // maps to your primary brand color
```

### If: Adding an interactive element (button, link, icon-only control)
**Then**: Ensure keyboard navigability (tab order), visible focus ring, ARIA label if no visible text
**Example**:
```typescript
// WRONG — no ARIA label, no focus ring
<div onClick={handleClose}>×</div>

// RIGHT
<button
  onClick={handleClose}
  aria-label="Close dialog"
  className="focus:outline focus:outline-2"
>
  ×
</button>
```

### If: Displaying user-supplied content in a screen
**Then**: Render as plain text; no PII in URL params, localStorage, or console logs
**Example**: See your governance rules for the zero-knowledge pattern for customer-facing screens
