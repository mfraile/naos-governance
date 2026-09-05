---
name: "cookbook-frontend"
description: "If-then recipes for frontend (Next.js/React or equivalent). Invoke when adding API calls, creating UI components, rendering user content, or making state-changing requests."
parameters: []
---

# Cookbook: Frontend

## When to Use

Use this skill when adding API calls, creating UI components, rendering user
content, or making state-changing requests.

> Extracted from `.github/instructions/frontend.instructions.md`. See that file for full domain rules.

### If: Adding a new API call from the frontend
**Then**: Add the typed function to your central API client file — never call `fetch()` directly in a component
**Example**:
```typescript
// WRONG — inline fetch, no type safety
const data = await fetch('/api/v1/items').then(r => r.json())

// RIGHT — typed client function
// [ADAPT: replace with your API client file path, e.g. frontend/lib/api.ts]
// In your API client file:
export async function listItems(userId: string): Promise<Item[]> {
  return apiClient.get<Item[]>(`/api/v1/items?user_id=${userId}`)
}
```

### If: Creating a new UI component
**Then**: Check your UI component library directory for existing primitives first — prefer composing over creating
**Example**:
```
# [ADAPT: your UI components directory and available primitives]
# e.g. frontend/components/ui/
# Common primitives: Accordion, Alert, Badge, Button, Card, Dialog, Form, Table
```

### If: Editing a UI component with a declared design-traceability object
**Then**: Update the matching `naos/design_traceability.yaml` entry's implementation paths, changed-file evidence, test/check evidence, and review disposition; do not treat the object ID as proof that design and code are synchronized
**Example**:
```yaml
object_id: "settings.notification_toggle"
changed_file_refs:
  - "frontend/components/settings/NotificationToggle.tsx"
test_evidence_refs:
  - "npm test -- NotificationToggle"
```

### If: Editing a UI component with optional UI experience quality enabled
**Then**: Update `naos/ui_experience_quality.yaml` for the affected screen/component stage, dependencies, data/API/state refs, screenshots or state evidence, accessibility/performance refs, and human-review disposition; do not treat the report as design approval or quality proof
**Example**:
```yaml
object_id: "settings.notification_toggle"
design_stage: post_implementation_review
fr_refs:
  - "FR-221"
task_refs:
  - "T-221"
state_coverage:
  - loading
  - empty
  - error
  - focus
  - disabled
visual_regression_refs:
  - "naos/evidence/ui/settings-notification-visual.md"
human_design_review:
  required: true
  reviewer: "product-design"
  disposition: "approved_with_followups"
  review_refs:
    - "docs/ui/reviews/settings-notification.md"
```

### If: Rendering user-provided content in the UI
**Then**: Sanitize before rendering — never `dangerouslySetInnerHTML` with unchecked content
**Example**:
```typescript
// WRONG
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// RIGHT — use DOMPurify or render as plain text
<p>{userContent}</p>
```

### If: Making a state-changing API call (POST/PUT/PATCH/DELETE)
**Then**: Include the CSRF token in the `X-CSRF-Token` header
**Example**: See your API client file for the CSRF header injection pattern
