# Project Context — FastAPI Generic

This project uses FastAPI as the service boundary.

## Architecture Notes

- API routes should remain thin and delegate business logic to service modules.
- Request and response schemas should be explicit and versioned when public.
- Persistence, queueing, and AI provider choices remain `[ADAPT:]` until specs 01-04 define them.

## NAOS Adaptation Notes

- Complete specs 01-03 before implementing new endpoints.
- Complete spec04 before finalizing module boundaries and architecture-specific instructions.
- Add database, event-bus, or AI-pipeline instructions later with `naos add instruction <name>` when those choices are real.
