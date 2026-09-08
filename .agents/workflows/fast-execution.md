# Workflow: fast-execution
Trigger: `/fast-execution`

## Behavior Guidelines
- Execute requested work directly across the codebase.
- Minimize commentary and omit conversational filler.
- Apply code changes, scaffolding, and file operations directly.
- Do not generate lengthy implementation summaries or explain obvious code changes.
- Keep agent response output under 10 lines unless explicitly requested otherwise.

## Standard Completion Report Format
```
✓ Completed requested task: [brief description]
✓ Files modified: [count]
✓ Issues requiring attention: [None / list blocking issues or required user decisions]
```
