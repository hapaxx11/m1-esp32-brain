# AGENTS.md — Instructions for AI Coding Agents

## Absolute privacy rule: never emit personal ambient information

Never repeat, publish, commit, or otherwise emit personal ambient information
observed in the user's environment, conversation, documents, device screens,
logs, captures, or test output. This applies to chat responses, code, tests,
fixtures, documentation, commit messages, issues, PR descriptions, screenshots,
HIL artifacts, and every other output.

This is broader than WiFi information. It includes network names, addresses and
credentials; nearby device identifiers; real names; locations; account or user
names; personal paths; hostnames; serial numbers; private filenames and messages;
and any other incidental information that can identify a person, place, device,
or account.

- Read only the minimum needed for the task and never echo values back for
  confirmation.
- Use generic descriptions and synthetic placeholders in examples, tests, and
  documentation.
- Redact captures, logs, reports, and PR content before sharing them.
- If exposure is discovered, remove it from current content without repeating
  the value and tell the user that redaction occurred.
- Never assume information is safe to share merely because it was visible during
  testing.

All project changes also require explicit permission before commits, pushes, PR
creation, PR edits, releases, or other remote operations. Push only to `origin`
when authorized. Do not add AI attribution or co-author trailers to commits.
