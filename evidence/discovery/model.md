# Model used

| Item | Value |
| --- | --- |
| Model | Claude Opus 5.5 (Anthropic), model ID `claude-opus-5-5` |
| Used for | Discovery (Run 1 and Run 2, conditions A, B and C) and repair (V1, V2) |
| Discovery dates | Run 1 committed 2026-11-05 (`212751e`); Run 2 committed 2026-11-07 (`14afdb2`) |
| Repair date | 2026-11-18 (`a1122bf`) |
| Interface | Discovery: claude.ai chat; repair: Claude Code |

## Notes

- Discovery: one fresh conversation per condition, with only the common review prompt and
  the inputs for that condition. No follow-up hints were given.
- Repair: separate conversations from discovery, labelled as repair assistance. The repair
  assistant was able to execute code. It reported running the security tests and writing
  extra tests, which were not adopted (see `evidence/patching/`).
- Dates are taken from the commits that added the responses; the conversations may have
  taken place slightly earlier.
