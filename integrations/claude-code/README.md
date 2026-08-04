# Claude Code integration

This wrapper installs three thin slash commands. Each command delegates to the single workflow in `skills/acc-engineer/SKILL.md` and `HARNESS.md`.

```bash
./integrations/claude-code/install.sh
```

Pass an explicit Claude commands directory as the first argument when required. The installer refuses to overwrite existing commands.
