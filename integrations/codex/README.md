# Codex integration

This wrapper installs the repository's platform-neutral `acc-engineer` skill into a Codex skills directory. The method remains in `skills/acc-engineer/HARNESS.md`.

```bash
./integrations/codex/install.sh
```

Pass an explicit skills directory as the first argument when required. The installer refuses to overwrite an existing skill. Invoke it with `$acc-engineer` after installation.
