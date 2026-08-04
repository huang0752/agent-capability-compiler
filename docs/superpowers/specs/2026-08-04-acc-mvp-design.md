# Agent Capability Compiler MVP Design

## Outcome

ACC is a Python 3.12, CLI-first toolchain that turns evidence-bound, read-only REST operations and declarative business workflows into a deterministic `.accpkg`. A fixed runtime loads that pack and exposes capabilities through MCP stdio without invoking an LLM or revealing credentials.

## Boundaries

- Engineering-time AI belongs to host products such as Codex and Claude Code and is guided by `skills/acc-engineer`.
- ACC reads source workspaces but writes only to a separate ACC project.
- Version 1 supports only HTTP `GET` and `HEAD`, read-only effects, MCP stdio, environment-backed secrets, and bounded declarative workflows.
- ACC does not provide a web control plane, an agent loop, production writes, dynamic code, dynamic hosts, or database access.

## Architecture

The repository is an `uv` workspace with four packages:

1. `acc-core` owns strict Pydantic contracts, YAML/JSON loading, evidence and workflow validation, compilation, diagnostics, coverage, eval orchestration, deterministic packaging, and the `acc` CLI.
2. `acc-runtime` owns pack loading, JSON Schema validation, credential resolution, policy enforcement, a constrained HTTP provider, workflow execution, and MCP JSON-RPC stdio.
3. `acc-adapter-sdk` defines a small read-only adapter contract, FastAPI server helper, fake adapter, and contract assertions.
4. `acc-testkit` provides a fake REST system, an MCP subprocess client, fault injection, and end-to-end assertions.

An ACC project is a directory with `project.yaml`, `operations/`, `capabilities/`, `policies/`, `evals/`, and `evidence/`. Validation produces stable diagnostics. Compilation emits normalized JSON IR into `build/`. Packaging copies only allow-listed project artifacts plus compiled IR into a normalized ZIP and records hashes in `pack.lock`.

## Contracts and compilation

All public Pydantic models reject unknown fields. File readers enforce size limits, reject symlinks, and confine relative paths to the project root. Operations require evidence, read-only effects, relative paths beginning with `/`, declared schemas, environment secret references, and `GET`/`HEAD` methods.

Workflow expressions use a deliberately small JSON reference grammar: `$.input`, `$.input.<field>`, `$.steps.<step>`, and `$.item`. No general expression evaluator is embedded. The compiler validates step IDs, operation and policy references, prior-step references, loop/concurrency bounds, and a final `emit`. Runtime implements the ten requested step forms with deterministic ordering and explicit limits.

## Runtime and security

The runtime verifies the archive layout and hashes before loading it. It resolves `base_url_ref` and `credential_ref` from the process environment, requires an `http` or `https` base URL, rejects credentials in tool input, confines operation paths to the configured origin, and never logs tokens or full bodies. Inputs, upstream results, and capability outputs are JSON Schema validated.

Policy processing checks required scopes supplied by runtime configuration, applies readable/denied fields, and performs redaction after operation execution and before MCP output. HTTP 403, 404, timeout, oversized response, invalid JSON, and schema failures map to stable error codes.

MCP stdio writes protocol messages only to stdout and diagnostics only to stderr. It supports initialize, tools/list, tools/call, ping, and shutdown-compatible EOF behavior.

## Test and example flow

The FastAPI CRM fixture models tenants, bearer scopes, customers, contacts, follow-ups, and todos. Its ACC project defines evidence-bound atomic operations and three business capabilities: `search_customers`, `get_customer_context`, and `find_overdue_followups`. The context capability combines customer data with parallel related-data calls.

Unit tests cover contracts and diagnostics; integration tests cover compiler, archive security, HTTP failures, and workflow execution; end-to-end tests start the fake CRM, build a pack, launch MCP stdio, list tools, call all three capabilities, and assert tenant denial and redaction.

## Delivery sequence

Work proceeds through the six requested milestones with focused commits. Each milestone runs its focused tests, full pytest suite, Ruff, mypy, diff review, and progress update before the next starts. Final verification rebuilds the same pack twice and compares SHA-256 digests, installs the workspace in an isolated `uv` environment, and reruns the end-to-end path.
