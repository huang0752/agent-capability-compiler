# ACC Frontend Interaction Evidence and Contract Design

## Status

Approved direction: frontend interaction facts become first-class ACC Core contracts and Coverage gates. This design is platform-neutral and must not encode `baogao-jin`, Vue, React, Angular, Flutter, or any other product/framework convention as Core semantics.

## Problem

ACC currently proves API and capability facts well:

- Scope Inventory establishes the source-route denominator.
- SourceContract describes evidenced requests, responses, and Action safety.
- Operation and Capability describe deterministic execution.
- CapabilityQuality checks selector acquisition, composition, and output budget.
- Coverage reports route trace, scenarios, constructability, schema fidelity, and related axes.

Frontend evidence is currently reduced to `ScopeRoute.usage_evidence_sources`: it proves only that a client calls a route. It cannot prove how users actually complete work. Important product semantics can exist only in client code or client configuration:

- initial loads and event-triggered calls;
- defaults and their authority or precedence;
- form, selection, route, trusted-context, and prior-response input bindings;
- dictionaries, option sources, value/label mappings, search, pagination, and cascades;
- field visibility, enabled state, dynamic required state, and reset behavior;
- master/detail, summary/detail, status, and related-data composition;
- loading, initial-empty, no-results, forbidden, and source-error states;
- date, enum, null, identifier, locale, and other encode/decode transforms;
- Action confirmation, optimistic concurrency, and refresh behavior.

Without these facts, route closure can be complete while the generated MCP remains difficult or incorrect to use.

## Goals

1. Treat frontend interaction behavior as evidence-bound, typed, platform-neutral truth.
2. Keep API truth, interaction truth, capability decisions, and runtime enforcement separate.
3. Establish an interaction/surface denominator independent of the route denominator.
4. Prove that required inputs, defaults, options, conditions, and related data are constructible.
5. Make omissions and uncertainty visible in validation, Coverage, tests, and handoff.
6. Support Read and Action capabilities without weakening existing authorization boundaries.
7. Allow framework-specific discoverers to emit one normalized format without putting parsers in Core.

## Non-goals

- Rendering or reproducing a source application's UI.
- Treating frontend visibility or disabled controls as authorization.
- Inferring backend permissions, effects, tenant boundaries, or Schema bounds from client code.
- Executing arbitrary frontend expressions or JavaScript in Core or Runtime.
- Encoding CSS, layout pixels, component library names, or framework lifecycle hooks.
- Making a source-connected API test count as client-adapter verification.

## Alternatives considered

### Skill-only guidance

This is fast but depends on one Agent following prose correctly. A different Agent or integration could omit the same facts again. Rejected as the final architecture.

### Extend SourceContract with UI fields

This mixes source API truth with consumer behavior and makes one route contract responsible for many screens and clients. Rejected.

### First-class interaction inventory and capability contract

Selected. Add a separate source-use denominator and a capability-side adoption contract. Core validates their relationship; framework-specific discovery stays outside Core.

## Authority model

Four distinct authorities remain explicit:

1. `ScopeInventory`: what source interfaces exist and their disposition.
2. `SourceContract`: what one source Operation accepts, returns, and safely does.
3. `UIInteractionInventory`: how discovered client surfaces currently obtain, combine, and consume data.
4. `InteractionContract`: which evidenced interaction semantics an Agent-facing Capability adopts, overrides, or intentionally omits.

No layer silently upgrades another layer's authority:

- A hidden button is not permission evidence.
- A frontend default is not automatically a backend default.
- An observed value is not an enum or maximum.
- A route call is not proof of a complete interaction.
- An InteractionContract is not proof that a real framework adapter conforms.

## Project documents

### UI interaction inventory

Projects with a discovered client surface contain `ui-interaction-inventory.yaml`.

Top-level shape:

```yaml
schema_version: "2"
scope:
  mode: none | discovered | complete
  evidence_sources: []
surfaces: []
interactions: []
summary: {}
```

`mode` semantics:

- `none`: evidence shows that no applicable interactive client surface exists.
- `discovered`: partial interaction discovery is recorded; missing coverage remains explicit.
- `complete`: all selected client surfaces and their business interactions form the declared denominator.

For `system_complete` source scope, a detected frontend/client tree cannot be declared `none` without evidence and explicit rationale. `complete` requires deterministic counters and closure. `discovered` is allowed during analysis but blocks a complete release claim.

### Surface

A surface is a user-visible or client-visible business entry point, not a framework component:

```yaml
id: customer-workbench
kind: page | dialog | panel | mobile_screen | command | embedded_flow
route_or_entry: /customers
business_purpose: Manage tenant-visible customers
evidence_sources: []
```

### Interaction

An interaction represents one business-relevant state transition or data consumption path:

```yaml
id: customer-workbench.initial-load
surface_id: customer-workbench
business_intent: Show the initial customer list and filters
trigger:
  kind: screen_load
route_ids: ["GET /api/customers"]
call_order: sequential
input_bindings: []
defaults: []
option_sources: []
conditions: []
related_data: []
result_consumption: []
states: []
evidence_claims: []
unknowns: []
```

Supported trigger vocabulary is semantic rather than framework-specific:

- `screen_load`
- `submit`
- `change`
- `select`
- `confirm`
- `refresh`
- `paginate`
- `sort`
- `navigate`
- `system_event`

### Input binding

Each binding maps a consumer input JSON Pointer to one typed source:

- `user_input`
- `route_parameter`
- `selected_record`
- `prior_response`
- `trusted_context`
- `literal`
- `computed`
- `user_preference`

Bindings contain source and target pointers, cardinality, optional mapping, and Evidence. Trusted context stays outside Agent input.

### Default semantics

A default is never represented by a value alone. It contains:

- target input pointer;
- source kind: `literal`, `source_response`, `trusted_context`, `user_preference`, or `computed`;
- authority: `contract`, `implementation`, `test`, or `observation`;
- precedence relative to caller input and source defaults;
- submission behavior: `omit`, `send`, or `send_if_changed`;
- override policy;
- Evidence claim.

Core validates literal defaults against the consumer Schema. Observation cannot prove an authoritative default. Trusted/server-derived values cannot become caller-overridable inputs.

### Option source

Option contracts describe:

- static or Capability/Operation producer;
- request bindings;
- items, value, label, and optional disabled/group pointers;
- search and pagination semantics;
- cascade dependencies;
- cache/freshness policy;
- empty and error behavior.

The cache identity contract always includes effective principal and tenant context when the producer is identity-scoped.

### Conditions

Conditions use a bounded typed AST, never arbitrary source expressions. Initial operators:

- boolean `all`, `any`, `not`;
- comparisons `eq`, `ne`, `in`, `present`;
- targets `visible`, `enabled`, `required`, `reset`.

References use declared JSON Pointers. Core checks types, missing references, and dependency cycles. Client expressions that cannot be normalized remain `unknown`; they are not executed.

### Related data and display consumption

`related_data` records producer output to consumer/view bindings:

- producer Capability or Operation;
- output pointer and target pointer;
- cardinality `one`, `optional`, or `many`;
- identity/join key;
- ordering and freshness semantics;
- failure isolation.

`result_consumption` records business presentation roles such as `table`, `detail`, `summary`, `status`, `option`, `navigation`, or `download_link`, with field pointers, ordering, formatting class, pagination, and states. These are semantic hints, not UI rendering instructions.

### States

Every interaction can declare:

- `initial`
- `loading`
- `ready`
- `empty`
- `no_results`
- `forbidden`
- `source_error`
- `stale`

State declarations specify entry condition and allowed next events. They allow headless verification of client behavior without rendering a framework.

### Evidence claims

Interaction claims reuse immutable `Evidence` but add typed claim semantics:

```yaml
target_pointer: /interactions/0/defaults/0
evidence: {...}
evidence_pointer: /path/to/source/fact
authority: implementation
```

Claims may reference frontend source, configuration, tests, route definitions, or documentation. `observation` cannot prove completeness, authorization, safety, dynamic requiredness, or authoritative defaults.

## Capability InteractionContract

Each Capability that adopts discovered interactions has one sidecar under `interaction-contracts/<capability-id>.yaml`.

It contains:

- capability ID;
- adopted interaction IDs;
- public input bindings;
- runtime-only/trusted bindings;
- adopted defaults and explicit overrides;
- option and related-data producer bindings;
- conditions that affect input construction;
- output/display projections;
- required headless scenarios;
- omissions with evidence-backed rationale.

The contract does not require an MCP client to render the original UI. It proves that the Capability preserves the business interaction needed to obtain inputs and understand results.

## Route and capability cross-links

`ScopeRoute` gains `interaction_ids`, defaulting to an empty list. `usage_evidence_sources` also defaults to empty; templates must never encourage fabricated frontend evidence.

Closure rules:

- every interaction route ID resolves to Scope Inventory;
- every `ScopeRoute.interaction_ids` entry resolves to the UI inventory;
- every adopted interaction resolves to an InteractionContract and Capability;
- excluded frontend-used routes retain the existing approval rule;
- a complete UI inventory cannot contain unclassified interactions;
- a complete capability release cannot silently omit a high-value interaction.

## Core validation

New stable diagnostics include:

- `ACC_UI_INTERACTION_ROUTE_UNKNOWN`
- `ACC_UI_INTERACTION_EVIDENCE_MISSING`
- `ACC_UI_INPUT_SOURCE_UNRESOLVED`
- `ACC_UI_DEFAULT_AUTHORITY_UNPROVEN`
- `ACC_UI_OPTION_SOURCE_UNTRACED`
- `ACC_UI_CONDITION_AUTHORITY_UNPROVEN`
- `ACC_UI_CONDITION_CYCLE`
- `ACC_UI_RELATED_DATA_DEPENDENCY_BROKEN`
- `ACC_UI_PRESENTATION_FIELD_UNPROVEN`
- `ACC_UI_HIDDEN_NOT_AUTHORIZATION`
- `ACC_UI_SURFACE_COVERAGE_INCOMPLETE`
- `ACC_UI_INTERACTION_CONTRACT_MISSING`

Validation proves:

- document and Evidence closure;
- input/output pointer existence and Schema compatibility;
- default validity and authority;
- producer output to consumer input compatibility;
- option value/label mapping;
- condition reference validity and acyclicity;
- presentation fields remain inside policy-visible Capability output;
- trusted context and secrets never become public inputs or outputs;
- Action interactions reference the Action lifecycle rather than a direct mutation call.

## Compiler and Pack

Compiler normalizes InteractionContracts and records:

- interaction contract digest;
- adopted interaction IDs;
- enforceable input/default/binding summary;
- option and related-data dependency graph;
- normalized safe condition AST;
- required scenario IDs.

Design-only annotations remain Pack sidecars. Runtime-enforceable facts are carried in IR with a canonical digest. Pack verification includes both inventories and all interaction sidecars.

## Runtime boundary

Existing MCP Tool list/call behavior remains deterministic and does not become a UI runtime.

- Defaults that affect Capability execution must compile into explicit input normalization or Workflow literals; JSON Schema `default` alone remains an annotation.
- Trusted defaults are restored only from `PrincipalContext` or source responses.
- Interaction metadata is exposed through a versioned, read-only MCP Resource/manifest with its own digest. Tool metadata contains only a resource URI and digest, not duplicated contracts.
- Runtime info reports the interaction digest separately from the tool-schema digest.
- Runtime never executes arbitrary transforms or frontend code.

## Headless reference evaluator

Testkit provides a platform-neutral evaluator for normalized interactions:

```text
state -> event -> bindings/defaults -> producer call -> condition/state
      -> consumer call -> result consumption -> next state
```

It records exact logical calls and arguments, state transitions, selected options, cleared/preserved fields, and public results. Framework adapters can replay the same fixtures and report conformance without changing Core semantics.

## Coverage

Coverage retains independent axes and adds:

- `surface_disposition`
- `interaction_trace`
- `input_binding_fidelity`
- `default_provenance`
- `option_resolution`
- `condition_coverage`
- `related_data_graph`
- `state_scenarios`
- `presentation_projection`
- `client_adapter_evidence`

No aggregate score is introduced. Route closure, source connection, and interaction conformance remain distinct facts.

Verification levels are separate:

- `contract_declared`
- `static_verified`
- `headless_verified`
- `runtime_offline_verified`
- `source_connected_verified`
- `client_adapter_verified`

One level does not automatically imply the next. In particular, `source_connected_verified` does not mean a real client adapter was verified.

## Test matrix

Cross-industry fixtures must cover at least:

1. CRM list to detail and selected-record binding.
2. ERP order editor with server defaults, options, and optimistic concurrency.
3. Finance filters with independent option producers and pagination.
4. Monitoring with one job selector and refresh/stale states.
5. CMS/LLM long text and presentation projection.
6. Permissions with an unbounded, identity-scoped option list.
7. Mobile cascade selectors.
8. Action preview, approval, commit, status, and post-commit refresh.

Scenario cases include missing/null/explicit defaults, omit/send behavior, option success/empty/error/paging, dependency change with stale response rejection, visible/enabled/required/reset conditions, hidden-field clear/preserve, loading/empty/no-results/forbidden/source-error states, value/label mapping, transform round trips, lossy transform rejection, tenant/principal cache isolation, exact Operation arguments, and Action concurrency.

## Engineer Skill changes

The Skill must:

- discover client surfaces separately from routes;
- normalize interaction evidence rather than treating frontend usage as a string only;
- record unknown and framework-specific behavior honestly;
- model Read and Action interactions consistently;
- require interaction audit before project validation;
- test defaults, cascades, related data, states, and Action confirmation/concurrency;
- report interaction verification independently in handoff.

The existing stale Read-only wording in Analyze/Model/Plan must be removed so current Action support is not narrowed. `usage_evidence_sources` templates default to `[]` and are populated only with real Evidence.

## Delivery sequence

1. Models and schemas for UIInteractionInventory and InteractionContract.
2. Project loading, Evidence closure, cross-reference validation, and templates.
3. Binding/default/condition/producer validators.
4. Compiler/IR/Pack digest and runtime manifest.
5. Headless evaluator and framework-neutral fixtures.
6. Coverage axes and CLI reports.
7. Engineer Skill, audits, maintained example, and documentation.
8. Full release gates, deterministic Pack verification, and independent review.

## Acceptance criteria

- A system with frontend surfaces can no longer claim complete interaction coverage from route calls alone.
- Defaults, options, conditions, related data, and presentation fields are evidence-bound and type-checked.
- API-only systems can explicitly and honestly declare no interaction surface.
- Capability inputs are constructible through proven interaction bindings.
- Hidden/disabled UI state never becomes authorization evidence.
- Source-connected tests and client-adapter tests remain separately labeled.
- No source framework or product-specific convention enters Core.
- Existing Read and Action security boundaries remain fail-closed.
