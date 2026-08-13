# Agent Usage Guide

This guide is a platform-neutral projection of one verified Agent Usage release.
The source API remains authoritative for authentication and authorization on every request.

## Release

- Usage release: finance-usage-1
- Domain: finance
- Release status: released
- Package digest: 2e56c75a246b67d9eaedca5dfc9988a86b15a973c92400101dfb589f839247ad
- Contract digest: sha256:d8dc8581d38f7300273b3067b05b1994ca223904728d55c2fc3c667ce821e9d6
- Decision digest: sha256:04916b844241e885c56a48060d5c3845f9d1d4b0e94032aba5a8f04b945deeeb
- Tool schema digest: sha256:84df295e8436ba50e3a7cac397a3be92850b6f419225900b19741ebf3ebfeb12

## Verification limits

- source_usage_traced: true
- usage_contract_verified: true
- headless_agent_verified: true
- host_adapter_verified: false
- real_mcp_verified: true
- user_accepted: true

## Known limitations

- None declared.

## Released routes

### invoice-list

Goal: Inspect the current invoice list.
Result: step `list` at `/items`.

Steps:

- `list` calls `finance.invoice.list` (capability `finance.invoice.list`, retry `safe`).

## Safety

- Do not infer authorization beyond the source response.
- The source API remains authoritative for every request.

## Structured route projection

```json
[{"action_lifecycle":null,"bindings":[],"business_goal_id":"inspect-invoices","conditions":[],"defaults":[],"error_handling":[{"behavior":"stop","description":"Stop on source HTTP failures.","id":"http-errors","outcomes":["forbidden","not_found","timeout","unauthorized"],"retry_policy":"never","step_ids":["list"]}],"id":"invoice-list","option_sources":[],"preconditions":[],"related_data":[],"result_consumption":[{"capability_id":"finance.invoice.list","field_pointers":["/items"],"id":"return-invoices","kind":"return","order":1,"step_id":"list"}],"result_pointer":"/items","result_step_id":"list","steps":[{"action_phase":null,"binding_ids":[],"capability_id":"finance.invoice.list","condition":null,"depends_on_step_ids":[],"id":"list","retry":"safe","tool_name":"finance.invoice.list"}]}]
```
