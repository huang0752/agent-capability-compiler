# Workflow conditions and transition tools

Branch conditions support a bounded, declarative AST in addition to the legacy static-reference
truthiness form. The supported operators are `eq`, `in`, `all`, `any`, and `not`. Operands are
explicitly tagged as either a `reference` or an inert JSON `literal`; executable expressions and
implicit string interpolation are not accepted.

```yaml
condition:
  operator: in
  item:
    kind: reference
    value: $.input.target_status
  values:
    kind: literal
    value: [closed, cancelled]
```

References use the existing workflow namespace and are checked at compile time. They may only
target inputs available in the current phase, the current item when applicable, or a prior named
step. Action commit references under `$.prepared` retain the existing sealed-prepare semantics.
Conditions are limited to 64 AST nodes, depth 16, and logical fan-out 16. Runtime evaluation repeats
those bounds and fails closed on malformed IR.

A transition is a business intent, not an HTTP route or a target-state constant. Prefer one Action
Capability with a bounded `target_status` selector when several low-risk states share the same
resource transition lifecycle. The tool-portfolio audit warns when multiple Action Capabilities use
the same `transition` intent and resource family, even when const schemas or Operation dependencies
differ. Separate Actions remain valid when their distinct business outcomes are evidenced; the
diagnostic is a review warning rather than a compilation error. Shared approve, commit, and status
tools are still projected once for the entire Action portfolio.
