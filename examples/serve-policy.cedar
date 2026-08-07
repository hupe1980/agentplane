// The smallest policy that lets a declared peer in, and an operator see the
// plane — written so the shape of a real one is visible.
//
// `agentplane serve` requires a policy file with no default, because a
// permissive engine and no engine are the same behaviour and only one of them
// looks governed.
//
// Three things are worth copying rather than the rules themselves:
//
//   * Both rules bind to what the **credential** established — `context.tenant`
//     and `context.roles`, derived by the authenticator, never by the request
//     body. A rule keyed on something a caller can claim is a rule the caller
//     writes for you.
//   * The two surfaces are separated **here**, not by the network. A peer token
//     carries `peer` and reaches `a2a:*`; the operator token carries `operator`
//     and reaches `api:*`. Neither can do the other's work even if it reaches
//     the other's socket — which is why `--operator-addr` being a separate port
//     is defence in depth rather than the control itself.
//   * The actions are enumerated. `a2a:message.send` is the one a peer needs
//     and the one that is easy to forget; a policy missing it denies at that
//     step with the caller told only that it was declined, and the operator
//     side of that refusal is a `tracing` event.
//
// The full sets, for a policy that needs more:
//   a2a:message.send  a2a:task.read   a2a:task.continue
//   a2a:task.cancel   a2a:task.push   a2a:card.extended
//   api:run.read      api:run.list    api:run.cancel
//   api:task.list     api:task.read   api:task.claim
//   api:task.release  api:task.decide api:case.read   api:event.deliver

// A peer may ask this agent to do work, and read back what it asked for.
permit(
    principal,
    action in [
        Action::"a2a:message.send",
        Action::"a2a:task.read",
        Action::"a2a:task.continue"
    ],
    resource
) when {
    context.tenant == "default" && context.roles.contains("peer")
};

// The runtime's own gates, which run *underneath* the surface gates above.
//
// **`roles` is deliberately absent here, and this is the trap worth knowing.**
// A role belongs to an authenticated HTTP caller, and `run:admit` and
// `effect:perform` are asked by the runtime — which has a plan and a delegation
// chain, not a request. Writing `context.roles.contains("peer")` on these
// actions does not deny; it makes the policy *fail to evaluate*, and Cedar is
// total, so the rule silently stops contributing and everything is denied for a
// reason that has nothing to do with rules. This crate reports that case
// distinctly rather than as an ordinary refusal:
//
//   ERROR agentplane.policy.denied: policy_error=true
//   detail=error while evaluating policy `policy0`:
//          record does not have the attribute `roles`
//   — fix the policy set; this denial may not mean what it appears to
//
// To key the runtime's gates on *who asked*, give the run a delegation chain:
// its context is merged into these requests, which is the supported path for
// caller attributes below the surface.
permit(
    principal,
    action in [Action::"run:admit", Action::"effect:perform"],
    resource
) when {
    context.tenant == "default"
};

// An operator may see what the plane did and clear what it is holding.
permit(
    principal,
    action in [
        Action::"api:run.list",
        Action::"api:run.read",
        Action::"api:run.cancel",
        Action::"api:task.list",
        Action::"api:task.read",
        Action::"api:task.claim",
        Action::"api:task.release",
        Action::"api:task.decide",
        Action::"api:case.read"
    ],
    resource
) when {
    context.tenant == "default" && context.roles.contains("operator")
};
