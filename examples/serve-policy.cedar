// The policy `agentplane init --serve` writes: a declared peer in, a framework
// calling the served tools, and an operator able to see the plane and stop it
// — written so the shape of a real one is visible.
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
//   * The surfaces are separated **here**, not by the network. A peer token
//     carries `peer` and reaches `a2a:*`; a framework token carries `framework`
//     and reaches `mcp:*`; the operator token carries `operator` and reaches
//     `api:*`. None can do another's work even if it reaches that socket —
//     which is why `--operator-addr` and `--mcp-addr` being separate ports is
//     defence in depth rather than the control itself.
//   * The actions are enumerated. `a2a:message.send` is the one a peer needs
//     and the one that is easy to forget; a policy missing it denies at that
//     step with the caller told only that it was declined, and the operator
//     side of that refusal is a `tracing` event.
//
// One grant here is wider than a deployment may want: `api:hold.release` sits
// with the on-call verbs, so whoever holds the `operator` role can lift a
// legal hold, after which retention may delete what the hold preserved. To
// split it, remove it from the on-call rule and permit it in a rule of its own
// on another role — `context.roles.contains("legal")` — given to the people
// who decide holds.
//
// The complete vocabulary, for a policy that needs more. A guard holds this
// block to the action lists in the crate, so an action added there and not
// added here stops the build — a comment claiming to be a full set is worth
// only what checks it.
//
// Asked by the *runtime*, underneath the surface. All three, always:
//   run:admit         effect:perform  data:release
//
// `effect:perform` covers a declared content check too: it is asked on
// resource `content.check`, so the permit below lets a checker see a value
// its own ceiling allows. `effect:declared`, `effect:egress` and
// `effect:content` label refusals the plane already decided and are never
// asked.
//
// Asked by the A2A surface, for a peer:
//   a2a:message.send  a2a:task.read   a2a:task.continue
//   a2a:task.cancel   a2a:task.push   a2a:card.extended
//   a2a:event.deliver
//
// Asked by the MCP surface (`--mcp-addr`), for a framework calling tools:
//   mcp:tool.list     mcp:tool.call   mcp:task.read   mcp:task.cancel
//   mcp:prompt.read   mcp:resource.read
//
// Asked by the operator API. The incident verbs are the ones to notice: a
// bundle missing them denies during the incident, which is the one time
// nobody is reading policy files.
//   api:run.read      api:run.list    api:run.history api:run.live
//   api:run.waiting   api:run.cancel  api:run.reopen  api:run.abandon
//   api:attention     api:drill.read  api:effect.reconcile
//   api:task.list     api:task.read   api:task.claim  api:task.release
//   api:task.takeover api:task.decide
//   api:case.read     api:case.list
//   api:obligation.list                api:obligation.acknowledge
//   api:hold.list     api:hold.place  api:hold.release
//   api:halt.list     api:halt.place  api:halt.lift
//   api:event.deliver api:deadletter.list
//   api:push.list     api:push.rearm

// A peer may ask this agent to do work, and read back what it asked for.
permit(
    principal,
    action in [
        Action::"a2a:message.send",
        Action::"a2a:task.read",
        Action::"a2a:task.continue",
        // Registering a webhook. Without this a peer's
        // `taskPushNotificationConfig` is declined by *policy* before the push
        // grant is ever consulted — the refusal is correct and says nothing
        // about the URL, which is exactly the uniform decline an external
        // caller gets. `--push-host` is the second gate, not the first.
        Action::"a2a:task.push"
    ],
    resource
) when {
    context.tenant == "default" && context.roles.contains("peer")
};

// Continuing a task supplies the event it awaits, and that is asked again as
// `a2a:event.deliver` on the event's kind — so it is granted per kind, never
// on every kind. The starter awaits none; for an agent that does, uncomment
// this and name the kinds a peer may answer:
//
//   permit(
//       principal,
//       action == Action::"a2a:event.deliver",
//       resource in [Resource::"approval.response"]
//   ) when {
//       context.tenant == "default" && context.roles.contains("peer")
//   };

// A framework may list the served tools, call them, and follow the calls that
// wait. Prompts and resources serve only what the reviewed manifests declare,
// and a framework that lists them at startup must not fail there.
permit(
    principal,
    action in [
        Action::"mcp:tool.list",
        Action::"mcp:tool.call",
        Action::"mcp:task.read",
        Action::"mcp:task.cancel",
        Action::"mcp:prompt.read",
        Action::"mcp:resource.read"
    ],
    resource
) when {
    context.tenant == "default" && context.roles.contains("framework")
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
//
// **`data:release` is deliberately not permitted here, and that is a refusal
// rather than an omission.** It is the third runtime action, asked on every
// typed release, and Cedar denies what no rule permits — so this bundle passes
// a run's effects and refuses to let a labelled value out. That is the right
// default for a starting policy, because the release gate is the one whose
// rules depend on what a deployment considers sensitive, and there is no
// answer to that which an example can supply. `preflight` will not warn you:
// it reports rules that cannot evaluate, and a rule nobody wrote evaluates
// fine. To open it, permit `data:release` on the labels you mean, reading
// `context.label` — never as a blanket permit beside the two above, which
// silently turns the lattice off. The rule below, uncommented, would let a
// value labelled up to `internal` out of a run and nothing above it; the
// security guide's release gate says what each label means:
// https://hupe1980.github.io/agentplane/docs/security/#information-flow-labels
//
//   permit(principal, action == Action::"data:release", resource) when {
//       context.tenant == "default" &&
//       ["public", "internal"].contains(context.label.sensitivity)
//   };
permit(
    principal,
    action in [Action::"run:admit", Action::"effect:perform"],
    resource
) when {
    context.tenant == "default"
};

// An operator may stop what is running and settle what it left behind. These
// are the verbs an incident needs, granted before it rather than discovered
// missing during it: halt the plane or one agent, cancel or abandon a run,
// settle an effect whose outcome is unknown, and hold or release a case.
@id("on-call verbs")
permit(
    principal,
    action in [
        Action::"api:halt.place",
        Action::"api:halt.lift",
        Action::"api:run.cancel",
        Action::"api:run.abandon",
        Action::"api:effect.reconcile",
        Action::"api:hold.place",
        Action::"api:hold.release"
    ],
    resource
) when {
    context.tenant == "default" && context.roles.contains("operator")
};

// An operator may see what the plane did and is doing — the halts in force,
// the runs in flight and waiting, and what needs a person — and clear what it
// is holding.
permit(
    principal,
    action in [
        Action::"api:halt.list",
        Action::"api:run.live",
        Action::"api:run.waiting",
        Action::"api:attention",
        Action::"api:run.list",
        Action::"api:run.read",
        Action::"api:run.history",
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
