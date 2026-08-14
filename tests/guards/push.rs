#![cfg(all(feature = "push", feature = "redb"))]

//! Webhook registration and delivery.
//!
//! Push is the one feature where an **untrusted party names an address this
//! plane will connect to**. Every other outbound destination is granted by an
//! operator; a webhook URL comes from whoever created the task. So these tests
//! are mostly about the three controls that keeps honest, and about what the
//! payload is allowed to contain.

use std::sync::Arc;

use agentplane::core::{RunId, Secret};
use agentplane::push::{PushAuthentication, PushConfig, PushError, PushPolicy, PushStore};
use agentplane::store::RedbStore;

fn config(url: &str) -> PushConfig {
    PushConfig {
        id: "cfg-1".to_owned(),
        task: RunId::generate(),
        url: url.to_owned(),
        token: Some(Secret::new("opaque-a2a-token")),
        authentication: Some(PushAuthentication {
            scheme: "Bearer".to_owned(),
            credentials: Secret::new("the-receivers-token"),
        }),
    }
}

// ── The grant ───────────────────────────────────────────────────────────────

/// A webhook host must be granted, and the grant is exact.
#[test]
fn a_webhook_host_must_be_granted() {
    let policy = PushPolicy::new().allow_host("acme.example");

    policy
        .check("https://acme.example/a2a")
        .expect("a granted host was refused");

    // A host nobody listed.
    assert!(matches!(
        policy.check("https://evil.example/a2a"),
        Err(PushError::HostNotGranted(_))
    ));

    // The two ways a near-match is talked into passing, and both are ordinary
    // to register:
    //
    // `evil-acme.example` *ends with* the granted host, so any implementation
    // that matches on a suffix accepts it — the classic allowlist bypass.
    assert!(
        matches!(
            policy.check("https://evil-acme.example/a2a"),
            Err(PushError::HostNotGranted(_))
        ),
        "a host ending in the granted one was accepted, so the allowlist is \
         bypassed by registering a domain"
    );
    // And a subdomain is a different host, not a covered one.
    assert!(matches!(
        policy.check("https://hooks.acme.example/a2a"),
        Err(PushError::HostNotGranted(_))
    ));
}

/// **An internationalised webhook grant matches a URL to that host.**
///
/// The grant is checked against `Url::host_str`, which the URL crate encodes to
/// punycode — so a grant only lowercased would store the Unicode form and never
/// match, silently refusing every delivery to the host it was meant to permit.
/// The sibling of the media-host defect, fixed with the same shared helper so
/// the two host-granting surfaces cannot drift.
#[test]
fn an_internationalised_webhook_host_grant_matches() {
    let policy = PushPolicy::new().allow_host("café.example");
    policy
        .check("https://café.example/a2a")
        .expect("an internationalised grant did not match a URL to the same host");
    policy
        .check("https://xn--caf-dma.example/a2a")
        .expect("the punycode spelling of the granted host is refused");
}

/// Plaintext webhooks are refused.
///
/// The payload describes somebody's task. Sending it in clear to an address the
/// recipient chose is a disclosure with extra steps.
#[test]
fn a_webhook_must_be_https() {
    let policy = PushPolicy::new().allow_host("hooks.acme.example");
    assert!(matches!(
        policy.check("http://hooks.acme.example/a2a"),
        Err(PushError::NotHttps)
    ));
}

/// The grant is re-checked at delivery, not only at registration.
///
/// A registration outlives the configuration that permitted it. A host removed
/// from the allowlist must stop receiving notifications for tasks registered
/// while it was still granted — a check performed only at write time cannot do
/// that, and the tasks that outlive a config change are exactly the long-running
/// ones this feature exists for.
#[tokio::test]
async fn a_revoked_host_stops_receiving_notifications() {
    use agentplane::push::{PushSender, PushTransport};

    // Registered under one policy...
    let permissive = PushPolicy::new().allow_host("hooks.acme.example");
    let registered = config("https://hooks.acme.example/a2a");
    permissive.check(&registered.url).expect("granted at first");

    // ...delivered under another, which no longer names the host.
    let sender = PushSender::new(PushPolicy::new().allow_host("hooks.other.example"));
    let refused = sender
        .deliver(&registered, &serde_json::json!({"statusUpdate": {}}))
        .await;
    assert!(
        matches!(refused, Err(PushError::HostNotGranted(_))),
        "a webhook registered before its host was revoked was still delivered \
         to: {refused:?}"
    );
}

/// A host that resolves inward is refused, however it was granted.
///
/// The second lock. An operator can grant a host by name; they cannot grant it
/// past the address check, so a name that resolves to loopback or a metadata
/// service reaches nothing.
#[tokio::test]
async fn a_webhook_resolving_to_a_private_address_is_refused() {
    use agentplane::push::{PushSender, PushTransport};

    // `localhost` is granted by name and still refused, because the refusal is
    // about where it resolves.
    let sender = PushSender::new(PushPolicy::new().allow_host("localhost"));
    let outcome = sender
        .deliver(
            &config("https://localhost/hook"),
            &serde_json::json!({"statusUpdate": {}}),
        )
        .await;
    assert!(
        matches!(outcome, Err(PushError::Unroutable(_))),
        "a granted host resolving to loopback was connected to: {outcome:?}"
    );
}

/// The conformance-kit exception is an exception, not an off switch.
///
/// The A2A kit's webhook receiver is `http://localhost:PORT`, which both
/// address controls refuse — correctly, and the cost was that the kit's **ten
/// push MUSTs could not run at all**, leaving the one surface where an
/// untrusted party names a destination with no outside-authority evidence.
/// `PushSender::allow_plaintext_loopback` lifts exactly two refusals for
/// exactly one shape of address, under `testkit`, which never belongs in a
/// production build.
///
/// Three halves are asserted, and the last two are what make it an exception:
/// the loopback case is permitted; a **plaintext public** host is still
/// refused with the flag set; and the **host grant** still has to name the
/// host, because that is the primary control and this lifts the second lock,
/// not the first.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn the_loopback_exception_lifts_two_refusals_and_no_others() {
    use agentplane::push::{PushSender, PushTransport};

    let granted = PushPolicy::new().allow_host("localhost");
    let permissive = PushSender::new(granted.clone()).allow_plaintext_loopback();

    // 1. Permitted: the kit's own shape. Nothing is listening, so the outcome
    //    is an *unreachable delivery* rather than a refusal — which is the
    //    distinction that proves the gate opened.
    let outcome = permissive
        .deliver(
            &config("http://localhost:1/hook"),
            &serde_json::json!({"statusUpdate": {}}),
        )
        .await;
    assert!(
        matches!(outcome, Ok(agentplane::push::Delivered::Unreachable(_))),
        "the loopback exception did not open the gate: {outcome:?}"
    );

    // 2. Still refused: plaintext to a host that is not this machine. If the
    //    flag were an off switch this would go out in the clear.
    let public = PushSender::new(PushPolicy::new().allow_host("hooks.acme.example"))
        .allow_plaintext_loopback();
    let outcome = public
        .deliver(
            &config("http://hooks.acme.example/a2a"),
            &serde_json::json!({"statusUpdate": {}}),
        )
        .await;
    assert!(
        matches!(outcome, Err(PushError::NotHttps)),
        "the exception let a public host be posted to in clear: {outcome:?}"
    );

    // 3. Still refused: loopback the operator never granted. The exception
    //    lifts the second lock; the host grant is the first.
    let ungranted = PushSender::new(PushPolicy::new()).allow_plaintext_loopback();
    let outcome = ungranted
        .deliver(
            &config("http://localhost:1/hook"),
            &serde_json::json!({"statusUpdate": {}}),
        )
        .await;
    assert!(
        matches!(outcome, Err(PushError::HostNotGranted(_))),
        "the exception skipped the operator's grant: {outcome:?}"
    );

    // 4. And without the flag, the same call is refused — otherwise this whole
    //    battery would pass with the gate permanently open.
    let strict = PushSender::new(granted);
    let outcome = strict
        .deliver(
            &config("http://localhost:1/hook"),
            &serde_json::json!({"statusUpdate": {}}),
        )
        .await;
    assert!(
        matches!(outcome, Err(PushError::NotHttps)),
        "plaintext loopback was permitted without asking for it: {outcome:?}"
    );
}

/// A bracketed IPv6 literal is judged by the address rule, not lost in DNS.
///
/// `Url::host_str` keeps the brackets and the resolver refuses them, so before
/// the strip every v6 webhook fell through to a DNS lookup that cannot succeed
/// — one whole address family dead, and classified as a retryable outage. A
/// private literal must refuse for the **right** reason: forbidden, not
/// unresolvable.
#[tokio::test]
async fn a_bracketed_ipv6_webhook_is_judged_not_unresolvable() {
    use agentplane::push::{PushSender, PushTransport};

    // Documentation range: granted by the operator, still private, and never
    // behind a DNS answer — so the only correct refusal is the address rule's.
    let sender = PushSender::new(PushPolicy::new().allow_host("[2001:db8::1]"));
    let outcome = sender
        .deliver(
            &config("https://[2001:db8::1]/hook"),
            &serde_json::json!({"statusUpdate": {}}),
        )
        .await;
    let error = match outcome {
        Err(PushError::Unroutable(detail)) => detail,
        other => panic!("a private v6 literal produced {other:?}"),
    };
    assert!(
        error.contains("forbidden address"),
        "the refusal is not the address rule's — the literal fell through to \
         DNS and died as unresolvable: {error}"
    );
}

/// And with the testkit loopback exception, `[::1]` is actually dialled.
///
/// The end-to-end pin for the address family: the literal parses, resolves to
/// itself, and reaches the transport — nothing listens on port 1, so the
/// outcome is an unreachable delivery rather than any refusal.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_bracketed_ipv6_loopback_literal_is_dialled_under_the_exception() {
    use agentplane::push::PushSender;

    let sender = PushSender::new(PushPolicy::new().allow_host("[::1]")).allow_plaintext_loopback();
    let outcome = <PushSender as agentplane::push::PushTransport>::deliver(
        &sender,
        &config("http://[::1]:1/hook"),
        &serde_json::json!({"statusUpdate": {}}),
    )
    .await;
    assert!(
        matches!(outcome, Ok(agentplane::push::Delivered::Unreachable(_))),
        "a v6 loopback literal was refused rather than dialled: {outcome:?}"
    );
}

// ── What the payload says ───────────────────────────────────────────────────

/// A configuration read back never carries its token.
///
/// The token is a correlation secret for somebody else's endpoint. A caller that
/// can read a configuration it did not create would otherwise learn it — and the
/// only party that needs it already has it.
#[test]
fn a_configuration_read_back_does_not_carry_its_token() {
    let shown = config("https://hooks.acme.example/a2a").redacted();
    let text = serde_json::to_string(&shown).expect("serialize");
    // **Both** secrets, and the test used to check only one of them. The
    // fixture carries two — `token`, the A2A correlation secret, and
    // `authentication.credentials`, the receiver's bearer — and this assertion
    // named the credentials while the test was called *does not carry its
    // token*. A mutation echoing `token` back therefore passed it: the string it
    // exposed was not the string being looked for. A fixture with two secrets
    // needs an assertion that names both, or it proves whichever one nobody
    // broke.
    for secret in ["the-receivers-token", "opaque-a2a-token"] {
        assert!(
            !text.contains(secret),
            "a webhook secret was echoed back to a caller: {text}"
        );
    }
    assert_eq!(shown["url"], "https://hooks.acme.example/a2a");
}

/// A token does not appear in a debug rendering either.
#[test]
fn a_webhook_token_is_not_printable() {
    let text = format!("{:?}", config("https://hooks.acme.example/a2a"));
    assert!(
        !text.contains("the-receivers-token"),
        "a webhook token is printable, so it is one log line from disclosure: {text}"
    );
}

// ── Storage ─────────────────────────────────────────────────────────────────

/// Registrations survive, are listed per task, and are deleted idempotently.
#[tokio::test]
async fn registrations_round_trip() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store")) as Arc<dyn PushStore>;
    let mut first = config("https://hooks.acme.example/one");
    let task = first.task;
    first.id = "one".to_owned();
    let second = PushConfig {
        id: "two".to_owned(),
        task,
        url: "https://hooks.acme.example/two".to_owned(),
        token: None,
        authentication: None,
    };

    store.put(&first, 1).await.expect("put");
    store.put(&second, 5).await.expect("put");

    let back = store.get(task, "one").await.expect("get").expect("present");
    assert_eq!(back.url, first.url);
    assert_eq!(
        back.token.as_ref().map(Secret::expose),
        Some("opaque-a2a-token")
    );
    assert_eq!(
        back.authentication
            .as_ref()
            .map(|authentication| authentication.credentials.expose()),
        Some("the-receivers-token"),
        "authentication did not survive storage, so notifications after restart would be anonymous"
    );

    let all = store.list(task).await.expect("list");
    assert_eq!(all.len(), 2, "a task's registrations were not both listed");

    let due = store.due(0, 10).await.expect("due");
    assert_eq!(due.len(), 2);
    assert_eq!(due[0].next_seq, 1);
    store
        .retry(task, "one", 100, "receiver unavailable")
        .await
        .expect("retry");
    assert_eq!(store.due(99, 10).await.expect("not due").len(), 1);
    store.advance(task, "one", 7).await.expect("advance");
    let advanced = store
        .due(0, 10)
        .await
        .expect("advanced")
        .into_iter()
        .find(|registration| registration.config.id == "one")
        .expect("one");
    assert_eq!(advanced.next_seq, 7);
    assert_eq!(advanced.attempts, 0);

    store.delete(task, "one").await.expect("delete");
    store.delete(task, "one").await.expect("deleting twice");
    assert!(store.get(task, "one").await.expect("get").is_none());
    assert_eq!(store.list(task).await.expect("list").len(), 1);
}

/// The embedded backend's native `due_in` answers exactly as the trait's
/// paging default would.
///
/// The override exists to make the namespace filter one scan instead of a
/// re-reading window; it must never make it a different *answer*. The battery
/// and its reasoning live in [`crate::due_conformance`], shared with the
/// `PostgreSQL` backend so the two overrides are held to one semantics.
#[tokio::test]
async fn redb_due_in_matches_the_paging_default() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store")) as Arc<dyn PushStore>;
    crate::due_conformance::pin_due_in_against_the_default(store).await;
}

/// Replacing credentials or a URL must not acknowledge events on the receiver's
/// behalf. Otherwise an update while a webhook is down can jump its cursor to
/// the task head and silently lose every pending notification.
#[tokio::test]
async fn replacing_a_registration_preserves_its_unacknowledged_cursor() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store")) as Arc<dyn PushStore>;
    let first = config("https://hooks.acme.example/old");
    store.put(&first, 3).await.expect("put");

    let mut replacement = first.clone();
    replacement.url = "https://hooks.acme.example/new".to_owned();
    store
        .put(&replacement, 10)
        .await
        .expect("replace destination");

    let registration = store
        .due(0, 1)
        .await
        .expect("due")
        .pop()
        .expect("registration");
    assert_eq!(registration.config.url, replacement.url);
    assert_eq!(
        registration.next_seq, 3,
        "replacement acknowledged records 3 through 9 without delivering them"
    );
}

/// One tenant cannot read another's webhooks.
///
/// A task id is not a capability. Without the tenant leading the key, a handle
/// for one tenant holding a valid task id would read another tenant's webhook —
/// disclosing both a destination and the bearer token for it.
#[tokio::test]
async fn one_tenants_webhooks_are_not_another_tenants() {
    use agentplane::core::TenantId;

    let base = RedbStore::open_in_memory().expect("store");
    let acme = Arc::new(
        base.clone()
            .for_tenant(TenantId::new("acme").expect("valid")),
    ) as Arc<dyn PushStore>;
    let globex =
        Arc::new(base.for_tenant(TenantId::new("globex").expect("valid"))) as Arc<dyn PushStore>;

    let theirs = config("https://hooks.acme.example/secret");
    let task = theirs.task;
    acme.put(&theirs, 1).await.expect("acme registers");

    assert!(
        globex.get(task, "cfg-1").await.expect("get").is_none(),
        "one tenant read another's webhook while holding nothing but a valid \
         task id — disclosing a destination and its bearer token"
    );
    assert!(
        globex.list(task).await.expect("list").is_empty(),
        "one tenant listed another's webhooks"
    );

    // And acme still reads its own, so this isolated rather than broke it.
    assert!(acme.get(task, "cfg-1").await.expect("get").is_some());
}
