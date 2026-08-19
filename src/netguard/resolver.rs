//! The address rule applied at connect time, so a client can be reused.
//!
//! # Why this exists rather than pinning each request
//!
//! Pinning a connection to pre-approved addresses is correct and costs a whole
//! HTTP client per request: a pin is a property of a [`reqwest::Client`], so a
//! caller that pins per destination builds one per destination — a fresh pool,
//! TLS session and handshake for every call. Judging in the resolver keeps the
//! guarantee and drops the cost, and covers more: a pooled client opens
//! connections long after any pre-flight returned, and those resolve through
//! here too.
//!
//! # What this covers, and what the caller still owes
//!
//! **Names only.** A host that is already an IP literal never reaches any
//! resolver — the connector dials it directly — so nothing here sees it. That
//! is not a gap, because a literal cannot resolve to something else later:
//! there is exactly one address, the caller's pre-flight already judged it, and
//! it is the one dialled. Names are the case with a second answer in it, and
//! they are the case this exists for.
//!
//! So the division is: the caller's pre-flight judges **every** destination,
//! once, and is what refuses a forbidden one. This re-judges **every name
//! resolution**, which is what closes the window between that check and a
//! connection the pool opens later. Neither is sufficient alone, and both call
//! one rule — [`judge`] — so they cannot disagree.
//!
//! It is also not a *classifier*: a refused address and a name that does not
//! resolve both reach the caller as a connect error, because that is all a DNS
//! hook can return. Telling an operator which happened is the pre-flight's job.
//!
//! Building a client that uses this is [`guarded_client`], which is the only
//! supported way: the resolver alone is not the guarantee.

use std::net::SocketAddr;
use std::sync::Arc;

/// How far a client is permitted to reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reach {
    /// Publicly routable addresses only — the rule for anything whose URL was
    /// influenced by somebody outside the deployment.
    Public,
    /// Public, plus a host that **is** a loopback literal or `localhost`.
    ///
    /// Named rather than inferred: the exception covers a host that *is*
    /// loopback, never one that merely resolved there, which is the rebinding
    /// attack and stays refused. Reachable only from `testkit` callers.
    PublicOrLoopbackName,
    /// Whatever the resolver answers.
    ///
    /// For destinations the **deployment itself** configured, where resolving
    /// inward is the point: an in-cluster collector has no public address, and
    /// refusing it leaves an operator running a sidecar that terminates TLS and
    /// forwards in clear — the same exposure with an extra hop.
    ///
    /// Gated on the feature that owns the only construction, so a build without
    /// an operator outbox has no way to name the unrestricted reach at all —
    /// the compiler's answer to *which reaches exist here*, rather than a
    /// silenced lint that would let the variant outlive its caller.
    #[cfg(feature = "push")]
    Any,
}

/// Judge a set of resolved addresses against a reach.
///
/// The **one** implementation of "may this client connect to these", called
/// from two places on purpose: here, at connect time, where it is what the
/// socket obeys; and from a caller's pre-flight, where it is what an operator
/// gets told. A second spelling of it would agree everywhere except the
/// boundary nobody probed, which is how this crate has already shipped one
/// ceiling that was right in one backend and wrong in the other.
///
/// # Errors
///
/// [`super::NetGuardError`] — `NoAddresses` for an outage, `Forbidden` for the
/// SSRF case. The distinction is a type because the caller's response differs:
/// one is retried, one never is.
pub(crate) fn judge<I>(
    reach: Reach,
    host: &str,
    resolved: I,
) -> Result<Vec<SocketAddr>, super::NetGuardError>
where
    I: IntoIterator<Item = SocketAddr>,
{
    let addrs: Vec<SocketAddr> = resolved.into_iter().collect();
    let exempt = match reach {
        #[cfg(feature = "push")]
        Reach::Any => true,
        // Named rather than inferred: the exception covers a host that *is*
        // loopback, never one that merely resolved there.
        Reach::PublicOrLoopbackName => super::is_loopback_name(host),
        Reach::Public => false,
    };
    if !exempt {
        return super::all_public(host, addrs);
    }
    // An exemption is from the *address* rule, never from the one answer that
    // is not a judgement: nothing to connect to is an outage, and a caller that
    // could not tell it from a refusal would abandon a destination over a DNS
    // blip.
    if addrs.is_empty() {
        return Err(super::NetGuardError::NoAddresses {
            host: host.to_owned(),
        });
    }
    Ok(addrs)
}

/// A [`reqwest::dns::Resolve`] that applies [`judge`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct GuardedResolver {
    reach: Reach,
}

impl GuardedResolver {
    pub(crate) const fn new(reach: Reach) -> Self {
        Self { reach }
    }

    /// A shared handle, which is what [`reqwest::ClientBuilder::dns_resolver`]
    /// takes.
    pub(crate) fn shared(reach: Reach) -> Arc<Self> {
        Arc::new(Self::new(reach))
    }
}

/// A client builder that already carries every rule an outbound client here
/// needs.
///
/// One constructor rather than three settings each caller remembers, because
/// the three are not independent: a proxy makes the resolver unreachable, a
/// redirect makes the judged host the wrong host, and the resolver is what
/// judges at all. A caller that set two of the three would have a client that
/// looks guarded and is not, and nothing downstream could observe the
/// difference — the address it must not reach is one no test can make DNS
/// answer with on demand.
///
/// So the guarantee is structural: there is one way to build a guarded client
/// in this crate, and it is this. What each setting buys:
///
/// * **`dns_resolver`** — every *name* this client resolves is judged,
///   including on the connections a pool opens long after any caller's
///   pre-flight returned. An IP-literal host bypasses it, which costs nothing:
///   a literal has one address and cannot rebind. Deliberately not combined
///   with `resolve`/`resolve_to_addrs`, which reqwest applies *over* a custom
///   resolver rather than through it.
/// * **`no_proxy`** — a proxied request resolves the *proxy*, so the resolver
///   would never be asked about the destination host at all. It also keeps this
///   plane's ambient identity off a request it did not authorize.
/// * **`redirect::none`** — a judgement about the endpoint says nothing about
///   the third host it forwards to.
pub(crate) fn guarded_client(reach: Reach) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(GuardedResolver::shared(reach))
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let reach = self.reach;
        Box::pin(async move {
            let host = name.as_str().to_owned();
            // Port zero: reqwest replaces it with the URL's port, or the
            // scheme's default when the URL names none. Resolving against a
            // port of our own choosing would be a second place the port is
            // decided, and the one that drifts is whichever the tests do not
            // exercise.
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let addrs = judge(reach, &host, resolved)
                .map_err(|refusal| Box::new(refusal) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::dns::Resolve as _;

    /// The resolver refuses what the pre-flight would have refused.
    ///
    /// Tested here because this is the check a **pooled** connection obeys, and
    /// it is the one a caller's pre-flight cannot stand in for: the pool opens
    /// connections after that check returned, re-resolving as it does. A
    /// resolver that answered with the addresses anyway would leave every
    /// caller's refusal a formality that holds only until the first reconnect.
    #[tokio::test]
    async fn a_public_only_client_is_not_handed_a_loopback_address() {
        let name: reqwest::dns::Name = "localhost".parse().expect("a resolvable name");
        let refused = GuardedResolver::new(Reach::Public).resolve(name).await;
        let error = refused.err().expect("localhost resolves inward");
        assert!(
            error.to_string().contains("forbidden address"),
            "a public-only client was handed loopback: {error}"
        );
    }

    /// A client built here cannot reach a server that is genuinely listening
    /// on this machine.
    ///
    /// The one test that observes the **wiring** rather than the rule. Every
    /// caller also checks its destination before dispatching, so a refusal in a
    /// caller's test proves only that the pre-flight ran — a client with no
    /// resolver attached passes all of those unchanged, and the address it
    /// would then reach is one no test can make DNS answer with on demand.
    ///
    /// Here there is no pre-flight: the request goes straight out. A real
    /// listener is bound so that the default resolver would *succeed*, which is
    /// what makes the failure meaningful rather than a name that resolves to
    /// nothing.
    #[tokio::test]
    async fn a_guarded_client_does_not_reach_a_live_server_on_this_machine() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a local port");
        let port = listener.local_addr().expect("an address").port();
        let served = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt as _;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                    .await;
                return true;
            }
            false
        });

        let client = guarded_client(Reach::Public)
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("a client");
        let outcome = client.get(format!("http://localhost:{port}/")).send().await;
        assert!(
            outcome.is_err(),
            "a public-only client reached a server on this machine, so the \
             address rule is not attached to the client and every pre-flight \
             that passes it is the only check there is"
        );

        served.abort();
    }

    /// An IP-literal host is judged by the caller's pre-flight, never here.
    ///
    /// The connector dials a literal directly, so no resolver is consulted —
    /// which is why [`guarded_client`] is never the whole control and every
    /// caller checks its destination first. Pinned because the division of
    /// labour is invisible from either side alone: this asserts the half that
    /// is *not* covered here, so a later reading of "the client judges every
    /// connection" cannot quietly become true-sounding.
    #[tokio::test]
    async fn an_ip_literal_never_reaches_this_resolver() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static CALLS: AtomicUsize = AtomicUsize::new(0);

        #[derive(Debug)]
        struct Counting;
        impl reqwest::dns::Resolve for Counting {
            fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
                CALLS.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    let addrs = tokio::net::lookup_host((name.as_str(), 0)).await?;
                    Ok(Box::new(addrs.collect::<Vec<_>>().into_iter()) as reqwest::dns::Addrs)
                })
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a local port");
        let port = listener.local_addr().expect("an address").port();
        let served = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt as _;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                    .await;
            }
        });

        let client = reqwest::Client::builder()
            .dns_resolver(Arc::new(Counting))
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("a client");
        let _ = client.get(format!("http://127.0.0.1:{port}/")).send().await;
        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            0,
            "a literal reached the resolver, so the split this module documents \
             — pre-flight judges every destination, this judges every name — is \
             not the split the transport implements"
        );

        served.abort();
    }

    /// The named exception is an exception, and the deployment's own reach is
    /// not the caller's.
    #[tokio::test]
    async fn the_two_exemptions_reach_what_they_are_for_and_nothing_else() {
        // Built as a list rather than an array because the unrestricted reach
        // only exists where an operator outbox does. `mut` would be unused in
        // the build without one, which is itself denied.
        let exempt = {
            #[cfg(feature = "push")]
            {
                vec![Reach::PublicOrLoopbackName, Reach::Any]
            }
            #[cfg(not(feature = "push"))]
            {
                vec![Reach::PublicOrLoopbackName]
            }
        };
        for reach in exempt {
            let name: reqwest::dns::Name = "localhost".parse().expect("a resolvable name");
            let addrs = GuardedResolver::new(reach)
                .resolve(name)
                .await
                .unwrap_or_else(|error| panic!("{reach:?} refused localhost: {error}"));
            assert!(
                addrs.count() > 0,
                "{reach:?} answered with nothing, which is an outage rather than \
                 the exemption it is supposed to be"
            );
        }
    }

    /// The loopback exemption is keyed on the **name**, never on the answer.
    ///
    /// A host that merely resolves inward is the rebinding attack, and it stays
    /// refused with the exception in force — otherwise the exemption is not an
    /// exception, it is an off switch anybody can reach by controlling a DNS
    /// record.
    #[test]
    fn a_name_that_is_not_loopback_gets_no_exemption_from_its_answers() {
        let inward = "10.0.0.1:443".parse().expect("an address");
        let refused = judge(Reach::PublicOrLoopbackName, "peer.example", vec![inward]);
        assert!(
            matches!(refused, Err(super::super::NetGuardError::Forbidden { .. })),
            "a public name resolving to a private address was admitted under the \
             loopback exception: {refused:?}"
        );
    }
}
