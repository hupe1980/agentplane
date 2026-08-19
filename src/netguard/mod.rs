//! Which IP addresses this plane will connect to.
//!
//! Three features dereference a URL somebody else influenced: governed media
//! fetches one a model was handed, a push notification posts to one a peer
//! supplied, and Agent Card discovery fetches one that arrived in a config, a
//! registry entry or a message. All three face the same attack — a hostname
//! that resolves inward, to a metadata service, a database, or a health
//! endpoint that answers with something interesting.
//!
//! Counting them is part of the control. This module said *two* while discovery
//! was already the third and unguarded, which is the shape of a claim written
//! about every other door while looking at this one: the sentence was true when
//! written, nothing re-checked it, and the door it did not know about was the
//! one standing open.
//!
//! The classification lives here, once, because two implementations of one rule
//! diverge and the one that diverges is whichever nobody probed at the boundary.
//! That is not hypothetical: this crate has already shipped a ceiling that was
//! correct in one backend and wrong in the other at exactly the edge case an
//! operator relies on.
//!
//! # Pure, and deliberately not in `core`
//!
//! This module makes no network calls: it answers *is this address one we are
//! willing to reach*, given an address somebody else resolved. Resolution and
//! connection pinning belong to the caller, because those need a runtime and a
//! client.
//!
//! It still does not live in `core`, which may not reference `std::net` at all —
//! a guard enforces that, and it caught this module on the way in. The rule is
//! blunter than strictly necessary and worth keeping blunt: "no I/O types" is
//! checkable, while "no I/O, except types that only describe addresses" is an
//! argument somebody has to re-make for every exception.
//!
//! # Deny-list, not allow-list, and why that is acceptable here
//!
//! A deny-list of private ranges is normally the weaker construction: anything
//! missed is permitted. It is used here because the alternative — enumerating
//! the public internet — is not expressible, and because it is usually not the
//! only control: media and push both also require an explicit **host** grant,
//! so an address must be both publicly routable *and* named by an operator.
//! This list is meant as the second lock.
//!
//! Card discovery is the exception worth stating rather than glossing: its
//! allowlist is optional, because a deployment that discovers agents from the
//! open internet cannot enumerate them in advance and one that refused to try
//! would simply not be used. With no allowlist set this list is the *only* lock
//! on that path — which is why it is applied there unconditionally, and why a
//! deployment that can name its peers should still name them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether this address is one the plane may connect to.
///
/// False for anything private, local, link-local, multicast, or otherwise
/// special — the ranges an SSRF payload aims at.
#[must_use]
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    // An IPv4-mapped address is an IPv4 address wearing a different notation, so
    // it is judged as one. Skipping this is how `::ffff:127.0.0.1` reaches
    // loopback through a v6 check that looked thorough.
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_v4(mapped);
    }
    // The first two clauses are deliberately redundant: `::` and `::1` both
    // have `segments[0] == 0`, so the clause below already refuses them. They
    // stay because a reader should not have to derive "loopback is refused"
    // from a bitmask, and because the arithmetic rule could later be narrowed.
    //
    // The consequence is worth stating so it is not re-investigated: an
    // automated sweep reports `|| -> &&` here as surviving, and it always will.
    // Nothing can distinguish the two, since every address satisfying either
    // clause satisfies the one below. It is an equivalent mutant, not a gap —
    // the only one left in this file, and the rest of it is pinned from both
    // sides of every edge by `every_range_is_refused_and_its_neighbour_is_not`.
    !(ip.is_unspecified()
        || ip.is_loopback()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        || (segments[0] & 0xff00) == 0xff00
        || segments[0] == 0
        || (segments[0] == 0x0064 && segments[1] == 0xff9b)
        || (segments[0] == 0x0100 && segments[1] == 0)
        || (segments[0] == 0x2001 && segments[1] <= 0x01ff)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[0] == 0x2002
        || (segments[0] & 0xfff0) == 0x3ff0
        || segments[0] == 0x5f00)
}

/// Whether a host *names* this machine, without resolving it.
///
/// Literals only, plus the one name every stack special-cases. Anything that
/// merely **resolves** to loopback is deliberately not covered: that is
/// [`all_public`]'s job against the answers DNS actually gave, and a name-based
/// guess in front of it would be a second implementation of one rule.
///
/// The distinction is the whole security content of this function. A loopback
/// exception keyed on the *name* is one a deployment wrote down; one keyed on
/// the *resolution* is one an attacker arranges, because making a name resolve
/// inward is the rebinding attack itself.
#[must_use]
pub fn is_loopback_name(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// A host grant, canonicalised the way a fetched or posted URL's host will be.
///
/// Both callers that grant a host — governed media and push webhooks — compare
/// the grant against [`reqwest::Url::host_str`], which the URL crate has
/// already lowercased and IDNA-encoded to punycode. A grant that was only
/// lowercased would store an internationalised host in its Unicode form and
/// **never match** the `xn--…` a URL to that host carries — fail-closed, but
/// silently, refusing every request to the host it was meant to permit. Both
/// grants therefore route through this, so the two sides agree by construction.
///
/// One implementation, in the module both callers already share for the
/// address rule, because the copy that diverges is whichever nobody probed at
/// the boundary — exactly how this crate shipped the same host check twice with
/// one silent gap.
///
/// `None` for anything that is not a bare host a URL could name: a grant
/// carrying a port, userinfo, a path, a query or a fragment is not the exact
/// host it appears to be, and is refused rather than stored as something that
/// cannot match.
#[cfg(any(feature = "media", feature = "push"))]
#[must_use]
pub fn canonical_host(raw: &str) -> Option<String> {
    let url = reqwest::Url::parse(&format!("https://{}/", raw.trim())).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url.host_str()?.trim_end_matches('.').to_ascii_lowercase())
}

/// Refuse unless **every** resolved address is public.
///
/// All of them, not the first: a hostname that answers with one public address
/// and one private one is the standard rebinding setup, and a check that stops
/// at the first answer passes it. The caller must then connect to exactly these
/// addresses — resolving again would invite a different answer.
///
/// Why a resolution was rejected.
///
/// Two variants rather than one string, because the caller's response differs by
/// kind: an empty resolution is an outage (retry later), a forbidden address is
/// a refusal (never fetch this). Deciding that by matching on message text — as
/// `media` once did — means the first reword of a message here silently flips a
/// retry into an abandonment. The distinction is a type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetGuardError {
    /// The host resolved to no addresses at all. An outage, not a refusal.
    #[error("DNS for '{host}' returned no addresses")]
    NoAddresses { host: String },
    /// The host resolved to a non-public address — loopback, private,
    /// link-local, or the cloud metadata service. The SSRF case.
    #[error("'{host}' resolved to forbidden address {address}")]
    Forbidden { host: String, address: IpAddr },
}

/// # Errors
///
/// [`NetGuardError::NoAddresses`] when there were no answers at all, and
/// [`NetGuardError::Forbidden`] when any answer is not public.
pub fn all_public<I>(host: &str, addresses: I) -> Result<Vec<std::net::SocketAddr>, NetGuardError>
where
    I: IntoIterator<Item = std::net::SocketAddr>,
{
    let addresses: Vec<_> = addresses.into_iter().collect();
    if addresses.is_empty() {
        return Err(NetGuardError::NoAddresses {
            host: host.to_owned(),
        });
    }
    for address in &addresses {
        if !is_public_ip(address.ip()) {
            return Err(NetGuardError::Forbidden {
                host: host.to_owned(),
                address: address.ip(),
            });
        }
    }
    let mut unique = std::collections::BTreeSet::new();
    unique.extend(addresses);
    Ok(unique.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every range, from both sides of every edge.
    ///
    /// A list of addresses that must be refused proves less than it looks. It
    /// cannot fail when a bound moves *outward*, because a wider rule still
    /// refuses everything the list names — so `b == 254` becoming `b != 254`,
    /// or `<=` becoming `>`, leaves it green while the classifier has changed
    /// meaning. An automated sweep put a number on that: of 111 mutations to
    /// this file, **67 survived** — nearly every comparison and nearly every
    /// `||` between the ranges, in the one function standing between a hostile
    /// URL and the internal network.
    ///
    /// So each row carries an address *inside* the range and its nearest
    /// neighbour *outside*, and the outside half is what does the work: it is
    /// the only thing that fails when a rule grows. The neighbours are chosen
    /// to be caught by no other rule, or they would prove nothing either.
    ///
    /// This pins **this classifier's** boundaries, not IANA's registry. Where
    /// the two differ the code is the subject under test, and a deliberate
    /// widening should fail here and be re-approved rather than pass quietly.
    /// (refused address, permitted neighbour, what the pair pins)
    type Edge = (&'static str, &'static str, &'static str);

    /// Both halves of every row, with the message naming which half failed.
    fn assert_edges(edges: &[Edge]) {
        for &(refused, permitted, why) in edges {
            assert!(
                !is_public_ip(refused.parse().unwrap()),
                "{refused} was treated as publicly routable ({why})"
            );
            assert!(
                is_public_ip(permitted.parse().unwrap()),
                "{permitted} was refused, so the rule for {why} reaches further \
                 than it should — the guard is refusing part of the internet"
            );
        }
    }

    #[test]
    fn every_ipv4_range_is_refused_and_its_neighbour_is_not() {
        assert_edges(&[
            ("0.1.2.3", "1.0.0.1", "0.0.0.0/8 — 'this network'"),
            ("10.255.255.254", "11.0.0.1", "10/8 private"),
            ("127.255.255.254", "128.0.0.1", "127/8 loopback"),
            (
                "100.64.0.1",
                "100.63.255.254",
                "100.64/10 CGNAT, lower edge",
            ),
            (
                "100.127.255.254",
                "100.128.0.1",
                "100.64/10 CGNAT, upper edge",
            ),
            (
                "169.254.169.254",
                "169.253.0.1",
                "link-local — cloud metadata",
            ),
            ("169.254.0.1", "169.255.0.1", "link-local, upper edge"),
            ("172.16.0.1", "172.15.0.1", "172.16/12 private, lower edge"),
            (
                "172.31.255.254",
                "172.32.0.1",
                "172.16/12 private, upper edge",
            ),
            (
                "192.0.0.1",
                "192.0.1.1",
                "192.0.0/24 IETF protocol assignments",
            ),
            ("192.0.2.1", "192.0.3.1", "192.0.2/24 TEST-NET-1"),
            (
                "192.88.99.1",
                "192.88.100.1",
                "192.88.99/24 6to4 relay anycast",
            ),
            (
                "192.168.1.1",
                "192.167.0.1",
                "192.168/16 private, lower edge",
            ),
            (
                "192.168.255.254",
                "192.169.0.1",
                "192.168/16 private, upper edge",
            ),
            (
                "198.18.0.1",
                "198.17.0.1",
                "198.18/15 benchmarking, lower edge",
            ),
            (
                "198.19.255.254",
                "198.20.0.1",
                "198.18/15 benchmarking, upper edge",
            ),
            ("198.51.100.1", "198.51.101.1", "198.51.100/24 TEST-NET-2"),
            ("203.0.113.1", "203.0.114.1", "203.0.113/24 TEST-NET-3"),
            ("224.0.0.1", "223.255.255.254", "224/4 multicast and above"),
            ("255.255.255.255", "223.255.255.254", "broadcast"),
        ]);
    }

    /// The v6 half of [`every_ipv4_range_is_refused_and_its_neighbour_is_not`].
    ///
    /// Split by family only to keep each function readable; the reasoning in
    /// that test's documentation governs both.
    #[test]
    fn every_ipv6_range_is_refused_and_its_neighbour_is_not() {
        assert_edges(&[
            ("::", "1::1", "unspecified, and ::/16 generally"),
            ("::2", "1::1", "::/16 — includes IPv4-compatible v6"),
            ("::1", "1::1", "loopback"),
            // An IPv4 address in v6 notation still reaches what it names, and
            // the neighbour proves the mapping is judged rather than waved past.
            (
                "::ffff:127.0.0.1",
                "::ffff:1.1.1.1",
                "IPv4-mapped is judged as v4",
            ),
            ("64:ff9b::1", "64:ff9c::1", "64:ff9b::/32 NAT64 well-known"),
            ("64:ff9b:1::1", "65::1", "64:ff9b:1::/48 local-use NAT64"),
            ("100::1", "101::1", "100::/64 discard-only"),
            (
                "2001::1",
                "2001:200::1",
                "2001::/23 protocol assignments, lower",
            ),
            ("2001:1ff::1", "2001:200::1", "2001::/23 upper edge"),
            ("2001:db8::1", "2001:db9::1", "2001:db8::/32 documentation"),
            ("2002::1", "2003::1", "2002::/16 6to4"),
            ("3ffe::1", "3fe0::1", "3ff0::/12, lower edge"),
            ("3fff::1", "3fe0::1", "3ff0::/12, upper edge"),
            ("5f00::1", "5f01::1", "5f00::/16 segment routing"),
            ("fc00::1", "fe00::1", "fc00::/7 unique-local, lower edge"),
            ("fdff::1", "fe00::1", "fc00::/7 unique-local, upper edge"),
            ("fe80::1", "fe40::1", "fe80::/10 link-local, lower edge"),
            ("febf::1", "fe40::1", "fe80::/10 link-local, upper edge"),
            ("fec0::1", "fe00::1", "fec0::/10 site-local, lower edge"),
            ("feff::1", "fe00::1", "fec0::/10 site-local, upper edge"),
            ("ff02::1", "fe00::1", "ff00::/8 multicast"),
        ]);
    }

    #[test]
    fn ordinary_public_addresses_are_permitted() {
        for addr in ["1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"] {
            assert!(
                is_public_ip(addr.parse().unwrap()),
                "{addr} was refused, so the guard refuses the internet"
            );
        }
    }

    /// One private answer poisons the whole resolution.
    ///
    /// The rebinding setup: a name answers with one public address and one
    /// private one, and a check that stops at the first passes it.
    #[test]
    fn one_private_answer_refuses_the_whole_resolution() {
        let addrs = [
            "1.1.1.1:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ];
        assert!(
            all_public("rebind.example", addrs).is_err(),
            "a resolution containing a private address was accepted because \
             another answer was public"
        );
    }
}
