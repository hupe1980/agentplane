//! Which IP addresses this plane will connect to.
//!
//! Two features dereference URLs a caller influences: governed media fetches one
//! a model was handed, and a push notification posts to one a peer supplied.
//! Both face the same attack — a hostname that resolves inward, to a metadata
//! service, a database, or a health endpoint that answers with something
//! interesting.
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
//! the public internet — is not expressible, and because it is never the only
//! control. Both callers also require an explicit **host** grant, so an address
//! must be both publicly routable *and* named by an operator. This list is the
//! second lock, not the first.

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

    #[test]
    fn the_ranges_an_ssrf_payload_aims_at_are_refused() {
        for addr in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254", // the cloud metadata service
            "0.0.0.0",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            // An IPv4 address in v6 notation still reaches loopback.
            "::ffff:127.0.0.1",
        ] {
            assert!(
                !is_public_ip(addr.parse().unwrap()),
                "{addr} was treated as publicly routable"
            );
        }
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
