#![cfg(all(feature = "keyring-vault", feature = "testkit"))]

//! The key ring contract, against a real Vault.
//!
//! `MemoryKeyRing` passing the battery proves the battery runs. It does not
//! prove `VaultTransit` works, because the two fail in entirely different
//! places: one cannot get a status code wrong or mis-decode base64, and the
//! other cannot get a `HashMap` wrong. An erasure obligation resting on an
//! adapter nothing ever ran is a promise nobody checked.
//!
//! The container is managed by `testcontainers`, so this needs a Docker daemon.
//! Without one the test **skips loudly** rather than failing, matching the
//! Postgres battery: a developer without Docker is not a broken build, and a
//! silent pass would be worse than either.

use std::sync::Arc;

use agentplane::keyring::{KeyRing, VaultTransit};
use agentplane::testkit::conformance_keyring;
use agentplane::testkit::memory_keyring::MemoryKeyRing;
use testcontainers_modules::testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{GenericImage, ImageExt};

/// The Vault release this adapter is certified against.
const VAULT: &str = "1.20";

/// Dev mode, so the root token is known and the server starts unsealed.
///
/// Fine here and nowhere else: a dev-mode Vault keeps everything in memory and
/// hands out a root token, which is exactly what a test wants and exactly what
/// production must not have.
const ROOT_TOKEN: &str = "conformance-root";

/// The same contract the in-process ring is held to.
///
/// Runs everywhere, every time — it needs no Docker — so a change that breaks
/// the battery itself is caught before anyone blames the container.
#[tokio::test]
async fn the_memory_key_ring_satisfies_the_key_ring_contract() {
    let ring = MemoryKeyRing::new();
    let report = conformance_keyring::check(&ring, "conformance-scope").await;
    report.assert_conforms("MemoryKeyRing");
}

/// The published port, retried.
///
/// `WaitFor` matching a stdout line means the process printed it, not that
/// Docker has finished publishing the port — so a one-shot query fails as
/// `PortNotExposed` on a loaded machine. That is a flake, and a flake trains
/// people to re-run rather than read, which costs more than the test is worth.
/// A genuinely dead container still fails here, loudly, after the bound.
async fn published_port<I>(
    container: &testcontainers_modules::testcontainers::ContainerAsync<I>,
    port: u16,
) -> u16
where
    I: testcontainers_modules::testcontainers::Image,
{
    let mut last = String::from("never queried");
    for _ in 0..50 {
        match container.get_host_port_ipv4(port).await {
            Ok(p) => return p,
            Err(e) => {
                last = e.to_string();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
    panic!("the container never published port {port}: {last}");
}

#[tokio::test]
async fn vault_transit_satisfies_the_key_ring_contract() {
    let image = GenericImage::new("hashicorp/vault", VAULT)
        .with_exposed_port(8200.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Development mode should NOT"))
        .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", ROOT_TOKEN)
        .with_env_var("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200");

    let Ok(container) = image.start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = published_port(&container, 8200).await;
    let address = format!("http://127.0.0.1:{port}");

    let http = reqwest::Client::new();
    let scope = "conformance-scope";

    // Enable the transit engine. A fresh Vault has no secrets engines mounted,
    // so this is setup rather than something the adapter should do: mounting an
    // engine is an operator's decision, not a side effect of storing a blob.
    let mounted = http
        .post(format!("{address}/v1/sys/mounts/transit"))
        .header("X-Vault-Token", ROOT_TOKEN)
        .json(&serde_json::json!({ "type": "transit" }))
        .send()
        .await
        .expect("mount transit");
    assert!(
        mounted.status().is_success(),
        "could not mount transit: {}",
        mounted.text().await.unwrap_or_default()
    );

    // Erasure is opt-in, and this is the line that makes it work. A transit key
    // refuses deletion unless configured for it, so a deployment that skips
    // this has a key ring that mints, opens and rotates perfectly and cannot
    // erase anything — which is the failure worth reproducing here rather than
    // discovering during an Article 17 request.
    for (path, body) in [
        (format!("keys/{scope}"), serde_json::json!({})),
        (
            format!("keys/{scope}/config"),
            serde_json::json!({ "deletion_allowed": true }),
        ),
    ] {
        let response = http
            .post(format!("{address}/v1/transit/{path}"))
            .header("X-Vault-Token", ROOT_TOKEN)
            .json(&body)
            .send()
            .await
            .expect("configure the transit key");
        assert!(
            response.status().is_success(),
            "configuring {path} failed: {}",
            response.text().await.unwrap_or_default()
        );
    }

    let ring: Arc<dyn KeyRing> = Arc::new(
        VaultTransit::new(&address, "transit", ROOT_TOKEN).expect("build the vault key ring"),
    );

    let report = conformance_keyring::check(ring.as_ref(), scope).await;
    report.assert_conforms("VaultTransit");
}

/// Erasure against a key that never allowed deletion fails, and says why.
///
/// The quiet failure this prevents: a deployment configures transit, never sets
/// `deletion_allowed`, and every erasure request comes back — from Vault — as a
/// 400 that a careless adapter would swallow or report as an outage worth
/// retrying. It is neither. It is a configuration decision that has to be made
/// before anyone is promised erasure, and the message has to say so.
#[tokio::test]
async fn erasing_a_key_that_forbids_deletion_is_refused_not_retried() {
    use agentplane::keyring::KeyError;

    let image = GenericImage::new("hashicorp/vault", VAULT)
        .with_exposed_port(8200.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Development mode should NOT"))
        .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", ROOT_TOKEN)
        .with_env_var("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200");

    let Ok(container) = image.start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = published_port(&container, 8200).await;
    let address = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();

    http.post(format!("{address}/v1/sys/mounts/transit"))
        .header("X-Vault-Token", ROOT_TOKEN)
        .json(&serde_json::json!({ "type": "transit" }))
        .send()
        .await
        .expect("mount transit");

    // Created, but never told deletion is allowed.
    let scope = "undeletable-scope";
    http.post(format!("{address}/v1/transit/keys/{scope}"))
        .header("X-Vault-Token", ROOT_TOKEN)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("create the key");

    let ring = VaultTransit::new(&address, "transit", ROOT_TOKEN).expect("build");
    let at = agentplane::core::Timestamp::from_unix_timestamp(1_760_000_000).expect("instant");

    match ring.destroy(scope, at, "art-17 request").await {
        Err(KeyError::Refused(why)) => {
            assert!(
                why.contains("deletion") || why.contains("not allowed"),
                "the refusal does not say what an operator must change: {why}"
            );
        }
        Err(KeyError::Unavailable(why)) => panic!(
            "a permanent configuration refusal was reported as a transient \
             outage, so a caller will retry an erasure that can never succeed: \
             {why}"
        ),
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(()) => panic!(
            "erasing a key that forbids deletion reported success — the data is \
             still readable and the request has been marked discharged"
        ),
    }
}
