//! Sticky architecture guards for the two SSRF controls reqwest cannot prove
//! through its public response API: redirects stay manual, and checked DNS
//! answers are pinned into the connector that performs the request.

#![cfg(feature = "media")]

fn source() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/media/mod.rs"))
        .expect("media source")
}

fn context_source() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/runtime/ctx.rs"))
        .expect("runtime context source")
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let (_, tail) = source.split_once(start).expect("start anchor");
    let (body, _) = tail.split_once(end).expect("end anchor");
    body
}

#[test]
fn governed_media_pins_every_validated_dns_answer_into_the_connection() {
    let source = source();
    assert!(
        source.contains(".resolve_to_addrs(host, &addrs)"),
        "validating DNS and then letting the connector resolve again permits rebinding"
    );
}

#[test]
fn governed_media_keeps_automatic_redirects_disabled() {
    let source = source();
    assert!(
        source.contains(".redirect(reqwest::redirect::Policy::none())"),
        "automatic redirects can leave the exact-host and public-address policy without revalidation"
    );
}

#[test]
fn governed_media_revalidates_every_redirect_target() {
    let source = source();
    assert!(
        source.contains("current = self.policy.validate_url(current.as_str())?;"),
        "a redirect target must repeat scheme, exact-host, and port authorization before DNS or HTTP"
    );
}

#[test]
fn case_retention_links_are_durable_before_blob_bytes() {
    let media = source();
    let fetch = between(
        &media,
        "async fn perform(&self) -> Result<FetchedMedia, EffectError>",
        "enum MediaError",
    );
    assert!(
        fetch.find(".link_blob(").expect("media case link")
            < fetch.find(".put(&fetched.bytes)").expect("media blob put"),
        "a crash after a media blob write must not leave bytes outside case-erasure traversal"
    );

    let context = context_source();
    let store = between(
        &context,
        "pub async fn store_blob",
        "pub async fn fetch_media",
    );
    assert!(
        store.find(".link_blob(").expect("case link")
            < store.find(".put(bytes)").expect("blob put"),
        "a crash after a blob write must not leave bytes outside case-erasure traversal"
    );
}
