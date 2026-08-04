//! Tests that talk to a real provider, and therefore cost money.
//!
//! # These do not run unless you ask twice
//!
//! Every test here skips unless **both** are set:
//!
//! * `AGENTPLANE_LIVE=1` — the deliberate opt-in;
//! * `OPENAI_API_KEY` — the credential.
//!
//! Two signals rather than one, and the second is the API key on purpose. A
//! developer with `OPENAI_API_KEY` exported in their shell — which is most
//! people who have one — would otherwise spend money every time they ran
//! `just ci`, and would find out at the end of the month. A credential being
//! *available* is not a decision to use it.
//!
//! They **skip loudly** rather than failing, matching the Postgres and Vault
//! batteries: a machine without credentials is not a broken build, and a silent
//! pass would be worse than either.
//!
//! Run them with `just test-live`, which loads `.env`.
//!
//! # Why bother, when `FakeProvider` exists
//!
//! The fake proves this crate's own logic. It cannot prove the *driver*: it
//! never rejects a malformed tool name, never returns a `finish_reason` we
//! mis-map, never disagrees with our idea of the wire format. Those are exactly
//! the defects a stubbed provider is structurally unable to have — and the
//! reason the Postgres and Vault batteries exist in the same shape.
//!
//! So each test below asserts something the fake could not: that a real provider
//! *accepts* what this crate sends, and that what it sends back is read the way
//! the crate claims.

mod openai;
