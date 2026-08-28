//! Domain-agnostic types and traits. **No I/O lives here.**
//!
//! This module's only dependencies are `serde`, `thiserror`, `async-trait`, and
//! the hashing primitives. That is enforced by a test in `tests/guards/layering.rs`
//! which fails the build if `core` gains an edge to any I/O-bearing module.
//!
//! The discipline matters more than it looks: it keeps the type layer
//! reviewable, lets the whole runtime be swapped under a simulator, and makes an
//! eventual crate split mechanical rather than archaeological.

mod attest;
mod budget;
mod calendar;
pub mod canon;
mod case;
mod cloudevent;
mod effect;
pub(crate) mod error;
mod event;
mod id;
mod identity;
mod label;
pub mod merkle;
mod plan;
mod policy;
mod retry;
mod secret;
mod skill;
mod task;
mod tenant;

pub use attest::{
    AttestError, Attestation, CheckpointSigner, DOMAIN_MANIFEST, DOMAIN_PROVENANCE, DOMAIN_RECORD,
    KeyId, SignError, Signer, Verifier, signing_hash,
};
pub use budget::{Budget, BudgetExceeded, Consumed, Ledger, Spend};
pub use calendar::{Calendar, CalendarError, WallClock};
pub use cloudevent::{
    CONTENT_TYPE as CLOUDEVENT_CONTENT_TYPE, CloudEvent, CloudEventError,
    HEADER_PREFIX as CLOUDEVENT_HEADER_PREFIX, SPEC_VERSION as CLOUDEVENT_SPEC_VERSION,
    is_structured_media_type as is_cloudevent_media_type,
};
mod quorum;
pub use quorum::{Outcome as QuorumOutcome, Quorum, QuorumError, Tally, Verdict};

mod egress;
pub use egress::{Egress, EgressError};

mod provenance;
pub use provenance::{NS as PROVENANCE_NS, Provenance};

pub use case::{
    Case, CaseStatus, CaseVersion, CorrelationKey, Deadline, DeadlineSpec, DeadlineState,
    SweptAction,
};
pub use effect::{
    AnyEffect, DeclaredOutput, Effect, EffectDescriptor, GroupOutcome, Reconciliation, Recovery,
};
pub use error::{
    Disposition, EffectError, PolicyError, REFUSED, RuntimeError, SkillError, StepError, StoreError,
};
pub use event::{
    AwaitSpec, DeadLetter, Delivery, InboundEvent, Subscription, SuspendReason, Timer,
};
pub use id::{
    BatchId, CaseId, Digest, EffectKey, Epoch, Phase, RunId, Seq, StepId, Timestamp,
    format_timestamp,
};
pub use identity::{
    Delegation, DelegationError, DelegationScheme, MAX_DELEGATION_DEPTH, Principal, Scope,
};
pub use label::{
    Label, ProtectedField, Release, ReleaseMark, ReleaseScope, Sensitivity, SourceId, Tainted,
    Trust,
};
pub use plan::{ArgSource, Collaboration, PlanError, PlanIR, PlanNode, Topology};
pub use policy::{
    ACTION_ADMIT, ACTION_DECLARED, ACTION_EGRESS, ACTION_PERFORM, ACTION_RELEASE, DenyAll,
    PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest,
};
pub use retry::{RetryPolicy, retry_after_seconds};
pub use secret::Secret;
pub use skill::{AgentRef, Capability, Compensation, Outcome, Skill, SkillDescriptor};
pub use task::{
    ClaimError, Decision, Justification, OnExpiry, Priority, Task, TaskId, TaskSpec, TaskState,
};
pub use tenant::{TenantError, TenantId, erasure_scope};
