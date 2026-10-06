//! The process side of `agentplane dev`: the plane the page drives, built by
//! the builder `run` uses and rebuilt over the same store when the manifest
//! file is saved and parses.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use agentplane::api::dev::{Declaration, DeclaredAgent, StartRequest, Started, Workbench};
use agentplane::core::{PolicyEngine, RunId, Tainted};
use agentplane::manifest::Manifest;
use agentplane::runtime::Runtime;

use super::{Backend, Fault};

/// How many runs of each outcome "replay every run" reads.
const REPLAY_LIMIT: usize = 1_000;

/// Everything a rebuild wires besides the manifests.
pub(super) struct Wiring {
    pub(super) file: String,
    pub(super) mcp: Vec<String>,
    pub(super) peer: Vec<String>,
    /// The subject `--acting-as` names; its chain is scoped to the file as
    /// each rebuild reads it.
    pub(super) acting_as: Option<String>,
    pub(super) policy: Arc<dyn PolicyEngine>,
}

/// The plane as the file last parsed, and the file as it is now.
struct Loaded {
    plane: Arc<Runtime>,
    manifests: Vec<Manifest>,
    /// The file's modification time when it was last read.
    modified: Option<SystemTime>,
    /// Why the file as it is now was not loaded.
    refused: Option<String>,
}

/// The dev session's plane.
pub(super) struct Bench {
    backend: Backend,
    wiring: Wiring,
    loaded: Mutex<Loaded>,
    /// Held for a whole rebuild, so two tabs reading a changed file build
    /// one plane and spawn each `--mcp` child once.
    reloading: tokio::sync::Mutex<()>,
    /// Where every plane this session builds forwards live model output.
    streams: Arc<agentplane::api::dev::StreamHub>,
}

fn modified(file: &str) -> Option<SystemTime> {
    std::fs::metadata(file).and_then(|m| m.modified()).ok()
}

impl Bench {
    /// Build the first plane.
    pub(super) async fn start(
        backend: Backend,
        wiring: Wiring,
        manifests: Vec<Manifest>,
    ) -> Result<Self, Fault> {
        let streams = agentplane::api::dev::StreamHub::new();
        let plane = Self::build(&backend, &wiring, &manifests, &streams).await?;
        let modified = modified(&wiring.file);
        Ok(Self {
            streams,
            backend,
            wiring,
            loaded: Mutex::new(Loaded {
                plane,
                manifests,
                modified,
                refused: None,
            }),
            reloading: tokio::sync::Mutex::new(()),
        })
    }

    async fn build(
        backend: &Backend,
        wiring: &Wiring,
        manifests: &[Manifest],
        streams: &Arc<agentplane::api::dev::StreamHub>,
    ) -> Result<Arc<Runtime>, Fault> {
        let chain = wiring
            .acting_as
            .as_deref()
            .map(|subject| super::chain_for(subject, manifests, &wiring.peer))
            .transpose()
            .map_err(super::usage)?;
        super::build_plane(
            backend,
            manifests,
            &wiring.mcp,
            &wiring.peer,
            chain,
            Some(Arc::clone(&wiring.policy)),
            Some(Arc::clone(streams) as Arc<dyn agentplane::runtime::RunStreamObserver>),
        )
        .await
    }

    fn held(&self) -> MutexGuard<'_, Loaded> {
        self.loaded.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Rebuild the plane when the file changed and parses; otherwise keep it,
    /// and say why the file as it is was not loaded.
    async fn reload_if_changed(&self) {
        let _rebuilding = self.reloading.lock().await;
        let now = modified(&self.wiring.file);
        if self.held().modified == now {
            return;
        }
        let loaded = match super::manifests_at(&self.wiring.file)
            .and_then(|m| super::require_declarative(&m).map(|()| m))
        {
            Ok(manifests) => Self::build(&self.backend, &self.wiring, &manifests, &self.streams)
                .await
                .map(|plane| (plane, manifests))
                .map_err(|fault| fault.to_string()),
            Err(why) => Err(why),
        };
        let mut held = self.held();
        held.modified = now;
        match loaded {
            Ok((plane, manifests)) => {
                held.plane = plane;
                held.manifests = manifests;
                held.refused = None;
            }
            Err(why) => held.refused = Some(why),
        }
    }
}

#[async_trait::async_trait]
impl Workbench for Bench {
    fn streams(&self) -> Arc<agentplane::api::dev::StreamHub> {
        Arc::clone(&self.streams)
    }

    async fn plane(&self) -> Arc<Runtime> {
        Arc::clone(&self.held().plane)
    }

    async fn declaration(&self) -> Declaration {
        self.reload_if_changed().await;
        let held = self.held();
        Declaration {
            file: self.wiring.file.clone(),
            agents: held
                .manifests
                .iter()
                .map(|m| DeclaredAgent {
                    name: m.metadata.name.clone(),
                    version: m.metadata.version.clone(),
                    digest: m
                        .digest()
                        .map_or_else(|e| e.to_string(), agentplane::core::Digest::to_hex),
                    bound: super::declared_bound(m).lines,
                    provides: m.spec.capabilities.provides.clone(),
                    input_schema: m.input_schema().cloned(),
                })
                .collect(),
            refused: held.refused.clone(),
            live: self
                .wiring
                .mcp
                .iter()
                .map(|m| format!("--mcp {m}"))
                .chain(self.wiring.peer.iter().map(|p| format!("--peer {p}")))
                .collect(),
        }
    }

    async fn start(&self, request: StartRequest) -> Result<Started, String> {
        let (plane, manifests) = {
            let held = self.held();
            (Arc::clone(&held.plane), held.manifests.clone())
        };
        let capability = super::entry_capability(&manifests, request.capability.as_deref())?;
        let keys = super::correlation(&request.correlate)?;
        let terms = agentplane::runtime::RunTerms::default().correlated(&capability, &keys);
        let agentplane::runtime::Admission::Fresh(outcome) = plane
            .run_under(&capability, Tainted::trusted(request.input), terms)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Err("an unkeyed run was answered as a keyed one".to_owned());
        };
        Ok(Started {
            run: outcome.run_id.to_string(),
            status: outcome.status.as_str().to_owned(),
        })
    }

    async fn replay(
        &self,
        run: Option<RunId>,
    ) -> Result<Vec<agentplane::api::dev::Replayed>, String> {
        let manifests = super::manifests_at(&self.wiring.file)?;
        let runs = if let Some(run) = run {
            vec![run]
        } else {
            let outcomes: Vec<String> = agentplane::runtime::OUTCOMES_OF_RECORD
                .iter()
                .map(|o| (*o).to_owned())
                .collect();
            agentplane::export::runs_to_read(&self.backend.journal(), &outcomes, true, REPLAY_LIMIT)
                .await
                .map_err(|e| e.to_string())?
                .runs
        };
        let mut verdicts = Vec::with_capacity(runs.len());
        for run in runs {
            let (verdict, detail) = match super::strict_verdict(&manifests, &self.backend, run)
                .await
                .map_err(|fault| fault.to_string())?
            {
                Ok(verdict) => {
                    use agentplane::runtime::Finding;
                    let kind = match verdict.finding {
                        Finding::Verified { .. } => "reproduced",
                        Finding::CannotReplay(_) => "cannot_replay",
                        _ => "diverged",
                    };
                    (kind, verdict.to_string())
                }
                Err(why) => ("unreadable", why),
            };
            verdicts.push(agentplane::api::dev::Replayed {
                run: run.to_string(),
                verdict: verdict.to_owned(),
                detail,
            });
        }
        Ok(verdicts)
    }
}
