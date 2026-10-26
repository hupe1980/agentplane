//! A journal another process reads while this one writes.
//!
//! The writer is a second process — this test binary, run again with the
//! file's path in its environment — because redb's locks are per process: a
//! reader and a writer inside one process would prove nothing about two.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agentplane::core::{RunId, StoreError};
use agentplane::journal::{Append, JournalStore, RecordKind};
use agentplane::store::RedbStore;

const WRITER: &str = "AGENTPLANE_SHARED_JOURNAL_WRITER";

fn note(text: &str) -> RecordKind {
    RecordKind::Note {
        text: text.to_owned(),
    }
}

/// Wait for a marker file another process writes.
async fn until(path: &Path) {
    for _ in 0..600 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{} never appeared", path.display());
}

/// The writer half, run in a child process: opens the file shared, appends,
/// waits for the reader, appends again.
#[tokio::test]
#[ignore = "the writer half of a_reader_beside_a_live_writer_sees_its_commits, run in a child process"]
async fn the_shared_writer() {
    let Ok(dir) = std::env::var(WRITER).map(PathBuf::from) else {
        return;
    };
    let store = Arc::new(RedbStore::open_shared(dir.join("plane.redb")).expect("a shared writer"));
    let run: RunId = std::fs::read_to_string(dir.join("run"))
        .unwrap()
        .parse()
        .unwrap();
    let lease = store
        .acquire(run, "writer", Duration::from_secs(60))
        .await
        .unwrap();
    store
        .append(lease.epoch, vec![Append::new(run, note("one"))])
        .await
        .unwrap();
    std::fs::write(dir.join("ready"), "").unwrap();
    until(&dir.join("go")).await;
    store
        .append(lease.epoch, vec![Append::new(run, note("two"))])
        .await
        .unwrap();
    until(&dir.join("done")).await;
}

/// **A second process reads a journal while its writer works.** It sees the
/// writer's commits, is woken when the writer appends, cannot write, and a
/// second writer is still refused.
#[tokio::test]
async fn a_reader_beside_a_live_writer_sees_its_commits() {
    let dir = std::env::temp_dir().join(format!(
        "agentplane-shared-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let run = RunId::generate();
    std::fs::write(dir.join("run"), run.to_string()).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "shared_journal::the_shared_writer",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env(WRITER, &dir)
        .spawn()
        .expect("the writer process");
    until(&dir.join("ready")).await;
    let path = dir.join("plane.redb");

    // Beside the live writer: a reader opens, a second writer does not.
    let reader = Arc::new(RedbStore::open_read_only(&path).expect("a reader beside the writer"));
    assert!(
        matches!(RedbStore::open(&path), Err(StoreError::InUse(_))),
        "a second writer opened beside the live one"
    );
    assert!(
        matches!(RedbStore::open_shared(&path), Err(StoreError::InUse(_))),
        "a second shared writer opened beside the live one"
    );

    // It reads what the writer committed.
    let records = reader.read(run, 1).await.unwrap();
    assert_eq!(
        records.len(),
        1,
        "the reader missed a commit made before it read"
    );

    // It cannot write.
    assert!(
        matches!(
            reader.append(1, vec![Append::new(run, note("x"))]).await,
            Err(StoreError::ReadOnly)
        ),
        "a write through a read-only handle was not refused as read-only"
    );

    // It is woken when the writer appends.
    let mut follower = reader.watch(run).await.expect("a follower");
    std::fs::write(dir.join("go"), "").unwrap();
    let woke = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(head) = follower.changed().await {
            if head >= 2 {
                return Some(head);
            }
        }
        None
    })
    .await;
    assert!(
        matches!(woke, Ok(Some(2))),
        "the follower was not woken by the append: {woke:?}"
    );
    assert_eq!(reader.read(run, 1).await.unwrap().len(), 2);

    std::fs::write(dir.join("done"), "").unwrap();
    assert!(child.wait().unwrap().success(), "the writer process failed");
    let _ = std::fs::remove_dir_all(&dir);
}
