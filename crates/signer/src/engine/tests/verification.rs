//! Exercise production proof admission without executing a synthetic verifier.
use super::{
    Arc, DepositBinding, Engine, Gate, LineagePolicy, Path, PathBuf, PinnedVerifier, ProofSpec,
    RecoverySchedule, Relation, Result, TestTip, ensure, fs, hash, key, number, pubkey, random32,
};
use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use zark_protocol::{local::ProcessLock, proof::ArtifactPin};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn proof_lock_waits_cancels_and_still_rejects_invalid_statements() -> Result<()> {
    let scratch = Scratch(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../work")
            .join(format!("proof-lock-wait-{}", hex::encode(random32()))),
    );
    fs::create_dir_all(&scratch.0)?;
    // Admission precedes statement decoding. An invalid statement must never
    // execute this artifact, even once contention has cleared.
    let artifact = scratch.0.join("never-executed");
    let bytes = b"not an executable or verification key";
    fs::write(&artifact, bytes)?;
    let pin = || ArtifactPin {
        path: artifact.clone(),
        sha256: hash(&[bytes]),
    };
    let verifier = PinnedVerifier::new(
        [1; 32],
        pin(),
        scratch.0.clone(),
        [(Relation::DepositAuthorization, pin())],
    )?;
    let origin = key();
    let engine = Engine::open(
        &scratch.0.join("db/state.sqlite"),
        &scratch.0.join("floor/checkpoint.json"),
        LineagePolicy {
            deployment: [1; 32],
            schedule: RecoverySchedule {
                initial: 480,
                gap: 60,
                margin: 6,
            },
            origin_key: pubkey(&origin),
            role_hashes: std::array::from_fn(|i| number(i as u64 + 1)),
        },
        verifier,
        Arc::new(Gate::default()),
        Arc::new(TestTip::new()),
        key(),
        origin,
    )?;
    let spec = ProofSpec {
        relation: Relation::DepositAuthorization,
        expected: Vec::new(),
    };
    let path = fs::canonicalize(&engine.db)?.with_extension("proof-admission.lock");
    let held = ProcessLock::acquire(&path)?;
    let deadline = Instant::now() + Duration::from_millis(20);
    let error = engine
        .verify(&spec, &[], &|| {
            ensure!(
                Instant::now() < deadline,
                "private request deadline exceeded"
            );
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "private request deadline exceeded");
    assert!(ProcessLock::acquire(&path).is_err(), "lock was released");

    let expected = DepositBinding::decode(&[]).err().unwrap().to_string();
    thread::scope(|scope| -> Result<()> {
        let (waiting, started) = mpsc::channel();
        let (done, result) = mpsc::channel();
        let engine = &engine;
        let spec = &spec;
        let waiter = scope.spawn(move || {
            let error = engine
                .verify(spec, &[], &|| {
                    waiting.send(())?;
                    Ok(())
                })
                .unwrap_err();
            done.send(error.to_string()).unwrap();
        });
        started.recv_timeout(Duration::from_secs(2))?;
        assert!(matches!(
            result.recv_timeout(Duration::from_millis(40)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(held);
        assert_eq!(result.recv_timeout(Duration::from_secs(2))?, expected);
        waiter.join().unwrap();
        Ok(())
    })?;
    // Neither cancellation nor the failed statement strands the next ticket.
    assert_eq!(
        engine
            .verify(&spec, &[], &|| Ok(()))
            .unwrap_err()
            .to_string(),
        expected
    );
    drop(ProcessLock::acquire(&path)?);
    Ok(())
}
