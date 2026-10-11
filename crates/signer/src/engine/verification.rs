//! Bounded proof verification outside the signer checkpoint lock.
use super::{
    DepositBinding, Engine, IssuanceBinding, LineageHandoverBinding, PredecessorKind, ProofSpec,
    Proofs, Relation, Result, ensure, fs, hash, random32,
};
use anyhow::Context;
use std::os::unix::fs::DirBuilderExt;

impl Engine {
    pub(super) fn verify(
        &self,
        spec: &ProofSpec,
        proof: &[u8],
        guard: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        #[cfg(test)]
        if let Proofs::Test(oracle) = &self.verifier {
            guard()?;
            return oracle.verify(spec, proof);
        }
        #[allow(
            clippy::infallible_destructuring_match,
            reason = "Production has only the real verifier; tests add a separately handled oracle variant"
        )]
        let verifier = match &self.verifier {
            Proofs::Real(verifier) => verifier,
            #[cfg(test)]
            Proofs::Test(_) => unreachable!(),
        };
        // Reuse bounded FIFO admission (128 requests, 5 seconds) independently
        // of the short checkpoint lock. One external verifier per database;
        // revision CAS still runs after verification and after this guard drops.
        let admission_path = fs::canonicalize(&self.db)?.with_extension("proof-admission.lock");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let _admission = crate::admission::Permit::acquire(&admission_path, deadline, guard)?;
        let _process = crate::admission::acquire_process_lock(
            &admission_path,
            deadline,
            guard,
            "proof verification busy: lock deadline",
        )?;
        guard()?;
        let scratch = self
            .db
            .parent()
            .context("db parent")?
            .join(format!("proof-{}", hex::encode(random32())));
        fs::DirBuilder::new().mode(0o700).create(&scratch)?;
        let result = (|| {
            let raw = &spec.expected;
            let verified = match spec.relation {
                Relation::SenderFromOrigin | Relation::SenderFromTransfer => verifier
                    .sender_handover(
                        if spec.relation == Relation::SenderFromOrigin {
                            PredecessorKind::Origin
                        } else {
                            PredecessorKind::Transfer
                        },
                        &LineageHandoverBinding::decode(raw)?,
                        proof,
                        &scratch,
                    )?,
                Relation::DepositAuthorization => verifier.deposit_authorization(
                    &DepositBinding::decode(raw)?,
                    proof,
                    &scratch,
                )?,
                Relation::ReceiverAuthorization => verifier.receiver_authorization(
                    &IssuanceBinding::decode(raw)?,
                    proof,
                    &scratch,
                )?,
                Relation::ExitFromOrigin | Relation::ExitFromTransfer => verifier
                    .cooperative_exit(
                        if spec.relation == Relation::ExitFromOrigin {
                            PredecessorKind::Origin
                        } else {
                            PredecessorKind::Transfer
                        },
                        &IssuanceBinding::decode(raw)?,
                        proof,
                        &scratch,
                    )?,
            };
            ensure!(
                verified.relation() == spec.relation && verified.statement_digest() == hash(&[raw]),
                "verifier returned a different relation"
            );
            Ok(())
        })();
        let _ = fs::remove_dir_all(scratch);
        result
    }
}
