//! Fresh signer snapshots are separate from historical proof and live Bitcoin
//! validity. Probes are short-lived in-memory values, never serialized retries.
use anyhow::{Result, ensure};
use k256::schnorr::SigningKey;
use serde::Deserialize;
use serde_json::Value;
use std::time::{Duration, Instant};
use zark_protocol::{
    handoff::{Digest, TransferContext},
    head::{Head, HeadQuery, Phase},
    remote::RemoteEndpoint,
    wire::{Command, Request},
};

const HEAD_LIFETIME: Duration = Duration::from_secs(30);

/// Implementations must authenticate the endpoint before disclosing requests.
/// Tests may use the actual isolated Engine through an in-process adapter.
pub trait SignerClient {
    fn request(&self, request: &Request) -> Result<Value>;
}
impl SignerClient for RemoteEndpoint {
    fn request(&self, request: &Request) -> Result<Value> {
        self.request(request)
    }
}

pub struct HeadProbe {
    request: Request,
    query: HeadQuery,
    deadline: Instant,
}
pub struct FreshHead {
    head: Head,
    deadline: Instant,
}

impl HeadProbe {
    pub fn new(context: &TransferContext, key: &SigningKey) -> Result<Self> {
        let query = HeadQuery::fresh(context.deployment, context.coin, context.session_auth)?;
        let request = Request::sign(
            context.clone(),
            Command::Head {
                query: query.clone(),
            },
            key,
        )?;
        Ok(Self {
            request,
            query,
            deadline: Instant::now() + HEAD_LIFETIME,
        })
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn verify(
        self,
        response: Value,
        control: &Digest,
        state: &Digest,
        capability: &Digest,
        phase: Phase,
    ) -> Result<FreshHead> {
        ensure!(
            Instant::now() < self.deadline,
            "signer head probe expired; request a fresh head"
        );
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reply {
            head: Head,
            signature: Vec<u8>,
        }
        let response: Reply = serde_json::from_value(response)
            .map_err(|_| anyhow::anyhow!("invalid signer head response"))?;
        let signature: [u8; 64] = response
            .signature
            .try_into()
            .map_err(|_| anyhow::anyhow!("head signature length"))?;
        response.head.verify(&self.query, control, &signature)?;
        ensure!(
            response.head.state == *state
                && response.head.capability == *capability
                && response.head.phase == phase,
            "signer no longer reports the expected ownership state"
        );
        let checked = FreshHead {
            head: response.head,
            deadline: self.deadline,
        };
        checked.require_fresh()?;
        Ok(checked)
    }
}
/// Reads a signed head and live Bitcoin evidence concurrently. They are reads
/// of independent systems, so sequencing them never made them atomic; the
/// freshness rules that do matter are enforced here instead of by ordering:
/// - the probe, and with it the deadline, exists before either read starts;
/// - the head is verified when its reply arrives and must still be fresh after
///   the chain read has also finished, however slowly either completed;
/// - nothing is retried or saved: a failed, slow or expired read fails the
///   check, and a new attempt needs a new probe and a new chain read. The chain
///   adapter's bounded tip-change retries remain inside this window.
///
/// The chain read runs on a helper thread because signer sessions are
/// thread-local; its `bitcoin-cli` children inherit this thread's lock.
pub fn read_with_chain<T: Send>(
    probe: HeadProbe,
    client: &dyn SignerClient,
    verify: impl FnOnce(HeadProbe, Value) -> Result<FreshHead>,
    chain: impl FnOnce() -> Result<T> + Send,
) -> Result<(FreshHead, T)> {
    let (head, observed) = zark_protocol::local::join_with_helper(
        || {
            let response = client.request(probe.request())?;
            verify(probe, response)
        },
        chain,
    )?;
    let head = head?;
    let observed = observed?;
    head.require_fresh()?;
    Ok((head, observed))
}

impl FreshHead {
    /// Call again after live Bitcoin observations and immediately before local
    /// acceptance. Passing does not make two independent systems atomic.
    pub fn require_fresh(&self) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline,
            "signer head expired during local checks"
        );
        Ok(())
    }
    pub fn revision(&self) -> u64 {
        self.head.revision
    }
    pub fn checkpoint_sequence(&self) -> u64 {
        self.head.checkpoint_sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Result<(TransferContext, SigningKey, SigningKey)> {
        let key = SigningKey::from_bytes(&[9; 32])?;
        let control = SigningKey::from_bytes(&[10; 32])?;
        Ok((
            TransferContext {
                start_revision: 1,
                scope: zark_protocol::handoff::OperationScope::Single,
                deployment: [1; 32],
                coin: [2; 32],
                previous_state: [3; 32],
                operation: [4; 32],
                recipient_claim: [5; 32],
                session_auth: key.verifying_key().to_bytes().into(),
            },
            key,
            control,
        ))
    }
    struct Signer<F: Fn() -> Result<Value>>(F, std::cell::Cell<u32>);
    impl<F: Fn() -> Result<Value>> SignerClient for Signer<F> {
        fn request(&self, _: &Request) -> Result<Value> {
            self.1.set(self.1.get() + 1);
            self.0()
        }
    }

    #[test]
    fn head_and_chain_reads_overlap_inside_one_freshness_window() -> Result<()> {
        use std::sync::{atomic::AtomicU32, atomic::Ordering::SeqCst, mpsc};
        let (context, key, control) = fixture()?;
        let control_public = control.verifying_key().to_bytes().into();
        let verify = |probe: HeadProbe, reply| {
            probe.verify(reply, &control_public, &[6; 32], &[7; 32], Phase::Accepted)
        };

        // The head reply waits until the chain read has started: sequential
        // reads would time out here instead of returning both results.
        let probe = HeadProbe::new(&context, &key)?;
        let reply = response(&probe, &control)?;
        let (started, chain_started) = mpsc::channel();
        let signer = Signer(
            || {
                chain_started.recv_timeout(Duration::from_secs(5))?;
                Ok(reply.clone())
            },
            Default::default(),
        );
        let (head, observed) = read_with_chain(probe, &signer, verify, move || {
            started.send(())?;
            Ok(11)
        })?;
        assert_eq!((head.revision(), observed, signer.1.get()), (8, 11, 1));

        // A head verified on arrival still expires during a slow chain read.
        let mut probe = HeadProbe::new(&context, &key)?;
        let reply = response(&probe, &control)?;
        probe.deadline = Instant::now() + Duration::from_millis(100);
        let signer = Signer(|| Ok(reply.clone()), Default::default());
        let chain_reads = AtomicU32::new(0);
        let slow = read_with_chain(probe, &signer, verify, || {
            chain_reads.fetch_add(1, SeqCst);
            std::thread::sleep(Duration::from_millis(250));
            Ok(())
        });
        assert!(slow.is_err_and(|e| e.to_string().contains("expired")));
        assert_eq!((signer.1.get(), chain_reads.load(SeqCst)), (1, 1));

        // Either failed read fails the check; neither side is retried.
        let probe = HeadProbe::new(&context, &key)?;
        let signer = Signer(|| anyhow::bail!("signer unavailable"), Default::default());
        let chain_reads = AtomicU32::new(0);
        let failed = read_with_chain(probe, &signer, verify, || {
            chain_reads.fetch_add(1, SeqCst);
            Ok(())
        });
        assert!(failed.is_err());
        assert_eq!((signer.1.get(), chain_reads.load(SeqCst)), (1, 1));
        let probe = HeadProbe::new(&context, &key)?;
        let reply = response(&probe, &control)?;
        let signer = Signer(|| Ok(reply.clone()), Default::default());
        let failed = read_with_chain(probe, &signer, verify, || -> Result<()> {
            anyhow::bail!("chain unavailable")
        });
        assert!(failed.is_err_and(|e| e.to_string() == "chain unavailable"));
        assert_eq!(signer.1.get(), 1);
        Ok(())
    }

    fn response(probe: &HeadProbe, control: &SigningKey) -> Result<Value> {
        let head = Head {
            query: probe.query.clone(),
            state: [6; 32],
            capability: [7; 32],
            phase: Phase::Accepted,
            revision: 8,
            checkpoint_sequence: 9,
        };
        Ok(serde_json::json!({"signature":head.sign(control)?.to_vec(),"head":head}))
    }
    #[test]
    fn head_probe_rejects_saved_challenge_substitution_and_expiry() -> Result<()> {
        let (context, key, control) = fixture()?;
        let control_public = control.verifying_key().to_bytes().into();
        let first = HeadProbe::new(&context, &key)?;
        let old = response(&first, &control)?;
        let next = HeadProbe::new(&context, &key)?;
        assert!(
            next.verify(
                old.clone(),
                &control_public,
                &[6; 32],
                &[7; 32],
                Phase::Accepted
            )
            .is_err()
        );
        let valid = first.verify(old, &control_public, &[6; 32], &[7; 32], Phase::Accepted)?;
        valid.require_fresh()?;
        let mut expired = HeadProbe::new(&context, &key)?;
        let reply = response(&expired, &control)?;
        expired.deadline = Instant::now();
        assert!(
            expired
                .verify(reply, &control_public, &[6; 32], &[7; 32], Phase::Accepted)
                .is_err()
        );
        for (state, cap, phase) in [
            ([8; 32], [7; 32], Phase::Accepted),
            ([6; 32], [8; 32], Phase::Accepted),
            ([6; 32], [7; 32], Phase::Issued),
        ] {
            let probe = HeadProbe::new(&context, &key)?;
            let reply = response(&probe, &control)?;
            assert!(
                probe
                    .verify(reply, &control_public, &state, &cap, phase)
                    .is_err()
            );
        }
        Ok(())
    }
}
