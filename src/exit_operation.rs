//! Cooperative withdrawal journal. Signing release is terminal even if a later
//! Bitcoin observation fails; retries retrieve the same completed transaction.
use crate::{
    chain::ChainConfig,
    exit::{ExitDraft, ExitParameters},
    freshness::{HeadProbe, SignerClient},
    types::Input,
};
use anyhow::{Result, ensure};
use bitcoin::{Transaction, consensus::serialize};
use k256::schnorr::SigningKey;
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use zark_protocol::{
    certificate::{OwnerCertificate, PredecessorKind},
    exit,
    handoff::{Digest, StateOpening, TransferContext},
    head::Phase,
    lineage::{IssuanceBinding, LineageBinding, LineagePolicy},
    local::ProcessLock,
    proof::{PinnedVerifier, Relation},
    random_scalar, random32,
    wire::{Command, Request},
};
mod storage;
mod witness;
use storage::{Record, create_directory, decode_any, lock};

pub(crate) struct ExitOwner {
    pub head_context: TransferContext,
    pub head_session: Digest,
    pub backing: Input,
    pub activation_input: Input,
    pub activation: Transaction,
    pub server: [u8; 64],
    pub state: StateOpening,
    pub server_salt: Digest,
    pub certificate: OwnerCertificate,
    pub start_revision: u64,
}

pub struct ExitOperation {
    directory: PathBuf,
    record: Record,
    policy: LineagePolicy,
    _lock: ProcessLock,
}
impl ExitOperation {
    #[allow(clippy::too_many_arguments)] // Keep explicit owner, destination and proof dependencies.
    pub(crate) fn create(
        directory: &Path,
        owner: ExitOwner,
        user: &Digest,
        capability: &Digest,
        destination: Digest,
        fee: u64,
        policy: &LineagePolicy,
        verifier: &PinnedVerifier,
        scratch: &Path,
    ) -> Result<Self> {
        let certificate = owner.certificate.verify(verifier, scratch)?;
        policy.require(
            &certificate.deployment,
            &certificate.policy,
            &certificate.origin_key,
            &certificate.role_hashes,
        )?;
        ensure!(
            owner.state.commitment()? == certificate.state
                && owner.state.funding == certificate.funding,
            "exit owner certificate mismatch"
        );
        let session = SigningKey::from_bytes(&random_scalar().to_bytes())?;
        let operation = random32();
        let context = TransferContext {
            deployment: policy.deployment,
            coin: certificate.coin,
            previous_state: certificate.state,
            operation,
            recipient_claim: exit::intent(&policy.deployment, &certificate.coin, &operation)?,
            session_auth: session.verifying_key().to_bytes().into(),
            start_revision: owner.start_revision,
            scope: zark_protocol::handoff::OperationScope::Single,
        };
        let record = Record {
            version: 3,
            head_context: owner.head_context,
            head_session: owner.head_session,
            context: context.clone(),
            session: session.to_bytes().into(),
            backing: owner.backing.clone(),
            activation_input: owner.activation_input.clone(),
            activation: hex::encode(serialize(&owner.activation)),
            certificate: hex::encode(&*owner.certificate.encode_private()?),
            predecessor: owner.certificate.kind(),
            capability: owner.state.capability,
            server_share: owner.state.server_share,
            destination,
            fee,
            prepare: None,
            issue: None,
            terminal: false,
        };
        create_directory(directory)?;
        let lock = lock(directory)?;
        ExitDraft::create(
            &directory.join("draft"),
            ExitParameters {
                context,
                backing: owner.backing,
                activation_input: owner.activation_input,
                activation: owner.activation,
                server: owner.server,
                current_recovery: owner.state.recovery,
                current_issuance: owner.state.issuance,
                server_salt: owner.server_salt,
                schedule: policy.schedule,
                destination,
                fee,
            },
            user,
            capability,
        )?;
        let result = Self {
            directory: directory.into(),
            record,
            policy: policy.clone(),
            _lock: lock,
        };
        result.verify(verifier, scratch)?;
        result.persist()?;
        Ok(result)
    }
    pub fn context(&self) -> &TransferContext {
        &self.record.context
    }
    pub fn is_terminal(&self) -> Result<bool> {
        self.validate()?;
        Ok(self.record.terminal)
    }
    pub fn has_issuance_request(&self) -> Result<bool> {
        self.validate()?;
        Ok(self.record.issue.is_some())
    }
    pub fn is_prepared(&self) -> Result<bool> {
        self.validate()?;
        Ok(self.draft()?.signing_binding().is_ok())
    }
    pub(crate) fn require_origin(
        &self,
        state: &Digest,
        destination: &Digest,
        fee: u64,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            self.record.context.previous_state == *state
                && self.record.destination == *destination
                && self.record.fee == fee,
            "saved exit belongs to another owner or destination"
        );
        Ok(())
    }
    fn draft(&self) -> Result<ExitDraft> {
        ExitDraft::open(&self.directory.join("draft"), &self.record.context)
    }
    fn certificate(&self) -> Result<OwnerCertificate> {
        OwnerCertificate::decode_private(&decode_any(&self.record.certificate)?)
    }
    fn current(&self) -> Result<LineageBinding> {
        self.certificate()?.lineage_binding()
    }
    pub fn proof_role(&self) -> Result<Relation> {
        self.validate()?;
        Ok(match self.record.predecessor {
            PredecessorKind::Origin => Relation::ExitFromOrigin,
            PredecessorKind::Transfer => Relation::ExitFromTransfer,
        })
    }
    fn role(&self) -> Relation {
        match self.record.predecessor {
            PredecessorKind::Origin => Relation::DepositAuthorization,
            PredecessorKind::Transfer => Relation::ReceiverAuthorization,
        }
    }
    fn verify(&self, verifier: &PinnedVerifier, scratch: &Path) -> Result<()> {
        self.validate()?;
        self.certificate()?.verify(verifier, scratch)?;
        Ok(())
    }
    fn chain(&self, chain: &ChainConfig) -> Result<()> {
        ensure!(
            chain.deployment.id()? == self.policy.deployment
                && chain.deployment.schedule() == self.policy.schedule,
            "exit chain deployment"
        );
        let observation = chain.observe(&self.record.backing, &self.record.activation_input)?;
        ensure!(
            observation.activation_height.is_none() && !observation.activation_in_mempool,
            "deposit already spent by activation; use explicit unilateral recovery"
        );
        Ok(())
    }
    fn head_probe(&self, phase: Phase) -> Result<HeadProbe> {
        // Before ExitPrepare succeeds only the accepted owner's session may
        // query its head. The new exit session becomes a participant at prepare.
        let (context, session) = if phase == Phase::Accepted {
            (&self.record.head_context, &self.record.head_session)
        } else {
            (&self.record.context, &self.record.session)
        };
        let key = SigningKey::from_bytes(session)?;
        HeadProbe::new(context, &key)
    }
    fn fresh(&self, phase: Phase, client: &dyn SignerClient, chain: &ChainConfig) -> Result<()> {
        let probe = self.head_probe(phase)?;
        let response = client.request(probe.request())?;
        let head = probe.verify(
            response,
            &zark_protocol::hex32(&chain.deployment.control_key)?,
            &self.record.context.previous_state,
            &self.record.capability,
            phase,
        )?;
        if phase == Phase::Accepted {
            ensure!(
                head.revision() == self.record.context.start_revision,
                "stale exit owner revision"
            );
        }
        self.chain(chain)?;
        head.require_fresh()
    }
    fn freeze(&mut self, command: Command, prepare: bool) -> Result<Request> {
        let saved = if prepare {
            &self.record.prepare
        } else {
            &self.record.issue
        };
        if let Some(saved) = saved {
            let request = Request::decode(&decode_any(saved)?)?;
            ensure!(
                *request.command.body()? == *command.body()?,
                "exit request already frozen"
            );
            return Ok(request);
        }
        let request = Request::sign(
            self.record.context.clone(),
            command,
            &SigningKey::from_bytes(&self.record.session)?,
        )?;
        if prepare {
            self.record.prepare = Some(hex::encode(&*request.encode()?));
        } else {
            self.record.issue = Some(hex::encode(&*request.encode()?));
        }
        self.persist()?;
        Ok(request)
    }
    fn freeze_preparation(&mut self) -> Result<Request> {
        if let Some(saved) = &self.record.prepare {
            return Request::decode(&decode_any(saved)?);
        }
        let command = {
            let draft = self.draft()?;
            let (funding, exit, blinding) = draft.commitments()?;
            Command::ExitPrepare {
                funding,
                server_share: self.record.server_share,
                capability: self.record.capability,
                exit,
                blinding,
                owner_authorization: draft.owner_authorization()?,
            }
        };
        // Persist reopens and validates the draft. Release its exclusive lock
        // before entering freeze; argument temporaries live through the call.
        self.freeze(command, true)
    }
    pub fn prepare(
        &mut self,
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
        chain: &ChainConfig,
    ) -> Result<()> {
        self.verify(verifier, scratch)?;
        ensure!(!self.record.terminal, "exit already released");
        if self.record.prepare.is_none() {
            self.fresh(Phase::Accepted, client, chain)?;
        }
        let request = self.freeze_preparation()?;
        self.chain(chain)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Nonce {
            server_nonce: Vec<u8>,
        }
        let response: Nonce = serde_json::from_value(client.request(&request)?)
            .map_err(|_| anyhow::anyhow!("invalid exit nonce response"))?;
        self.draft()?.bind_nonce(
            &self.record.context,
            response
                .server_nonce
                .try_into()
                .map_err(|_| anyhow::anyhow!("exit nonce size"))?,
        )?;
        Ok(())
    }
    pub fn binding(&self) -> Result<IssuanceBinding> {
        Ok(IssuanceBinding {
            signing: self.draft()?.signing_binding()?,
            policy: self.current()?.policy,
            origin_key: self.policy.origin_key,
            role_hashes: self.policy.role_hashes,
        })
    }
    pub fn issue(
        &mut self,
        proof: &[u8],
        verifier: &PinnedVerifier,
        scratch: &Path,
        client: &dyn SignerClient,
        chain: &ChainConfig,
    ) -> Result<Transaction> {
        self.verify(verifier, scratch)?;
        let binding = self.binding()?;
        verifier.cooperative_exit(self.record.predecessor, &binding, proof, scratch)?;
        if self.record.terminal {
            return self.draft()?.completed_transaction();
        }
        let request = self.freeze(
            Command::ExitIssue {
                predecessor: self.record.predecessor,
                statement: binding.encode()?,
                proof: proof.to_vec(),
            },
            false,
        )?;
        // If release already happened but its response was lost, use the bound
        // retrieval path. Never require an old Accepted/Draft head to recover it.
        self.fresh(Phase::Draft, client, chain)?;
        self.finish_response(client.request(&request)?)
    }
    pub fn retrieve(&mut self, client: &dyn SignerClient) -> Result<Transaction> {
        self.validate()?;
        ensure!(self.record.issue.is_some(), "no exit issuance to retrieve");
        // The inner transaction is durably written before the outer terminal
        // marker. Recover that exact completed signature locally after a crash;
        // no signer or prover availability is required to keep the exit usable.
        let completed = {
            let draft = self.draft()?;
            draft.completed_transaction()
        };
        if let Ok(transaction) = completed {
            self.record.terminal = true;
            self.persist()?;
            return Ok(transaction);
        }
        let request = Request::sign(
            self.record.context.clone(),
            Command::RetrieveExit {
                binding_digest: self.binding()?.signing.digest()?,
            },
            &SigningKey::from_bytes(&self.record.session)?,
        )?;
        self.finish_response(client.request(&request)?)
    }
    fn finish_response(&mut self, value: Value) -> Result<Transaction> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Released {
            terminal: bool,
            partial: Digest,
            binding_digest: Digest,
            state: Digest,
            capability: Digest,
        }
        let response: Released = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("invalid exit release response"))?;
        let binding = self.binding()?.signing;
        ensure!(
            response.terminal
                && response.binding_digest == binding.digest()?
                && response.state == self.record.context.previous_state
                && response.capability == exit::terminal_capability(&self.record.context)?,
            "exit release response binding mismatch"
        );
        let tx =
            self.draft()?
                .finish(&self.record.context, binding.server_nonce, response.partial)?;
        self.record.terminal = true;
        self.persist()?;
        Ok(tx)
    }
    pub fn publish(&self, chain: &ChainConfig) -> Result<Value> {
        self.validate()?;
        ensure!(self.record.terminal, "exit signature has not been released");
        ensure!(
            chain.deployment.id()? == self.policy.deployment,
            "exit chain deployment"
        );
        let exit = self.draft()?.completed_transaction()?;
        chain.publish(&exit)?;
        let confirmations = chain.confirmations(&exit)?;
        Ok(
            serde_json::json!({"transaction_id":exit.compute_txid().to_string(),"amount_received_sat":self.record.activation_input.amount-self.record.fee,
            "deposit_amount_sat":self.record.activation_input.amount,"recovery_amount_sat":self.record.backing.amount,"activation_broadcast":false,
            "fee_sat":self.record.fee,"confirmations":confirmations,"required_confirmations":chain.minimum_confirmations,
            "waiting":confirmations<chain.minimum_confirmations as u64,"signature_status":"released_terminal"}),
        )
    }
}

#[cfg(test)]
#[path = "exit_operation_tests.rs"]
mod tests;
