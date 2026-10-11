//! Read-only responses and exact issued-response retrieval for authenticated sessions.
use super::{
    Checkpoint, Coin, Command, Engine, Head, HeadPhase, Phase, Purpose, Request, Result, Store,
    Value, ensure, exit_protocol, json,
};
use anyhow::Context;

impl Engine {
    pub(super) fn read_response(
        &self,
        store: &Store,
        coin: &Coin,
        revision: u64,
        floor: &Checkpoint,
        request: &Request,
    ) -> Result<Option<Value>> {
        match &request.command {
            Command::RetrieveIssued { binding_digest } => {
                let value = store
                    .response_for(Purpose::DepositIssuance, &request.context)?
                    .or(store.response_for(Purpose::RecoveryIssuance, &request.context)?)
                    .or(store.response_for(Purpose::BatchReadiness, &request.context)?)
                    .context("no issued response for this recipient session")?;
                ensure!(
                    value["binding_digest"] == json!(binding_digest),
                    "issued response binding mismatch"
                );
                Ok(Some(value))
            }
            Command::RetrieveExit { binding_digest } => {
                exit_protocol::validate_context(&request.context)?;
                let value = store
                    .response_for(Purpose::ExitIssuance, &request.context)?
                    .context("no issued exit for this owner session")?;
                ensure!(
                    value["binding_digest"] == json!(binding_digest),
                    "exit response binding mismatch"
                );
                Ok(Some(value))
            }
            Command::RetrieveBootstrap { binding_digest } => {
                zark_protocol::bootstrap::validate_context(&request.context)?;
                let response = store
                    .response_for(Purpose::DepositIssuance, &request.context)?
                    .context("bootstrap activation not released for this session")?;
                ensure!(
                    response["activation_binding_digest"] == json!(binding_digest),
                    "bootstrap response binding mismatch"
                );
                Ok(Some(response))
            }
            Command::CompleteSender {} => {
                ensure!(
                    store
                        .response_for(Purpose::SenderHandover, &request.context)?
                        .is_some(),
                    "unknown sender handover session"
                );
                Ok(Some(
                    json!({"completed":store.operation_accepted(&request.context.coin,&request.context.operation)?}),
                ))
            }
            Command::Head { query } => {
                let known = coin.current_session == request.context
                    || coin
                        .exit
                        .as_ref()
                        .is_some_and(|e| e.context == request.context)
                    || coin.pending.as_ref().is_some_and(|p| {
                        p.sender.as_ref() == Some(&request.context)
                            || p.recipient.as_ref() == Some(&request.context)
                    });
                ensure!(known, "head session is not a current participant");
                ensure!(
                    query.deployment == coin.deployment
                        && query.coin == coin.coin
                        && query.session_auth == request.context.session_auth,
                    "head query context mismatch"
                );
                let phase = match coin.phase {
                    Phase::Reserved | Phase::Handover => HeadPhase::Reserved,
                    Phase::BootstrapAllocated
                    | Phase::BootstrapPrepared
                    | Phase::Origin
                    | Phase::OriginPrepared
                    | Phase::RecipientProposed
                    | Phase::Prepared
                    | Phase::ExitPrepared => HeadPhase::Draft,
                    Phase::OriginIssued | Phase::Issued => HeadPhase::Issued,
                    Phase::Accepted => HeadPhase::Accepted,
                    Phase::Terminal => HeadPhase::Terminal,
                };
                let head = Head {
                    query: query.clone(),
                    state: coin.state,
                    capability: coin.capability,
                    phase,
                    revision,
                    checkpoint_sequence: floor.sequence,
                };
                let signature = head.sign(&self.control)?;
                Ok(Some(json!({"head":head,"signature":signature.to_vec()})))
            }
            _ => Ok(None),
        }
    }
}
