//! Apply an authorized mutation; the engine commits and checkpoints before releasing its response.
use super::{
    Coin, Command, DepositBinding, Digest, Engine, Exit, IssuanceBinding, IssuedOriginRecord,
    IssuedTransferRecord, LineageHandoverBinding, Pending, Phase, PredecessorKind, Request, Result,
    ServerShareOpening, StateOpening, Value, ensure, issuance_commitment, json, mask_commitment,
    nonzero_random, point, policy_commitment, random_scalar, random32, scalar,
};
use anyhow::Context;
use zeroize::Zeroize;

impl Engine {
    pub(super) fn apply(&self, mut coin: Coin, request: &Request) -> Result<(Coin, Value, bool)> {
        let mut purge = false;
        let response = match &request.command {
            Command::BootstrapPrepare { .. } | Command::BootstrapFreeze { .. } => {
                self.bootstrap_apply(&mut coin, request)?
            }
            Command::ExitPrepare {
                funding,
                server_share,
                capability,
                exit,
                blinding,
                ..
            } => {
                let secret: Digest = random_scalar().to_bytes().into();
                let nonce_point = point(secret)?;
                coin.exit = Some(Exit {
                    context: request.context.clone(),
                    funding: *funding,
                    capability: *capability,
                    server_share: *server_share,
                    server_point: point(coin.server_secret)?,
                    exit: *exit,
                    blinding: *blinding,
                    nonce_secret: Some(secret),
                    nonce_point: nonce_point.clone(),
                    signing: None,
                    partial: None,
                });
                coin.phase = Phase::ExitPrepared;
                json!({"server_nonce":nonce_point})
            }
            Command::ExitIssue { statement, .. } => {
                let s = IssuanceBinding::decode(statement)?.signing;
                let e = coin.exit.as_mut().context("frozen exit")?;
                let mut nonce = e.nonce_secret.take().context("frozen exit nonce")?;
                let partial: Digest = (scalar(&nonce)?
                    + scalar(&s.blinded_challenge)? * scalar(&coin.server_secret)?)
                .to_bytes()
                .into();
                nonce.zeroize();
                coin.server_secret.zeroize();
                e.signing = Some(s.encode()?);
                e.partial = Some(partial);
                coin.capability = s.next_capability;
                coin.current_session = request.context.clone();
                coin.phase = Phase::Terminal;
                json!({"terminal":true,"partial":partial,"binding_digest":s.digest()?,"state":coin.state,"capability":coin.capability})
            }
            Command::Reserve { .. } | Command::BatchReserve { .. } => {
                let mask: Digest = random_scalar().to_bytes().into();
                let salt = nonzero_random();
                let cm = mask_commitment(&request.context.intent(), &mask, &salt)?;
                let mut p = Pending::new(false);
                if let Command::BatchReserve { manifest, .. } = &request.command {
                    p.batch = Some(manifest.id);
                }
                p.sender = Some(request.context.clone());
                p.mask = Some(mask);
                p.mask_salt = Some(salt);
                p.cm = Some(cm);
                coin.pending = Some(p);
                coin.phase = Phase::Reserved;
                json!({"mask":mask,"mask_salt":salt,"mask_commitment":cm})
            }
            Command::Handover { statement, .. } => {
                let h = LineageHandoverBinding::decode(statement)?.handover;
                coin.pending.as_mut().context("pending")?.handover = Some(h.encode()?);
                coin.phase = Phase::Handover;
                json!({"authorized":true})
            }
            Command::ProposeRecipient {
                statement, delta, ..
            } => {
                let p = coin.pending.as_mut().context("pending")?;
                let draft = scalar(&coin.server_secret)? + scalar(delta)?
                    - scalar(&p.mask.context("mask")?)?;
                let secret: Digest = draft.to_bytes().into();
                let salt = nonzero_random();
                p.claim = Some(statement.clone());
                p.recipient = Some(request.context.clone());
                p.draft_secret = Some(secret);
                p.draft_salt = Some(salt);
                if let Some(m) = &mut p.mask {
                    m.zeroize();
                }
                if let Some(s) = &mut p.mask_salt {
                    s.zeroize();
                }
                p.mask = None;
                p.mask_salt = None;
                coin.phase = Phase::RecipientProposed;
                purge = true;
                json!({"draft_server":point(secret)?,"server_salt":salt})
            }
            Command::Prepare { recovery, blinding } => {
                let p = coin.pending.as_mut().context("pending")?;
                let nonce: Digest = random_scalar().to_bytes().into();
                let public = point(nonce)?;
                p.recovery = Some(*recovery);
                p.blinding = Some(*blinding);
                p.nonce_secret = Some(nonce);
                p.nonce_point = Some(public.clone());
                coin.phase = if p.origin {
                    Phase::OriginPrepared
                } else {
                    Phase::Prepared
                };
                json!({"server_nonce":public,"server_salt":if p.origin{coin.server_salt}else{p.draft_salt.context("draft salt")?},
                    "draft_server":point(if p.origin{coin.server_secret}else{p.draft_secret.context("draft")?})?})
            }
            Command::Issue { statement, .. }
            | Command::BatchReady { statement, .. }
            | Command::IssueDeposit { statement, .. } => {
                let deposit = if matches!(request.command, Command::IssueDeposit { .. }) {
                    Some(DepositBinding::decode(statement)?)
                } else {
                    None
                };
                let authorization = if let Some(deposit) = &deposit {
                    IssuanceBinding::decode(&deposit.authorization.encode()?)?
                } else {
                    IssuanceBinding::decode(statement)?
                };
                let s = &authorization.signing;
                let p = coin.pending.as_mut().context("pending")?;
                let mut nonce = p.nonce_secret.take().context("frozen nonce")?;
                let new_secret = if p.origin {
                    coin.server_secret
                } else {
                    p.draft_secret.take().context("draft share")?
                };
                let partial: Digest = (scalar(&nonce)?
                    + scalar(&s.blinded_challenge)? * scalar(&new_secret)?)
                .to_bytes()
                .into();
                nonce.zeroize();
                let salt = if p.origin {
                    coin.server_salt
                } else {
                    p.draft_salt.context("frozen server salt")?
                };
                let server_commitment = ServerShareOpening {
                    deployment: coin.deployment,
                    coin: coin.coin,
                    server: s.draft_server,
                    salt,
                }
                .commitment()?;
                let state = StateOpening {
                    deployment: coin.deployment,
                    coin: coin.coin,
                    funding: coin.funding,
                    capability: s.next_capability,
                    recovery: s.recovery,
                    server_share: server_commitment,
                    policy: policy_commitment(self.policy.schedule)?,
                    issuance: issuance_commitment(&s.digest()?, &partial)?,
                }
                .commitment()?;
                coin.server_secret.zeroize();
                coin.server_secret = new_secret;
                coin.server_salt = salt;
                coin.state = state;
                coin.capability = s.next_capability;
                if !p.origin {
                    coin.owner_kind = PredecessorKind::Transfer;
                    p.issued_transfer = Some(IssuedTransferRecord::from_request(
                        request,
                        &authorization,
                        partial,
                        salt,
                        state,
                    )?);
                }
                coin.current_session = request.context.clone();
                coin.phase = if p.origin {
                    Phase::OriginIssued
                } else {
                    Phase::Issued
                };
                p.signing = Some(s.encode()?);
                p.partial = Some(partial);
                p.mask = None;
                p.mask_salt = None;
                p.draft_secret = None;
                purge = true;
                let mut response = json!({"issued":true,"partial":partial,"binding_digest":s.digest()?,"state":state,"capability":s.next_capability});
                if let Some(deposit) = deposit {
                    let activation = coin
                        .bootstrap
                        .as_mut()
                        .context("deposit bootstrap missing")?
                        .release(&coin.server_secret)?;
                    let activation_partial: Digest =
                        serde_json::from_value(activation["activation_partial"].clone())?;
                    let signature = self
                        .origin
                        .sign_raw(&self.lineage(&coin).origin_message()?, &random32())?
                        .to_bytes()
                        .to_vec();
                    let issued = IssuedOriginRecord::from_request(
                        request,
                        &deposit,
                        partial,
                        activation_partial,
                        salt,
                        state,
                        signature.clone(),
                    )?;
                    response["binding_digest"] = json!(deposit.digest()?);
                    response["activation_partial"] = json!(activation_partial);
                    response["activation_binding_digest"] =
                        activation["activation_binding_digest"].clone();
                    response["origin_signature"] = json!(signature);
                    response["issuance_identity"] = json!(issued.identity()?);
                    coin.pending
                        .as_mut()
                        .context("pending deposit")?
                        .issued_origin = Some(issued);
                }
                response
            }
            Command::AcceptOrigin { .. } => {
                let origin = coin.pending.as_ref().context("pending")?.origin;
                ensure!(origin, "transfer cannot use origin acknowledgement");
                let result = json!({"accepted":true,"state":coin.state});
                coin.pending = None;
                coin.phase = Phase::Accepted;
                result
            }
            Command::AcknowledgeTransfer {
                state,
                issuance_identity,
            } => {
                let pending = coin.pending.as_ref().context("issued transfer")?;
                ensure!(
                    !pending.origin && coin.phase == Phase::Issued,
                    "transfer acknowledgement cannot accept origin"
                );
                ensure!(
                    *state == coin.state
                        && pending
                            .issued_transfer
                            .as_ref()
                            .context("issued transfer seal")?
                            .identity()?
                            == *issuance_identity,
                    "acknowledgement differs from issued transfer"
                );
                coin.pending = None;
                coin.phase = Phase::Accepted;
                json!({"accepted":true,"state":coin.state})
            }
            _ => anyhow::bail!("invalid mutation"),
        };
        Ok((coin, response, purge))
    }
}
