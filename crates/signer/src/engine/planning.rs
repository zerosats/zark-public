//! Authorization checks and proof statements; no persisted state is mutated here.
use super::{
    ClaimBinding, Coin, Command, DepositBinding, Engine, HandoverBinding, IssuanceBinding,
    LineageBinding, LineageHandoverBinding, Phase, PredecessorKind, ProofSpec, Relation, Request,
    Result, Scalar, ServerShareOpening, delta_commitment, draft_access_commitment, ensure,
    exit_protocol, nonzero, origin_previous_capability, origin_refresh_commitment, point,
    policy_commitment, recipient, refresh_commitment, scalar, sender,
};
use anyhow::Context;

impl Engine {
    pub(super) fn lineage(&self, coin: &Coin) -> LineageBinding {
        LineageBinding {
            deployment: coin.deployment,
            coin: coin.coin,
            funding: coin.funding,
            state: coin.state,
            policy: policy_commitment(self.policy.schedule).expect("validated schedule"),
            origin_key: self.policy.origin_key,
            role_hashes: self.policy.role_hashes,
        }
    }
    pub(super) fn plan(&self, coin: &Coin, request: &Request) -> Result<Option<ProofSpec>> {
        coin.validate(&self.policy)?;
        ensure!(coin.phase != Phase::Terminal, "coin is terminal");
        ensure!(request.context.coin == coin.coin, "coin context mismatch");
        let spec = match &request.command {
            Command::BootstrapPrepare { .. } | Command::BootstrapFreeze { .. } => {
                return self.bootstrap_plan(coin, request);
            }
            Command::Reserve {
                owner_authorization,
            }
            | Command::BatchReserve {
                owner_authorization,
                ..
            } => {
                ensure!(
                    coin.phase == Phase::Accepted,
                    "coin is not available for reservation"
                );
                ensure!(
                    request.context.previous_state == coin.state,
                    "reservation is not for current state"
                );
                ensure!(
                    request.context.recipient_claim
                        != exit_protocol::intent(
                            &coin.deployment,
                            &coin.coin,
                            &request.context.operation
                        )?,
                    "exit context requires the exit command"
                );
                ensure!(
                    matches!(request.command, Command::BatchReserve { .. })
                        == matches!(
                            request.context.scope,
                            zark_protocol::handoff::OperationScope::Batch { .. }
                        ),
                    "reservation scope differs from command"
                );
                owner_authorization.verify_reservation(&request.context, &coin.capability)?;
                return Ok(None);
            }
            Command::ExitPrepare {
                funding,
                server_share,
                capability,
                exit,
                blinding,
                owner_authorization,
                ..
            } => {
                ensure!(
                    coin.phase == Phase::Accepted,
                    "coin is not available for exit"
                );
                exit_protocol::validate_context(&request.context)?;
                nonzero(*exit)?;
                nonzero(*blinding)?;
                let sc = ServerShareOpening {
                    deployment: coin.deployment,
                    coin: coin.coin,
                    server: point(coin.server_secret)?.try_into().expect("point length"),
                    salt: coin.server_salt,
                }
                .commitment()?;
                ensure!(
                    request.context.previous_state == coin.state
                        && *funding == coin.funding
                        && *capability == coin.capability
                        && *server_share == sc,
                    "exit preparation differs from current state"
                );
                ensure!(
                    *capability != exit_protocol::terminal_capability(&request.context)?,
                    "exit capability collision"
                );
                owner_authorization.verify_exit(
                    &request.context,
                    &coin.capability,
                    funding,
                    server_share,
                    exit,
                    blinding,
                )?;
                return Ok(None);
            }
            Command::ExitIssue {
                statement,
                predecessor,
                ..
            } => {
                ensure!(
                    *predecessor == coin.owner_kind,
                    "exit predecessor kind mismatch"
                );
                ensure!(
                    coin.phase == Phase::ExitPrepared,
                    "exit issuance is out of phase"
                );
                let e = coin.exit.as_ref().context("frozen exit")?;
                ensure!(
                    e.context == request.context,
                    "exit owner session or intent mismatch"
                );
                let outer = IssuanceBinding::decode(statement)?;
                let s = &outer.signing;
                self.policy.require(
                    &s.context.deployment,
                    &outer.policy,
                    &outer.origin_key,
                    &outer.role_hashes,
                )?;
                let server: [u8; 64] = e
                    .server_point
                    .as_slice()
                    .try_into()
                    .expect("validated exit point");
                ensure!(
                    s.context == e.context
                        && s.funding == e.funding
                        && s.previous_capability == e.capability
                        && s.next_capability == exit_protocol::terminal_capability(&e.context)?
                        && s.recovery == e.exit
                        && s.nonce_commitment == e.blinding
                        && s.draft_server == server
                        && s.server_nonce.as_slice() == e.nonce_point
                        && s.refresh_commitment
                            == exit_protocol::share_commitment(&e.context, &e.funding, &server)?,
                    "exit issuance differs from frozen preparation"
                );
                ProofSpec {
                    relation: match predecessor {
                        PredecessorKind::Origin => Relation::ExitFromOrigin,
                        PredecessorKind::Transfer => Relation::ExitFromTransfer,
                    },
                    expected: outer.encode()?,
                }
            }
            Command::Handover {
                statement,
                predecessor,
                ..
            } => {
                ensure!(
                    *predecessor == coin.owner_kind,
                    "sender predecessor kind mismatch"
                );
                ensure!(
                    coin.phase == Phase::Reserved,
                    "sender handover is out of phase"
                );
                let p = coin.pending.as_ref().context("pending handover")?;
                sender(p, &request.context)?;
                let outer = LineageHandoverBinding::decode(statement)?;
                let h = &outer.handover;
                self.policy.require(
                    &h.intent.deployment,
                    &h.policy,
                    &outer.origin_key,
                    &outer.role_hashes,
                )?;
                let sc = ServerShareOpening {
                    deployment: coin.deployment,
                    coin: coin.coin,
                    server: point(coin.server_secret)?.try_into().expect("point length"),
                    salt: coin.server_salt,
                }
                .commitment()?;
                ensure!(
                    h.intent == request.context.intent()
                        && h.intent.previous_state == coin.state
                        && h.funding == coin.funding
                        && h.previous_capability == coin.capability
                        && h.server_share == sc
                        && Some(h.mask) == p.cm,
                    "sender handover differs from reserved state"
                );
                ProofSpec {
                    relation: match predecessor {
                        PredecessorKind::Origin => Relation::SenderFromOrigin,
                        PredecessorKind::Transfer => Relation::SenderFromTransfer,
                    },
                    expected: outer.encode()?,
                }
            }
            Command::ProposeRecipient {
                statement,
                delta,
                delta_salt,
                token,
                ..
            } => {
                ensure!(
                    coin.phase == Phase::Handover,
                    "provisional recipient admission is unavailable"
                );
                let p = coin.pending.as_ref().context("pending claim")?;
                let h = HandoverBinding::decode(p.handover.as_ref().context("sender handover")?)?;
                ensure!(
                    draft_access_commitment(&h.intent, token)? == h.draft_access,
                    "invalid provisional admission token"
                );
                let c = ClaimBinding::decode(statement)?;
                ensure!(
                    c.context == request.context && c.context.intent() == h.intent,
                    "claim context differs from frozen handover"
                );
                ensure!(
                    c.mask == h.mask
                        && c.masked_share == h.masked_share
                        && c.bridge == h.bridge
                        && c.next_capability != coin.capability,
                    "claim commitments differ from handover"
                );
                ensure!(
                    c.delta == delta_commitment(&request.context, delta, delta_salt)?,
                    "delta opening mismatch"
                );
                let new = scalar(&coin.server_secret)? + scalar(delta)?
                    - scalar(&p.mask.context("reserved mask")?)?;
                ensure!(new != Scalar::ZERO, "zero draft signer share");
                return Ok(None);
            }
            Command::Prepare { recovery, blinding } => {
                ensure!(
                    matches!(coin.phase, Phase::Origin | Phase::RecipientProposed),
                    "recovery preparation is out of phase"
                );
                let p = coin.pending.as_ref().context("pending preparation")?;
                recipient(p, &request.context)?;
                nonzero(*recovery)?;
                nonzero(*blinding)?;
                return Ok(None);
            }
            Command::Issue { statement, .. }
            | Command::BatchReady { statement, .. }
            | Command::IssueDeposit { statement, .. } => {
                ensure!(
                    matches!(coin.phase, Phase::OriginPrepared | Phase::Prepared),
                    "recovery issuance is out of phase"
                );
                let p = coin.pending.as_ref().context("pending issuance")?;
                recipient(p, &request.context)?;
                ensure!(
                    p.origin == matches!(request.command, Command::IssueDeposit { .. }),
                    "origin requires combined deposit authorization"
                );
                if matches!(request.command, Command::Issue { .. }) {
                    ensure!(p.batch.is_none(), "batch member requires atomic readiness");
                } else if matches!(request.command, Command::BatchReady { .. }) {
                    ensure!(
                        p.batch.is_some() && !p.origin,
                        "batch readiness requires a transfer member"
                    );
                }
                let deposit = if p.origin {
                    Some(DepositBinding::decode(statement)?)
                } else {
                    None
                };
                if let Some(deposit) = &deposit {
                    let bootstrap = coin
                        .bootstrap
                        .as_ref()
                        .context("deposit bootstrap missing")?;
                    bootstrap.matches(&deposit.bootstrap)?;
                    ensure!(
                        bootstrap.binding_bytes()? == deposit.bootstrap.encode()?,
                        "deposit activation differs from frozen binding"
                    );
                }
                let outer = if let Some(deposit) = deposit {
                    deposit.authorization
                } else {
                    IssuanceBinding::decode(statement)?
                };
                let s = &outer.signing;
                self.policy.require(
                    &s.context.deployment,
                    &outer.policy,
                    &outer.origin_key,
                    &outer.role_hashes,
                )?;
                let draft = if p.origin {
                    coin.server_secret
                } else {
                    p.draft_secret.context("draft share")?
                };
                let draft_point: [u8; 64] = point(draft)?.try_into().expect("point length");
                let (previous, next, refresh) = if p.origin {
                    (
                        origin_previous_capability(&coin.deployment, &coin.coin)?,
                        coin.capability,
                        origin_refresh_commitment(&request.context, &coin.funding, &draft_point)?,
                    )
                } else {
                    let h = HandoverBinding::decode(p.handover.as_ref().context("handover")?)?;
                    let c = ClaimBinding::decode(p.claim.as_ref().context("claim")?)?;
                    (
                        coin.capability,
                        c.next_capability,
                        refresh_commitment(
                            &request.context,
                            &h.mask,
                            &h.masked_share,
                            &h.bridge,
                            &c.delta,
                            &draft_point,
                        )?,
                    )
                };
                ensure!(
                    s.context == request.context
                        && s.funding == coin.funding
                        && s.refresh_commitment == refresh
                        && s.previous_capability == previous
                        && s.next_capability == next
                        && Some(s.recovery) == p.recovery
                        && Some(s.nonce_commitment) == p.blinding
                        && s.draft_server == draft_point
                        && Some(s.server_nonce.to_vec()) == p.nonce_point,
                    "signing request differs from frozen preparation"
                );
                ProofSpec {
                    relation: if p.origin {
                        Relation::DepositAuthorization
                    } else {
                        Relation::ReceiverAuthorization
                    },
                    expected: if p.origin {
                        statement.clone()
                    } else {
                        outer.encode()?
                    },
                }
            }
            Command::AcceptOrigin {
                state,
                issuance_identity,
            } => {
                ensure!(
                    coin.phase == Phase::OriginIssued,
                    "origin acceptance is out of phase"
                );
                let p = coin.pending.as_ref().context("issued receipt")?;
                recipient(p, &request.context)?;
                ensure!(p.origin, "transfer requires issued-record acknowledgement");
                ensure!(
                    *state == coin.state
                        && p.issued_origin
                            .as_ref()
                            .context("issued origin seal")?
                            .identity()?
                            == *issuance_identity,
                    "origin acknowledgement differs from issued deposit"
                );
                return Ok(None);
            }
            Command::AcknowledgeTransfer {
                state,
                issuance_identity,
            } => {
                ensure!(
                    coin.phase == Phase::Issued,
                    "transfer acknowledgement is out of phase"
                );
                let p = coin.pending.as_ref().context("issued transfer")?;
                ensure!(!p.origin, "origin requires deposit acknowledgement");
                recipient(p, &request.context)?;
                let issued = p
                    .issued_transfer
                    .as_ref()
                    .context("missing issued transfer seal")?;
                ensure!(
                    *state == coin.state && *issuance_identity == issued.identity()?,
                    "acknowledgement differs from issued transfer"
                );
                return Ok(None);
            }
            _ => anyhow::bail!("read-only request reached mutation path"),
        };
        Ok(Some(spec))
    }
}
