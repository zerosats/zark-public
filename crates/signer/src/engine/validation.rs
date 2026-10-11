//! Validation of persisted lifecycle states before planning or mutation.
use super::{
    ClaimBinding, Coin, DEPOSIT_AUTHORIZATION, HandoverBinding, LineageBinding, LineagePolicy,
    Phase, PredecessorKind, ProjectivePoint, RECEIVER_AUTHORIZATION, Result, Scalar,
    ServerShareOpening, SigningBinding, StateOpening, ensure, exit_protocol, issuance_commitment,
    mask_commitment, nonzero, origin_previous_capability, origin_previous_state,
    origin_refresh_commitment, point, policy_commitment, refresh_commitment, scalar,
};
use anyhow::Context;

impl Coin {
    pub(super) fn validate_exit(&self) -> Result<()> {
        ensure!(self.pending.is_none(), "exit overlaps a transfer");
        let e = self.exit.as_ref().context("missing frozen exit")?;
        exit_protocol::validate_context(&e.context)?;
        self.current_session.encode()?;
        ensure!(
            e.context.deployment == self.deployment
                && e.context.coin == self.coin
                && e.context.previous_state == self.state
                && self.current_session.deployment == self.deployment
                && self.current_session.coin == self.coin
                && e.funding == self.funding,
            "frozen exit context mismatch"
        );
        for field in [e.capability, e.server_share, e.exit, e.blinding] {
            nonzero(field)?;
        }
        let server: [u8; 64] = e
            .server_point
            .as_slice()
            .try_into()
            .context("exit server point length")?;
        let server_point = zark_protocol::point(&server)?;
        let nonce_point = zark_protocol::point(&e.nonce_point)?;
        ensure!(e.nonce_point.len() == 64, "exit nonce length");
        let sc = ServerShareOpening {
            deployment: self.deployment,
            coin: self.coin,
            server,
            salt: self.server_salt,
        }
        .commitment()?;
        ensure!(
            sc == e.server_share,
            "frozen exit share commitment mismatch"
        );
        let terminal = exit_protocol::terminal_capability(&e.context)?;
        ensure!(e.capability != terminal, "exit capability did not change");
        if self.phase == Phase::ExitPrepared {
            ensure!(
                e.signing.is_none() && e.partial.is_none() && e.nonce_secret.is_some(),
                "prepared exit shape mismatch"
            );
            let nonce = e.nonce_secret.context("exit nonce")?;
            ensure!(
                scalar(&self.server_secret)? != Scalar::ZERO
                    && scalar(&nonce)? != Scalar::ZERO
                    && point(self.server_secret)? == e.server_point
                    && point(nonce)? == e.nonce_point
                    && self.capability == e.capability,
                "prepared exit secret mismatch"
            );
        } else {
            ensure!(
                self.phase == Phase::Terminal
                    && self.server_secret == [0; 32]
                    && e.nonce_secret.is_none()
                    && self.capability == terminal
                    && self.current_session == e.context,
                "terminal exit authority mismatch"
            );
            let s =
                SigningBinding::decode(e.signing.as_ref().context("terminal signing binding")?)?;
            let partial = e.partial.context("terminal partial")?;
            ensure!(
                s.context == e.context
                    && s.funding == e.funding
                    && s.previous_capability == e.capability
                    && s.next_capability == terminal
                    && s.recovery == e.exit
                    && s.nonce_commitment == e.blinding
                    && s.draft_server == server
                    && s.server_nonce.as_slice() == e.nonce_point
                    && s.refresh_commitment
                        == exit_protocol::share_commitment(&e.context, &e.funding, &server)?,
                "terminal signing binding mismatch"
            );
            ensure!(
                ProjectivePoint::GENERATOR * scalar(&partial)?
                    == nonce_point + server_point * scalar(&s.blinded_challenge)?,
                "terminal partial mismatch"
            );
        }
        Ok(())
    }
    pub(super) fn validate(&self, policy: &LineagePolicy) -> Result<()> {
        ensure!(
            self.deployment == policy.deployment,
            "coin deployment mismatch"
        );
        if let Some(bootstrap) = &self.bootstrap {
            bootstrap.validate(self)?;
        }
        if matches!(
            self.phase,
            Phase::BootstrapAllocated | Phase::BootstrapPrepared
        ) {
            ensure!(
                self.bootstrap.is_some() && self.exit.is_none(),
                "bootstrap lifecycle missing allocation"
            );
            nonzero(self.coin)?;
            nonzero(self.state)?;
            self.current_session.encode()?;
            return Ok(());
        }
        for field in [
            self.coin,
            self.funding,
            self.state,
            self.capability,
            self.server_salt,
        ] {
            nonzero(field)?;
        }
        if matches!(self.phase, Phase::ExitPrepared | Phase::Terminal) {
            return self.validate_exit();
        }
        ensure!(self.exit.is_none(), "non-exit phase retained exit record");
        ensure!(
            scalar(&self.server_secret)? != Scalar::ZERO,
            "zero stored server share"
        );
        self.current_session.encode()?;
        ensure!(
            self.current_session.deployment == self.deployment
                && self.current_session.coin == self.coin,
            "stored session context mismatch"
        );
        let stable = matches!(self.phase, Phase::Accepted | Phase::Terminal);
        ensure!(
            stable == self.pending.is_none(),
            "invalid pending lifecycle shape"
        );
        if let Some(p) = &self.pending {
            ensure!(
                p.origin
                    == matches!(
                        self.phase,
                        Phase::Origin | Phase::OriginPrepared | Phase::OriginIssued
                    ),
                "origin lifecycle mismatch"
            );
            ensure!(!p.origin || p.batch.is_none(), "origin cannot join a batch");
            ensure!(
                !p.origin || self.owner_kind == PredecessorKind::Origin,
                "origin predecessor kind mismatch"
            );
            if let Some(ctx) = &p.sender {
                ctx.encode()?;
                ensure!(
                    ctx.deployment == self.deployment && ctx.coin == self.coin,
                    "stored sender context"
                );
            }
            if let Some(ctx) = &p.recipient {
                ctx.encode()?;
                ensure!(
                    ctx.deployment == self.deployment && ctx.coin == self.coin,
                    "stored recipient context"
                );
            }
            if let Some(secret) = p.draft_secret {
                ensure!(scalar(&secret)? != Scalar::ZERO, "zero draft share");
            }
            if let Some(secret) = p.nonce_secret {
                ensure!(scalar(&secret)? != Scalar::ZERO, "zero stored nonce");
            }
            if let Some(mask) = p.mask {
                ensure!(scalar(&mask)? != Scalar::ZERO, "zero stored mask");
            }
            if let Some(raw) = &p.handover {
                HandoverBinding::decode(raw)?;
            }
            if let Some(raw) = &p.claim {
                ClaimBinding::decode(raw)?;
            }
            if let Some(raw) = &p.signing {
                SigningBinding::decode(raw)?;
            }
            let issued = matches!(self.phase, Phase::Issued | Phase::OriginIssued);
            ensure!(
                p.issued_transfer.is_some() == (issued && !p.origin),
                "issued transfer seal lifecycle mismatch"
            );
            ensure!(
                p.issued_origin.is_some() == (issued && p.origin),
                "issued origin seal lifecycle mismatch"
            );
            ensure!(
                issued == p.partial.is_some() && issued == p.signing.is_some(),
                "issued lifecycle mismatch"
            );
            if issued {
                ensure!(
                    p.mask.is_none() && p.draft_secret.is_none() && p.nonce_secret.is_none(),
                    "issued record retained signing secrets"
                );
            }
            let masked = matches!(self.phase, Phase::Reserved | Phase::Handover);
            let transferred = !p.origin;
            let handed = transferred && self.phase != Phase::Reserved;
            let claimed = matches!(
                self.phase,
                Phase::RecipientProposed | Phase::Prepared | Phase::Issued
            );
            let prepared = matches!(
                self.phase,
                Phase::OriginPrepared | Phase::Prepared | Phase::OriginIssued | Phase::Issued
            );
            ensure!(
                p.sender.is_some() == transferred && p.recipient.is_some() == (p.origin || claimed),
                "stored participant shape"
            );
            ensure!(
                p.cm.is_some() == transferred
                    && p.mask.is_some() == masked
                    && p.mask_salt.is_some() == masked,
                "stored mask shape"
            );
            ensure!(
                p.handover.is_some() == handed && p.claim.is_some() == claimed,
                "stored proof binding shape"
            );
            ensure!(
                p.draft_secret.is_some() == (claimed && !issued)
                    && p.draft_salt.is_some() == claimed,
                "stored draft shape"
            );
            ensure!(
                p.recovery.is_some() == prepared
                    && p.blinding.is_some() == prepared
                    && p.nonce_point.is_some() == prepared
                    && p.nonce_secret.is_some() == (prepared && !issued),
                "stored nonce shape"
            );
            for value in [p.cm, p.mask_salt, p.draft_salt, p.recovery, p.blinding]
                .into_iter()
                .flatten()
            {
                nonzero(value)?;
            }
            if let Some(ctx) = &p.sender {
                if !issued {
                    ensure!(
                        ctx.previous_state == self.state,
                        "reserved predecessor mismatch"
                    );
                }
                if let Some(m) = p.mask {
                    ensure!(
                        p.cm == Some(mask_commitment(
                            &ctx.intent(),
                            &m,
                            &p.mask_salt.context("mask salt")?
                        )?),
                        "stored mask commitment mismatch"
                    );
                }
            }
            if let Some(raw) = &p.handover {
                let h = HandoverBinding::decode(raw)?;
                ensure!(
                    h.intent == p.sender.as_ref().context("sender")?.intent()
                        && h.funding == self.funding
                        && Some(h.mask) == p.cm
                        && h.policy == policy_commitment(policy.schedule)?,
                    "stored handover mismatch"
                );
                if !issued {
                    ensure!(
                        h.previous_capability == self.capability
                            && h.server_share
                                == ServerShareOpening {
                                    deployment: self.deployment,
                                    coin: self.coin,
                                    server: point(self.server_secret)?
                                        .try_into()
                                        .expect("point length"),
                                    salt: self.server_salt
                                }
                                .commitment()?,
                        "stored predecessor share mismatch"
                    );
                }
                if let Some(raw) = &p.claim {
                    let c = ClaimBinding::decode(raw)?;
                    ensure!(
                        Some(&c.context) == p.recipient.as_ref()
                            && c.context.intent() == h.intent
                            && c.mask == h.mask
                            && c.masked_share == h.masked_share
                            && c.bridge == h.bridge,
                        "stored claim mismatch"
                    );
                }
            }
            if let Some(nonce) = &p.nonce_point {
                zark_protocol::point(nonce)?;
                if let Some(secret) = p.nonce_secret {
                    ensure!(*nonce == point(secret)?, "stored nonce point mismatch");
                }
            }
            if p.origin {
                ensure!(
                    p.recipient.as_ref() == Some(&self.current_session)
                        && self.current_session.previous_state
                            == origin_previous_state(&self.deployment, &self.coin)?,
                    "stored origin context mismatch"
                );
            }
            if issued {
                let s = SigningBinding::decode(p.signing.as_ref().context("signing")?)?;
                let partial = p.partial.context("partial")?;
                if let Some(record) = &p.issued_origin {
                    record.identity()?;
                    ensure!(
                        self.owner_kind == PredecessorKind::Origin
                            && record.deposit_role_hash
                                == policy.role_hashes[DEPOSIT_AUTHORIZATION]
                            && record.context == s.context
                            && record.signing_digest == s.digest()?
                            && record.partial == partial
                            && record.server_salt == self.server_salt
                            && record.state == self.state
                            && record.capability == self.capability
                            && Some(record.activation_partial)
                                == self
                                    .bootstrap
                                    .as_ref()
                                    .context("issued origin bootstrap")?
                                    .released_partial(),
                        "issued origin seal differs from durable state"
                    );
                    LineageBinding {
                        deployment: self.deployment,
                        coin: self.coin,
                        funding: self.funding,
                        state: self.state,
                        policy: policy_commitment(policy.schedule)?,
                        origin_key: policy.origin_key,
                        role_hashes: policy.role_hashes,
                    }
                    .verify_origin_attestation(&record.origin_signature.as_slice().try_into()?)?;
                }
                if let Some(record) = &p.issued_transfer {
                    record.identity()?;
                    ensure!(
                        self.owner_kind == PredecessorKind::Transfer
                            && record.receiver_role_hash
                                == policy.role_hashes[RECEIVER_AUTHORIZATION]
                            && record.context == s.context
                            && record.signing_digest == s.digest()?
                            && record.partial == partial
                            && record.server_salt == self.server_salt
                            && record.state == self.state
                            && record.capability == self.capability,
                        "issued transfer seal differs from durable state"
                    );
                }
                let actual = point(self.server_secret)?;
                ensure!(
                    s.context == self.current_session
                        && Some(&s.context) == p.recipient.as_ref()
                        && s.funding == self.funding
                        && s.next_capability == self.capability
                        && Some(s.recovery) == p.recovery
                        && Some(s.nonce_commitment) == p.blinding
                        && s.draft_server.as_slice() == actual
                        && Some(s.server_nonce.to_vec()) == p.nonce_point,
                    "issued signing binding mismatch"
                );
                ensure!(
                    ProjectivePoint::GENERATOR * scalar(&partial)?
                        == zark_protocol::point(&s.server_nonce)?
                            + zark_protocol::point(&s.draft_server)?
                                * scalar(&s.blinded_challenge)?,
                    "stored partial signature mismatch"
                );
                let server_share = ServerShareOpening {
                    deployment: self.deployment,
                    coin: self.coin,
                    server: s.draft_server,
                    salt: self.server_salt,
                }
                .commitment()?;
                let expected = StateOpening {
                    deployment: self.deployment,
                    coin: self.coin,
                    funding: self.funding,
                    capability: self.capability,
                    recovery: s.recovery,
                    server_share,
                    policy: policy_commitment(policy.schedule)?,
                    issuance: issuance_commitment(&s.digest()?, &partial)?,
                }
                .commitment()?;
                ensure!(expected == self.state, "issued state commitment mismatch");
                if p.origin {
                    ensure!(
                        s.previous_capability
                            == origin_previous_capability(&self.deployment, &self.coin)?
                            && s.refresh_commitment
                                == origin_refresh_commitment(
                                    &s.context,
                                    &self.funding,
                                    &s.draft_server
                                )?,
                        "issued origin mismatch"
                    );
                } else {
                    let h = HandoverBinding::decode(p.handover.as_ref().context("handover")?)?;
                    let c = ClaimBinding::decode(p.claim.as_ref().context("claim")?)?;
                    ensure!(
                        s.previous_capability == h.previous_capability
                            && s.next_capability == c.next_capability
                            && Some(self.server_salt) == p.draft_salt
                            && s.refresh_commitment
                                == refresh_commitment(
                                    &s.context,
                                    &h.mask,
                                    &h.masked_share,
                                    &h.bridge,
                                    &c.delta,
                                    &s.draft_server
                                )?,
                        "issued transfer mismatch"
                    );
                }
            }
        }
        Ok(())
    }
}
