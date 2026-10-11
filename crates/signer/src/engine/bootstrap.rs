//! Fresh joint-parent allocation. The parent contribution is held until the
//! exact combined deposit proof is verified; there is no caller-supplied share import.
use super::*;
use zark_protocol::bootstrap::{self as bootstrap_protocol, BootstrapBinding};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bootstrap {
    context: TransferContext,
    parent_server: Vec<u8>,
    active_server: Vec<u8>,
    active_salt: Digest,
    parent_funding: Option<Digest>,
    active_funding: Option<Digest>,
    capability: Option<Digest>,
    blinding: Option<Digest>,
    nonce_secret: Option<Digest>,
    nonce_point: Option<Vec<u8>>,
    binding: Option<Vec<u8>>,
    partial: Option<Digest>,
}
impl Drop for Bootstrap {
    fn drop(&mut self) {
        if let Some(n) = &mut self.nonce_secret {
            n.zeroize();
        }
    }
}
impl Bootstrap {
    #[cfg(test)]
    pub(super) fn test_frozen(
        context: &TransferContext,
        funding: Digest,
        capability: Digest,
        share: Digest,
        salt: Digest,
    ) -> Result<Self> {
        let nonce: Digest = random_scalar().to_bytes().into();
        let server = point(share)?;
        let parent_funding = nonzero_random();
        let blinding = nonzero_random();
        let nonce_point = point(nonce)?;
        let binding = BootstrapBinding {
            context: context.clone(),
            parent_funding,
            active_funding: funding,
            initial_capability: capability,
            parent_server: server.clone().try_into().unwrap(),
            active_server: server.clone().try_into().unwrap(),
            nonce_commitment: blinding,
            parent_nonce: nonce_point.clone().try_into().unwrap(),
            blinded_challenge: Scalar::from(9u64).to_bytes().into(),
        };
        Ok(Self {
            context: context.clone(),
            parent_server: server.clone(),
            active_server: server,
            active_salt: salt,
            parent_funding: Some(parent_funding),
            active_funding: Some(funding),
            capability: Some(capability),
            blinding: Some(blinding),
            nonce_secret: Some(nonce),
            nonce_point: Some(nonce_point),
            binding: Some(binding.encode()?),
            partial: None,
        })
    }
    pub(super) fn binding_bytes(&self) -> Result<Vec<u8>> {
        self.binding
            .clone()
            .context("frozen activation binding missing")
    }
    pub(super) fn released_partial(&self) -> Option<Digest> {
        self.partial
    }
    pub(super) fn validate(&self, coin: &Coin) -> Result<()> {
        bootstrap_protocol::validate_context(&self.context)?;
        ensure!(
            self.context.deployment == coin.deployment && self.context.coin == coin.coin,
            "bootstrap identity mismatch"
        );
        let ps = zark_protocol::point(&self.parent_server)?;
        zark_protocol::point(&self.active_server)?;
        ensure!(
            self.parent_server.len() == 64
                && self.active_server.len() == 64
                && self.parent_server == self.active_server,
            "bootstrap server points"
        );
        nonzero(self.active_salt)?;
        let allocated = coin.phase == Phase::BootstrapAllocated;
        let prepared = coin.phase == Phase::BootstrapPrepared;
        let released = self.partial.is_some();
        ensure!(
            self.parent_funding.is_some() != allocated
                && self.active_funding.is_some() != allocated
                && self.capability.is_some() != allocated
                && self.blinding.is_some() != allocated
                && self.nonce_point.is_some() != allocated,
            "bootstrap frozen shape"
        );
        ensure!(
            self.binding.is_some() == (!allocated && !prepared)
                && self.nonce_secret.is_some() == (!allocated && !released),
            "bootstrap release shape"
        );
        if let Some(nonce) = self.nonce_secret {
            ensure!(
                scalar(&nonce)? != Scalar::ZERO && Some(point(nonce)?) == self.nonce_point,
                "bootstrap nonce mismatch"
            );
        }
        if !allocated {
            for value in [
                self.parent_funding,
                self.active_funding,
                self.capability,
                self.blinding,
            ]
            .into_iter()
            .flatten()
            {
                nonzero(value)?;
            }
            ensure!(
                self.parent_funding != self.active_funding,
                "bootstrap identical outputs"
            );
            ensure!(
                Some(coin.funding) == self.active_funding,
                "bootstrap backing changed"
            );
        }
        if released {
            ensure!(
                !matches!(
                    coin.phase,
                    Phase::BootstrapAllocated
                        | Phase::BootstrapPrepared
                        | Phase::Origin
                        | Phase::OriginPrepared
                ),
                "released parent still in origin phase"
            );
        }
        if !released {
            ensure!(
                matches!(
                    coin.phase,
                    Phase::BootstrapAllocated
                        | Phase::BootstrapPrepared
                        | Phase::Origin
                        | Phase::OriginPrepared
                ),
                "unreleased parent escaped bootstrap"
            );
            ensure!(
                coin.current_session == self.context
                    && point(coin.server_secret)? == self.active_server
                    && coin.server_salt == self.active_salt,
                "bootstrap active allocation mismatch"
            );
            if !allocated {
                ensure!(
                    Some(coin.funding) == self.active_funding
                        && Some(coin.capability) == self.capability,
                    "bootstrap active commitments mismatch"
                );
            }
            ensure!(
                coin.state == self.context.previous_state,
                "bootstrap predecessor mismatch"
            );
        }
        if let Some(raw) = &self.binding {
            let b = BootstrapBinding::decode(raw)?;
            self.matches(&b)?;
            if let Some(partial) = self.partial {
                ensure!(
                    ProjectivePoint::GENERATOR * scalar(&partial)?
                        == zark_protocol::point(&b.parent_nonce)?
                            + ps * scalar(&b.blinded_challenge)?,
                    "bootstrap parent partial mismatch"
                );
            }
        }
        if allocated {
            ensure!(
                coin.funding == [0; 32] && coin.capability == [0; 32] && coin.pending.is_none(),
                "unfrozen bootstrap coin shape"
            );
        }
        if prepared {
            ensure!(
                coin.pending.is_none(),
                "prepared bootstrap pending recovery"
            );
        }
        Ok(())
    }
    pub(super) fn matches(&self, b: &BootstrapBinding) -> Result<()> {
        ensure!(
            b.context == self.context
                && Some(b.parent_funding) == self.parent_funding
                && Some(b.active_funding) == self.active_funding
                && Some(b.initial_capability) == self.capability
                && b.parent_server.as_slice() == self.parent_server
                && b.active_server.as_slice() == self.active_server
                && Some(b.nonce_commitment) == self.blinding
                && Some(b.parent_nonce.to_vec()) == self.nonce_point,
            "bootstrap binding differs from frozen allocation"
        );
        Ok(())
    }
    pub(super) fn release(&mut self, current_share: &Digest) -> Result<Value> {
        ensure!(
            self.partial.is_none(),
            "activation signature already released"
        );
        let b = BootstrapBinding::decode(
            self.binding
                .as_ref()
                .context("held bootstrap authorization")?,
        )?;
        self.matches(&b)?;
        ensure!(
            point(*current_share)? == self.parent_server,
            "bootstrap authority changed before release"
        );
        let mut nonce = self.nonce_secret.take().context("parent nonce")?;
        let partial: Digest = (scalar(&nonce)?
            + scalar(&b.blinded_challenge)? * scalar(current_share)?)
        .to_bytes()
        .into();
        nonce.zeroize();
        self.partial = Some(partial);
        Ok(json!({"activation_partial":partial,"activation_binding_digest":b.digest()?}))
    }
}

impl Engine {
    pub(super) fn allocate_bootstrap(
        &self,
        store: &mut Store,
        floor: &Checkpoint,
        request: &Request,
        digest: Digest,
        guard: &dyn Fn() -> Result<()>,
    ) -> Result<Value> {
        bootstrap_protocol::validate_context(&request.context)?;
        let active: Digest = random_scalar().to_bytes().into();
        // One live authority controls both outputs. Activation consumes its own
        // nonce; it must not revoke the current owner's deposit authority. The
        // normal Issue transition rotates this share for BOTH outputs together.
        let parent = active;
        let salt = nonzero_random();
        let ctx = request.context.clone();
        let b = Bootstrap {
            context: ctx.clone(),
            parent_server: point(parent)?,
            active_server: point(active)?,
            active_salt: salt,
            parent_funding: None,
            active_funding: None,
            capability: None,
            blinding: None,
            nonce_secret: None,
            nonce_point: None,
            binding: None,
            partial: None,
        };
        let response = json!({"parent_server":b.parent_server,"active_server":b.active_server,"active_server_salt":salt});
        let coin = Coin {
            owner_kind: PredecessorKind::Origin,
            deployment: ctx.deployment,
            coin: ctx.coin,
            funding: [0; 32],
            state: ctx.previous_state,
            capability: [0; 32],
            server_secret: active,
            server_salt: salt,
            current_session: ctx,
            phase: Phase::BootstrapAllocated,
            pending: None,
            exit: None,
            bootstrap: Some(b),
        };
        coin.validate(&self.policy)?;
        self.admission.authorize(&request.context)?;
        guard()?;
        #[cfg(test)]
        self.trip(tests::Fault::BeforeCommit)?;
        store.allocate_request(&coin, request, digest, &response, floor)?;
        #[cfg(test)]
        self.trip(tests::Fault::AfterCommit)?;
        store.publish(&self.checkpoint)?;
        #[cfg(test)]
        self.trip(tests::Fault::AfterCheckpoint)?;
        Ok(response)
    }
    pub(super) fn bootstrap_plan(
        &self,
        coin: &Coin,
        request: &Request,
    ) -> Result<Option<ProofSpec>> {
        let b = coin
            .bootstrap
            .as_ref()
            .context("coin has no bootstrap allocation")?;
        ensure!(
            b.context == request.context,
            "bootstrap owner session mismatch"
        );
        match &request.command {
            Command::BootstrapPrepare {
                parent_funding,
                active_funding,
                capability,
                blinding,
            } => {
                ensure!(
                    coin.phase == Phase::BootstrapAllocated,
                    "bootstrap preparation out of phase"
                );
                for x in [parent_funding, active_funding, capability, blinding] {
                    nonzero(*x)?;
                }
                ensure!(
                    parent_funding != active_funding,
                    "bootstrap identical outputs"
                );
                Ok(None)
            }
            Command::BootstrapFreeze { statement } => {
                ensure!(
                    coin.phase == Phase::BootstrapPrepared,
                    "bootstrap freeze out of phase"
                );
                let binding = BootstrapBinding::decode(statement)?;
                b.matches(&binding)?;
                Ok(None)
            }
            _ => anyhow::bail!("invalid bootstrap mutation"),
        }
    }
    pub(super) fn bootstrap_apply(&self, coin: &mut Coin, request: &Request) -> Result<Value> {
        let b = coin.bootstrap.as_mut().context("bootstrap")?;
        match &request.command {
            Command::BootstrapPrepare {
                parent_funding,
                active_funding,
                capability,
                blinding,
            } => {
                let nonce: Digest = random_scalar().to_bytes().into();
                let public = point(nonce)?;
                b.parent_funding = Some(*parent_funding);
                b.active_funding = Some(*active_funding);
                b.capability = Some(*capability);
                b.blinding = Some(*blinding);
                b.nonce_secret = Some(nonce);
                b.nonce_point = Some(public.clone());
                coin.funding = *active_funding;
                coin.capability = *capability;
                coin.phase = Phase::BootstrapPrepared;
                Ok(json!({"parent_nonce":public}))
            }
            Command::BootstrapFreeze { statement } => {
                b.binding = Some(statement.clone());
                coin.phase = Phase::Origin;
                let mut pending = Pending::new(true);
                pending.recipient = Some(request.context.clone());
                coin.pending = Some(pending);
                Ok(json!({"frozen":true,"activation_held":true}))
            }
            _ => anyhow::bail!("invalid bootstrap mutation"),
        }
    }
}
