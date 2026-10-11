//! Fresh synthetic application fixtures, not a signer endpoint or live wallet.
//! Server shares, server nonce scalars and the origin secret exist only here.
use anyhow::{Context, Result, ensure};
use bitcoin::{
    OutPoint, Transaction, Txid,
    consensus::serialize,
    hashes::Hash,
    secp256k1::{Keypair, Message, Parity, Secp256k1, SecretKey, XOnlyPublicKey},
};
use k256::{ProjectivePoint, Scalar};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zark_protocol::{
    even,
    handoff::{
        ClaimBinding, FundingOpening, HandoverBinding, RecoveryDelay, RecoveryOpening,
        RecoverySchedule, ServerShareOpening, SigningBinding, StateOpening, TransferContext,
        TransferIntent, blinding_commitment, bridge_commitment, capability_commitment,
        delta_commitment, issuance_commitment, mask_commitment, masked_share_commitment,
        origin_previous_capability, origin_previous_state, origin_refresh_commitment,
        policy_commitment, recipient_claim_commitment, refresh_commitment,
    },
    hash, hex32, point, point_bytes, random_scalar, random32, scalar,
};
use zark_wallet::{
    bitcoin::{attach_signature, backup, sighash},
    recovery::{RecoveryDraft, RecoveryParameters},
    signing::{Blinding, FundingKey},
    types::Input,
};

const SOURCE: &str = "synthetic fresh test keys and unbroadcast coins only; never for funds";
const SCHEDULE: RecoverySchedule = RecoverySchedule {
    initial: 480,
    gap: 60,
    margin: 6,
};

fn nonzero() -> [u8; 32] {
    loop {
        let value = random32();
        if value != [0; 32] {
            return value;
        }
    }
}
fn secret_bytes(s: Scalar) -> [u8; 32] {
    s.to_bytes().into()
}
fn point_of(s: Scalar) -> [u8; 64] {
    point_bytes(ProjectivePoint::GENERATOR * s).unwrap()
}
fn even_key() -> (Scalar, [u8; 64]) {
    let s = random_scalar();
    let (point, sign) = even(ProjectivePoint::GENERATOR * s).unwrap();
    (s * sign, point_bytes(point).unwrap())
}
fn bytes<const N: usize>(value: &Value) -> Result<[u8; N]> {
    let v: Vec<u8> = serde_json::from_value(value.clone())?;
    v.try_into()
        .map_err(|_| anyhow::anyhow!("fixture byte length"))
}
fn mkdir(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
fn write_json(path: &Path, value: &Value) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::File::open(path.parent().context("fixture parent")?)?.sync_all()?;
    Ok(())
}

struct Common {
    deployment: [u8; 32],
    coin: [u8; 32],
    funding: [u8; 32],
    policy: [u8; 32],
    backing: Input,
    activation_input: Input,
    activation: Transaction,
}

/// Non-serializable generator state. No production client method accepts these
/// server secrets; a synthetic server computes only the requested partial.
struct Owner {
    user: Scalar,
    server: Scalar,
    capability: [u8; 32],
    server_salt: [u8; 32],
    payout_secret: Scalar,
    payout: [u8; 64],
    binding: SigningBinding,
    partial: [u8; 32],
    backup_salt: [u8; 32],
    delay: RecoveryDelay,
    state: [u8; 32],
    recovery: Value,
}

struct PrivacyChecks {
    never_client: Vec<Vec<u8>>,
    actor_forbidden: Vec<(String, Vec<u8>)>,
}
impl PrivacyChecks {
    fn new() -> Self {
        Self {
            never_client: vec![],
            actor_forbidden: vec![],
        }
    }
    fn server_secret(&mut self, secret: Scalar) {
        self.never_client.push(secret_bytes(secret).to_vec());
    }
    fn forbid(&mut self, actor: &str, value: &[u8]) {
        self.actor_forbidden.push((actor.into(), value.to_vec()));
    }
}

fn common(user: Scalar, server: Scalar, privacy: &mut PrivacyChecks) -> Result<Common> {
    let deployment = nonzero();
    let coin = nonzero();
    let backing_key = FundingKey::new(ProjectivePoint::GENERATOR * server, user)?;
    let deposit_user = user;
    let deposit_server = server;
    privacy.server_secret(deposit_server);
    let deposit_key = FundingKey::new(ProjectivePoint::GENERATOR * deposit_server, deposit_user)?;
    let txid = Txid::from_byte_array(nonzero());
    let activation_input = Input {
        deployment: hex::encode(deployment),
        id: hex::encode(coin),
        funding_salt: hex::encode(nonzero()),
        internal_point: hex::encode(point_bytes(deposit_key.internal)?),
        txid: txid.to_string(),
        vout: 0,
        amount: 100_000,
    };
    let mut activation = zark_wallet::bitcoin::activation(
        OutPoint::new(txid, 0),
        100_000,
        &[(99_000, backing_key.xonly()?)],
        0,
    )?;
    let blind = Blinding::default();
    let nonce = random_scalar();
    privacy.server_secret(nonce);
    let rs = ProjectivePoint::GENERATOR * nonce;
    let sp = ProjectivePoint::GENERATOR * deposit_server;
    let session = blind.bind(
        &deposit_key,
        sp,
        rs,
        sighash(&activation, 100_000, deposit_key.xonly()?)?,
    )?;
    let signature = blind.finish(
        &deposit_key,
        &session,
        sp,
        rs,
        nonce + session.challenge * deposit_server,
    )?;
    attach_signature(&mut activation, 100_000, deposit_key.xonly()?, &signature)?;
    let funding_salt = nonzero();
    let backing = Input {
        deployment: hex::encode(deployment),
        id: hex::encode(coin),
        funding_salt: hex::encode(funding_salt),
        internal_point: hex::encode(point_bytes(backing_key.internal)?),
        txid: activation.compute_txid().to_string(),
        vout: 0,
        amount: 99_000,
    };
    let funding = FundingOpening {
        deployment,
        coin,
        salt: funding_salt,
        txid: activation.compute_txid().to_byte_array(),
        vout: 0,
        amount: 99_000,
        internal_point: point_bytes(backing_key.internal)?,
    }
    .commitment()?;
    Ok(Common {
        deployment,
        coin,
        funding,
        policy: policy_commitment(SCHEDULE)?,
        backing,
        activation_input,
        activation,
    })
}

fn state(
    common: &Common,
    binding: &SigningBinding,
    partial: &[u8; 32],
    server_salt: [u8; 32],
) -> Result<[u8; 32]> {
    StateOpening {
        deployment: common.deployment,
        coin: common.coin,
        funding: common.funding,
        capability: binding.next_capability,
        recovery: binding.recovery,
        server_share: ServerShareOpening {
            deployment: common.deployment,
            coin: common.coin,
            server: binding.draft_server,
            salt: server_salt,
        }
        .commitment()?,
        policy: common.policy,
        issuance: issuance_commitment(&binding.digest()?, partial)?,
    }
    .commitment()
}

#[allow(clippy::too_many_arguments)] // Explicit independent synthetic witness components.
fn finish_owner(
    common: &Common,
    user: Scalar,
    server: Scalar,
    capability: [u8; 32],
    payout_secret: Scalar,
    binding: SigningBinding,
    partial: [u8; 32],
    backup_salt: [u8; 32],
    delay: RecoveryDelay,
    mut recovery: Value,
) -> Result<Owner> {
    let server_salt = nonzero();
    let state = state(common, &binding, &partial, server_salt)?;
    let payout = point_of(payout_secret);
    ensure!(payout[63] & 1 == 0, "payout normalization");
    recovery["fixture_version"] = json!(1);
    recovery["source"] = json!(SOURCE);
    recovery["server_salt"] = json!(server_salt);
    recovery["state_commitment"] = json!(state);
    recovery["capability"] = json!(capability);
    ensure!(
        binding.next_capability
            == capability_commitment(&common.deployment, &common.coin, &capability)?,
        "state capability opening"
    );
    Ok(Owner {
        user,
        server,
        capability,
        server_salt,
        payout_secret,
        payout,
        binding,
        partial,
        backup_salt,
        delay,
        state,
        recovery,
    })
}

fn signing_request(path: &Path, binding: &SigningBinding, origin: bool) -> Result<()> {
    write_json(
        &path.join("signing-request.json"),
        &json!({
            "stage":"unsigned recovery committed; blinded challenge bound; no usable partial yet",
            "statement":binding.encode()?,"binding_digest":binding.digest()?,
            "required_authorization":if origin {"origin-issuance-authorization"} else {"transfer-issuance-authorization"},
            "authorization_proof_generated":false,"authorization_proof_verified":false,
            "source":SOURCE,
        }),
    )
}
fn synthetic_partial(
    path: &Path,
    binding: &SigningBinding,
    server: Scalar,
    nonce: Scalar,
) -> Result<[u8; 32]> {
    ensure!(
        path.join("signing-request.json").exists(),
        "record unsigned request before synthetic response"
    );
    ensure!(
        binding.draft_server == point_of(server) && binding.server_nonce == point_of(nonce),
        "test server binding"
    );
    let partial = secret_bytes(nonce + scalar(&binding.blinded_challenge)? * server);
    write_json(
        &path.join("signing-response.json"),
        &json!({
            "stage":"test-only precomputed response; NOT evidence of authorized or durable production issuance",
            "binding_digest":binding.digest()?,"partial":partial,"server_nonce":binding.server_nonce.to_vec(),
            "host_issuance_lifecycle_verified":false,"source":SOURCE,
        }),
    )?;
    Ok(partial)
}

fn initial_owner(
    path: &Path,
    common: &Common,
    user: Scalar,
    server: Scalar,
    privacy: &mut PrivacyChecks,
) -> Result<Owner> {
    let capability = zark_protocol::owner_auth::generate_secret();
    let (claim_secret, claim_point) = even_key();
    let claim_salt = nonzero();
    let operation = nonzero();
    let (_session_secret, session_point) = even_key();
    // An allocation context, not an invented predecessor certificate. The
    // separate origin attestation authenticates this initial state's entry.
    let context = TransferContext {
        start_revision: 0,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: common.deployment,
        coin: common.coin,
        previous_state: origin_previous_state(&common.deployment, &common.coin)?,
        operation,
        recipient_claim: recipient_claim_commitment(
            &common.deployment,
            &common.coin,
            &operation,
            &claim_point[..32].try_into()?,
            &claim_salt,
        )?,
        session_auth: session_point[..32].try_into()?,
    };
    let (payout_secret, payout) = even_key();
    let delay = SCHEDULE.delay_after(0)?;
    let backup_salt = nonzero();
    let nonce_salt = nonzero();
    let recovery = RecoveryOpening {
        deployment: common.deployment,
        coin: common.coin,
        funding: common.funding,
        salt: backup_salt,
        payout: payout[..32].try_into()?,
        fee: 1000,
        delay,
    }
    .commitment()?;
    let blind = Blinding::default();
    let nonce = random_scalar();
    privacy.server_secret(nonce);
    let sp = ProjectivePoint::GENERATOR * server;
    let rp = ProjectivePoint::GENERATOR * nonce;
    let key = FundingKey::new(sp, user)?;
    let mut transaction = backup(
        OutPoint::new(common.activation.compute_txid(), 0),
        99_000,
        1000,
        payout[..32].try_into()?,
        delay.blocks(),
    )?;
    let session = blind.bind(&key, sp, rp, sighash(&transaction, 99_000, key.xonly()?)?)?;
    let binding = SigningBinding {
        context: context.clone(),
        funding: common.funding,
        refresh_commitment: origin_refresh_commitment(
            &context,
            &common.funding,
            &point_bytes(sp)?,
        )?,
        previous_capability: origin_previous_capability(&common.deployment, &common.coin)?,
        next_capability: capability_commitment(&common.deployment, &common.coin, &capability)?,
        recovery,
        nonce_commitment: blinding_commitment(
            &context,
            &common.funding,
            &recovery,
            &secret_bytes(blind.alpha),
            &secret_bytes(blind.beta),
            &nonce_salt,
        )?,
        draft_server: point_bytes(sp)?,
        server_nonce: point_bytes(rp)?,
        blinded_challenge: secret_bytes(session.challenge),
    };
    signing_request(path, &binding, true)?;
    let partial = synthetic_partial(path, &binding, server, nonce)?;
    let signature = blind.finish(&key, &session, sp, rp, scalar(&partial)?)?;
    attach_signature(&mut transaction, 99_000, key.xonly()?, &signature)?;
    let values = json!({
        "statement": binding.encode()?, "binding_digest": binding.digest()?, "partial": partial, "signature": signature.to_vec(),
        "user": secret_bytes(user), "alpha": secret_bytes(blind.alpha), "beta": secret_bytes(blind.beta),
        "funding_salt": hex32(&common.backing.funding_salt)?, "backup_salt": backup_salt, "nonce_salt": nonce_salt,
        "txid": common.activation.compute_txid().to_byte_array(), "vout": 0, "amount": 99_000, "fee": 1000,
        "destination": payout.to_vec(), "delay": delay.blocks(), "session_auth_point": session_point.to_vec(),
        "transaction": hex::encode(serialize(&transaction)),
    });
    // These are allocation-only keys, neither a server secret nor an old-owner
    // opening needed by the receiver of a later handover.
    let _ = claim_secret;
    finish_owner(
        common,
        user,
        server,
        capability,
        payout_secret,
        binding,
        partial,
        backup_salt,
        delay,
        values,
    )
}

#[allow(clippy::too_many_arguments)] // Explicit independent synthetic witness components.
fn sender_values(
    common: &Common,
    owner: &Owner,
    handover: &HandoverBinding,
    mask: Scalar,
    mask_salt: [u8; 32],
    z: Scalar,
    z_salt: [u8; 32],
    bridge_salt: [u8; 32],
    token: [u8; 32],
) -> Result<Value> {
    Ok(json!({
        "statement": handover.encode()?, "binding_digest": handover.digest()?, "server": point_of(owner.server).to_vec(), "token":token,
        "server_salt": owner.server_salt, "user": secret_bytes(owner.user), "capability": owner.capability,
        "mask": secret_bytes(mask), "mask_salt": mask_salt, "masked_share": secret_bytes(z), "masked_share_salt": z_salt,
        "funding_salt": hex32(&common.backing.funding_salt)?, "funding_output_key": common.backing.key()?, "txid": common.activation.compute_txid().to_byte_array(),
        "vout": 0, "amount": 99_000, "destination": owner.payout.to_vec(), "fee": 1000,
        "delay": owner.delay.blocks(), "backup_salt": owner.backup_salt,
        "issuance_digest": issuance_commitment(&owner.binding.digest()?, &owner.partial)?, "bridge_salt": bridge_salt,
        "initial": SCHEDULE.initial, "gap": SCHEDULE.gap, "margin": SCHEDULE.margin,
    }))
}

fn transfer(
    root: &Path,
    common: &Common,
    old: &Owner,
    sender: &str,
    recipient: &str,
    privacy: &mut PrivacyChecks,
) -> Result<Owner> {
    let capability = zark_protocol::owner_auth::generate_secret();
    let previous_capability =
        capability_commitment(&common.deployment, &common.coin, &old.capability)?;
    let next_capability = capability_commitment(&common.deployment, &common.coin, &capability)?;
    ensure!(previous_capability != next_capability, "fresh capability");
    let (claim_secret, claim_point) = even_key();
    let claim_salt = nonzero();
    let operation = nonzero();
    let (_receiver_session_secret, session_point) = even_key();
    let (_sender_session_secret, sender_session_point) = even_key();
    let intent = TransferIntent {
        start_revision: 1,
        scope: zark_protocol::handoff::OperationScope::Single,
        deployment: common.deployment,
        coin: common.coin,
        previous_state: old.state,
        operation,
        recipient_claim: recipient_claim_commitment(
            &common.deployment,
            &common.coin,
            &operation,
            &claim_point[..32].try_into()?,
            &claim_salt,
        )?,
    };
    let context = intent.with_session(session_point[..32].try_into()?)?;
    let sender_context = intent.with_session(sender_session_point[..32].try_into()?)?;
    zark_protocol::owner_auth::OwnerAuthorization::sign_reservation(
        &sender_context,
        &old.capability,
    )?
    .verify_reservation(&sender_context, &previous_capability)?;
    // Reservation is conceptually accepted before choosing/releasing m; this
    // native fixture is not an implementation of that host state machine.
    let mask = loop {
        let m = random_scalar();
        if old.user + m != Scalar::ZERO {
            break m;
        }
    };
    let z = old.user + mask;
    let (user, delta, server) = loop {
        let user = random_scalar();
        let delta = z - user;
        let server = old.server + delta - mask;
        if server != Scalar::ZERO && user != old.user {
            break (user, delta, server);
        }
    };
    ensure!(
        old.server + old.user == server + user,
        "raw aggregate scalar changed"
    );
    ensure!(
        point_of(old.server + old.user) == point_of(server + user),
        "raw aggregate point changed"
    );
    let new_key = FundingKey::new(ProjectivePoint::GENERATOR * server, user)?;
    ensure!(
        new_key.xonly()? == common.backing.key()?,
        "Taproot key changed"
    );
    privacy.server_secret(server);
    let mask_salt = nonzero();
    let z_salt = nonzero();
    let bridge_salt = nonzero();
    let delta_salt = nonzero();
    let cm = mask_commitment(&intent, &secret_bytes(mask), &mask_salt)?;
    let cz = masked_share_commitment(&intent, &secret_bytes(z), &z_salt)?;
    let bridge = bridge_commitment(
        &intent,
        &common.funding,
        old.delay,
        &common.policy,
        &bridge_salt,
    )?;
    let cd = delta_commitment(&context, &secret_bytes(delta), &delta_salt)?;
    let token = nonzero();
    let handover = HandoverBinding {
        draft_access: zark_protocol::handoff::draft_access_commitment(&intent, &token)?,
        intent,
        funding: common.funding,
        mask: cm,
        masked_share: cz,
        bridge,
        previous_capability,
        server_share: ServerShareOpening {
            deployment: common.deployment,
            coin: common.coin,
            server: point_of(old.server),
            salt: old.server_salt,
        }
        .commitment()?,
        policy: common.policy,
    };
    let claim = ClaimBinding {
        context: context.clone(),
        mask: cm,
        masked_share: cz,
        bridge,
        delta: cd,
        next_capability,
    };
    let refresh = refresh_commitment(&context, &cm, &cz, &bridge, &cd, &point_of(server))?;
    let (payout_secret, _) = even_key();
    let next_delay = RecoveryDelay::from_sequence(old.delay.blocks() - SCHEDULE.gap)?;
    SCHEDULE.check_transition(old.delay, next_delay)?;
    let parameters = RecoveryParameters {
        context: context.clone(),
        backing: common.backing.clone(),
        activation_input: common.activation_input.clone(),
        activation: common.activation.clone(),
        draft_server: point_of(server),
        refresh_commitment: refresh,
        previous_capability,
        next_capability,
        schedule: SCHEDULE,
        previous_delay: old.delay,
        next_delay,
        fee: 1000,
    };
    let draft_path = root.join(recipient).join("draft");
    let draft = RecoveryDraft::create(
        &draft_path,
        parameters,
        &secret_bytes(user),
        &secret_bytes(payout_secret),
    )?;
    let commitments = draft.commitments()?;
    ensure!(
        commitments.funding == common.funding,
        "recipient funding commitment"
    );
    drop(draft);
    let mut draft = RecoveryDraft::open(&draft_path, &context)?;
    let nonce = random_scalar();
    privacy.server_secret(nonce);
    let binding = draft.bind_server_nonce(&context, point_of(nonce))?;
    signing_request(&root.join(recipient), &binding, false)?;
    let partial = synthetic_partial(&root.join(recipient), &binding, server, nonce)?;
    let transaction = draft.finish(&context, point_of(nonce), partial)?;
    drop(draft);
    let restored = RecoveryDraft::open(&draft_path, &context)?;
    ensure!(
        serialize(&restored.completed_transaction()?) == serialize(&transaction),
        "durable recipient recovery"
    );
    restored.export_portable(&root.join(recipient).join("portable-recovery.json"))?;
    drop(restored);
    // Reading this actor's own synthetic durable record exposes its witness
    // values to its test prover, not to a sender or server directory.
    let record: Value = serde_json::from_slice(&fs::read(draft_path.join("recovery-draft.json"))?)?;
    let backup_salt = bytes::<32>(&record["backup_salt"])?;
    let payout = point_of(payout_secret);
    let signature: [u8; 64] = transaction.input[0].witness[0].try_into()?;
    let recovery = json!({
        "statement": binding.encode()?, "binding_digest": binding.digest()?, "partial": partial, "signature": signature.to_vec(),
        "user": secret_bytes(user), "alpha": record["alpha"], "beta": record["beta"],
        "funding_salt": hex32(&common.backing.funding_salt)?, "backup_salt": backup_salt, "nonce_salt": record["nonce_salt"],
        "txid": common.activation.compute_txid().to_byte_array(), "vout": 0, "amount": 99_000, "fee": 1000,
        "destination": payout.to_vec(), "delay": next_delay.blocks(), "session_auth_point": session_point.to_vec(),
        "transaction": hex::encode(serialize(&transaction)),
    });
    let owner = finish_owner(
        common,
        user,
        server,
        capability,
        payout_secret,
        binding,
        partial,
        backup_salt,
        next_delay,
        recovery,
    )?;
    write_json(
        &root.join(sender).join("handover.json"),
        &sender_values(
            common,
            old,
            &handover,
            mask,
            mask_salt,
            z,
            z_salt,
            bridge_salt,
            token,
        )?,
    )?;
    write_json(
        &root.join(recipient).join("handover-public.json"),
        &json!({"statement": handover.encode()?, "binding_digest": handover.digest()?}),
    )?;
    write_json(
        &root.join(recipient).join("claim.json"),
        &json!({
            "statement": claim.encode()?, "binding_digest": claim.digest()?, "claim_secret": secret_bytes(claim_secret),
            "claim_point": claim_point.to_vec(), "claim_salt": claim_salt, "session_auth_point": session_point.to_vec(),
            "masked_share": secret_bytes(z), "masked_share_salt": z_salt, "user": secret_bytes(user),
            "delta": secret_bytes(delta), "delta_salt": delta_salt, "next_capability": capability,
        }),
    )?;
    write_json(
        &root.join(recipient).join("bridge.json"),
        &json!({"funding": common.funding, "old_delay": old.delay.blocks(),
        "policy": common.policy, "bridge_salt": bridge_salt, "intent": handover.intent.encode()?}),
    )?;
    privacy.forbid(recipient, &secret_bytes(old.user));
    privacy.forbid(recipient, &point_of(old.server));
    privacy.forbid(recipient, &old.server_salt);
    privacy.forbid(recipient, &old.capability);
    privacy.forbid(recipient, &old.payout[..32]);
    privacy.forbid(recipient, &secret_bytes(old.payout_secret));
    privacy.forbid(recipient, &old.backup_salt);
    privacy.forbid(recipient, &secret_bytes(mask));
    privacy.forbid(recipient, &mask_salt);
    privacy.forbid(sender, &secret_bytes(user));
    privacy.forbid(sender, &secret_bytes(delta));
    privacy.forbid(sender, &payout[..32]);
    privacy.forbid(sender, &secret_bytes(payout_secret));
    privacy.forbid(sender, &capability);
    privacy.forbid(sender, &secret_bytes(claim_secret));
    Ok(owner)
}

fn actor_files(root: &Path, actor: &str, owner: &Owner) -> Result<()> {
    write_json(&root.join(actor).join("recovery.json"), &owner.recovery)?;
    write_json(
        &root.join(actor).join("wallet-private.json"),
        &json!({"source": SOURCE,
        "user": secret_bytes(owner.user), "capability": owner.capability, "payout_secret": secret_bytes(owner.payout_secret)}),
    )?;
    Ok(())
}

fn origin(
    root: &Path,
    common: &Common,
    alice: &Owner,
    privacy: &mut PrivacyChecks,
) -> Result<[u8; 64]> {
    let (origin_secret, origin_key) = even_key();
    privacy.server_secret(origin_secret);
    let message = hash(&[
        b"ZARK/private-handoff/origin/v1",
        &8u32.to_le_bytes(),
        &common.deployment,
        &common.coin,
        &common.funding,
        &alice.state,
        &common.policy,
    ]);
    let secp = Secp256k1::new();
    let pair =
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&secret_bytes(origin_secret))?);
    let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(message), &pair);
    secp.verify_schnorr(
        &signature,
        &Message::from_digest(message),
        &pair.x_only_public_key().0,
    )?;
    let nonce = XOnlyPublicKey::from_slice(&signature.as_ref()[..32])?
        .public_key(Parity::Even)
        .serialize_uncompressed();
    write_json(
        &root.join("alice/origin.json"),
        &json!({
            "origin_signature": signature.as_ref().to_vec(), "origin_nonce_point": nonce[1..].to_vec(), "origin_key_point":origin_key.to_vec(), "message": message,
        }),
    )?;
    Ok(origin_key)
}

fn contains(value: &Value, needle: &[u8]) -> bool {
    match value {
        Value::String(s) => s.contains(&hex::encode(needle)),
        Value::Array(values) => {
            if let Some(bytes) = values
                .iter()
                .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect::<Option<Vec<_>>>()
                && bytes.windows(needle.len()).any(|window| window == needle)
            {
                return true;
            }
            values.iter().any(|v| contains(v, needle))
        }
        Value::Object(values) => values.values().any(|v| contains(v, needle)),
        _ => false,
    }
}
fn json_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = vec![];
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            files.extend(json_files(&path)?);
        } else if path.extension().is_some_and(|ext| ext == "json") {
            files.push(path);
        }
    }
    Ok(files)
}

fn generate(root: &Path) -> Result<()> {
    mkdir(root)?;
    for actor in ["alice", "bob", "carol"] {
        mkdir(&root.join(actor))?;
    }
    let mut privacy = PrivacyChecks::new();
    let (user, server) = loop {
        let u = random_scalar();
        let s = random_scalar();
        if u + s != Scalar::ZERO {
            break (u, s);
        }
    };
    privacy.server_secret(server);
    let common = common(user, server, &mut privacy)?;
    let alice = initial_owner(&root.join("alice"), &common, user, server, &mut privacy)?;
    actor_files(root, "alice", &alice)?;
    let origin_key = origin(root, &common, &alice, &mut privacy)?;
    let bob = transfer(root, &common, &alice, "alice", "bob", &mut privacy)?;
    actor_files(root, "bob", &bob)?;
    write_json(
        &root.join("bob/off-policy-recovery.json"),
        &off_policy_recovery(&bob.recovery)?,
    )?;
    let carol = transfer(root, &common, &bob, "bob", "carol", &mut privacy)?;
    actor_files(root, "carol", &carol)?;
    ensure!(
        [
            alice.delay.blocks(),
            bob.delay.blocks(),
            carol.delay.blocks()
        ] == [480, 420, 360],
        "first three owners of the eight-owner recovery schedule"
    );
    ensure!(
        SCHEDULE
            .check_transition(carol.delay, RecoveryDelay::from_sequence(1)?)
            .is_err(),
        "off-schedule transfer unexpectedly accepted"
    );
    let common_json = json!({"fixture_version":1,"source":SOURCE,"version":10,
        "deployment":common.deployment,"coin":common.coin,"funding":common.funding,"policy":common.policy,
        "schedule":{"initial":SCHEDULE.initial,"gap":SCHEDULE.gap,"margin":SCHEDULE.margin,"owners":zark_protocol::handoff::INITIAL_OWNER_LIMIT},
        "origin_key":origin_key[..32].to_vec(),"origin_key_point":origin_key.to_vec(),
        "funding_opening":{"salt":hex32(&common.backing.funding_salt)?,"txid":common.activation.compute_txid().to_byte_array(),
            "vout":0,"amount":99_000,"internal_point":hex::decode(&common.backing.internal_point)?},
        "backing":common.backing,"activation_input":common.activation_input,"activation":hex::encode(serialize(&common.activation)),
        "recursive_vk_configuration":"not fabricated here; proof orchestrator must pin its actual compiled role hashes"});
    // Common data intentionally has no historical state, recovery or signature.
    for secret in [
        alice.state,
        bob.state,
        carol.state,
        alice.payout[..32].try_into()?,
        bob.payout[..32].try_into()?,
        carol.payout[..32].try_into()?,
    ] {
        ensure!(
            !contains(&common_json, &secret),
            "common manifest leaked private state/recovery"
        );
    }
    write_json(&root.join("common.json"), &common_json)?;
    for path in json_files(root)? {
        let value: Value = serde_json::from_slice(&fs::read(&path)?)?;
        for secret in &privacy.never_client {
            ensure!(
                !contains(&value, secret),
                "server secret leaked to client fixture"
            );
        }
        for (actor, secret) in &privacy.actor_forbidden {
            if path.starts_with(root.join(actor)) {
                ensure!(
                    !contains(&value, secret),
                    "another actor's opening leaked in fixture"
                );
            }
        }
        ensure!(
            fs::metadata(&path)?.permissions().mode() & 0o777 == 0o600,
            "fixture file permissions"
        );
    }
    write_json(
        &root.join("manifest.json"),
        &json!({"fixture_version":1,"source":SOURCE,"common":"common.json",
        "actors":["alice","bob","carol"],"native_activation_signature_verified":true,"native_recovery_signatures_verified":3,
        "durable_recipient_reloads_verified":2,"role_secret_scans_passed":true,"server_secrets_persisted":false,
        "proofs_generated":false,"chain_backing_verified":false,"issuance_authorization_proofs_verified":false,
        "host_issuance_lifecycle_verified":false,
        "pipeline_gate":"verify the origin/transfer issuance authorization before treating the precomputed response as authorized"}),
    )?;
    Ok(())
}

/// A counterfactual unsigned challenge. This is never sent to a signer and
/// never receives a partial; it only tests the pre-issuance proof policy gate.
fn off_policy_recovery(original: &Value) -> Result<Value> {
    let raw: Vec<u8> = serde_json::from_value(original["statement"].clone())?;
    let mut binding = SigningBinding::decode(&raw)?;
    let user = scalar(&bytes::<32>(&original["user"])?)?;
    let server = point(&binding.draft_server)?;
    let server_nonce = point(&binding.server_nonce)?;
    let key = FundingKey::new(server, user)?;
    let txid = Txid::from_byte_array(bytes(&original["txid"])?);
    let vout = original["vout"].as_u64().context("vout")? as u32;
    let amount = original["amount"].as_u64().context("amount")?;
    let fee = original["fee"].as_u64().context("fee")?;
    let destination = bytes::<64>(&original["destination"])?;
    let delay = RecoveryDelay::from_sequence(1)?;
    let transaction = backup(
        OutPoint::new(txid, vout),
        amount,
        fee,
        destination[..32].try_into()?,
        1,
    )?;
    let blind = Blinding::default();
    let backup_salt = nonzero();
    let nonce_salt = nonzero();
    let session = blind.bind(
        &key,
        server,
        server_nonce,
        sighash(&transaction, amount, key.xonly()?)?,
    )?;
    binding.recovery = RecoveryOpening {
        deployment: binding.context.deployment,
        coin: binding.context.coin,
        funding: binding.funding,
        salt: backup_salt,
        payout: destination[..32].try_into()?,
        fee,
        delay,
    }
    .commitment()?;
    binding.nonce_commitment = blinding_commitment(
        &binding.context,
        &binding.funding,
        &binding.recovery,
        &secret_bytes(blind.alpha),
        &secret_bytes(blind.beta),
        &nonce_salt,
    )?;
    binding.blinded_challenge = secret_bytes(session.challenge);
    let mut result = original.clone();
    for key in [
        "partial",
        "signature",
        "transaction",
        "server_salt",
        "state_commitment",
    ] {
        result
            .as_object_mut()
            .context("fixture object")?
            .remove(key);
    }
    result["statement"] = json!(binding.encode()?);
    result["binding_digest"] = json!(binding.digest()?);
    result["alpha"] = json!(secret_bytes(blind.alpha));
    result["beta"] = json!(secret_bytes(blind.beta));
    result["backup_salt"] = json!(backup_salt);
    result["nonce_salt"] = json!(nonce_salt);
    result["delay"] = json!(1);
    result["unsigned_transaction"] = json!(hex::encode(serialize(&transaction)));
    result["source"] = json!(SOURCE);
    result["negative_case"] = json!(
        "valid primitive recovery relation, but off-policy delay must fail composed authorization BEFORE any partial"
    );
    ensure!(
        SCHEDULE
            .check_transition(RecoveryDelay::from_sequence(480)?, delay)
            .is_err(),
        "off-policy request unexpectedly allowed"
    );
    ensure!(
        result.get("partial").is_none() && result.get("signature").is_none(),
        "negative fixture issued a partial"
    );
    Ok(result)
}

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("zark-lineage-native-{}", hex::encode(random32()))))
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn coherent_three_owner_fixtures_preserve_keys_verify_recoveries_and_separate_secrets() -> Result<()>
{
    let home = Home::new();
    generate(&home.0)?;
    ensure!(generate(&home.0).is_err(), "existing fixture overwritten");
    let bob: Value = serde_json::from_slice(&fs::read(home.0.join("bob/claim.json"))?)?;
    let carol: Value = serde_json::from_slice(&fs::read(home.0.join("carol/claim.json"))?)?;
    ensure!(
        bob["user"] != carol["user"] && bob["next_capability"] != carol["next_capability"],
        "recipient secret reuse"
    );
    Ok(())
}

#[test]
#[ignore = "writes fresh synthetic proof inputs only when an explicit output path is supplied"]
fn export_fresh_three_owner_lineage_fixture() -> Result<()> {
    let output = PathBuf::from(
        std::env::var("ZARK_LINEAGE_FIXTURE_OUT")
            .context("set ZARK_LINEAGE_FIXTURE_OUT to a NEW directory")?,
    );
    generate(&output)?;
    println!("Synthetic lineage fixture: {}", output.display());
    Ok(())
}

#[test]
#[ignore = "adds one unsigned negative fixture to an explicitly selected synthetic fixture directory"]
fn append_unsigned_off_policy_fixture() -> Result<()> {
    let output = PathBuf::from(
        std::env::var("ZARK_LINEAGE_FIXTURE_OUT")
            .context("set existing synthetic fixture directory")?,
    );
    let manifest: Value = serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    ensure!(
        manifest["source"] == SOURCE && manifest["server_secrets_persisted"] == false,
        "unexpected fixture source"
    );
    let recovery: Value = serde_json::from_slice(&fs::read(output.join("bob/recovery.json"))?)?;
    write_json(
        &output.join("bob/off-policy-recovery.json"),
        &off_policy_recovery(&recovery)?,
    )?;
    println!("Unsigned off-policy fixture added; no partial created.");
    Ok(())
}
