//! Native certificate/codec tests. Synthetic proof bytes are never verified as a proof.
use anyhow::Result;
use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
use zark_protocol::{
    bootstrap::BootstrapBinding,
    certificate::{IssuedOriginRecord, OwnerCertificate, issued_lineage},
    deposit::DepositBinding,
    handoff::{OperationScope, SigningBinding, TransferContext, origin_previous_state},
    lineage::{IssuanceBinding, ROLE_COUNT},
    point_bytes,
    proof::PROOF_BYTES,
    wire::{Command, Request},
};

fn fixture() -> Result<(DepositBinding, SigningKey, SigningKey)> {
    let session = SigningKey::from_bytes(&[7; 32])?;
    let origin = SigningKey::from_bytes(&[8; 32])?;
    let context = TransferContext {
        deployment: [1; 32],
        coin: [2; 32],
        previous_state: origin_previous_state(&[1; 32], &[2; 32])?,
        operation: [3; 32],
        recipient_claim: [4; 32],
        session_auth: session.verifying_key().to_bytes().into(),
        start_revision: 0,
        scope: OperationScope::Single,
    };
    let server = point_bytes(ProjectivePoint::GENERATOR * Scalar::from(12u64))?;
    let mut roles = [[0; 32]; ROLE_COUNT];
    for (i, role) in roles.iter_mut().enumerate() {
        role[31] = (i + 1) as u8;
    }
    let authorization = IssuanceBinding {
        signing: SigningBinding {
            context: context.clone(),
            funding: [5; 32],
            refresh_commitment: [6; 32],
            previous_capability: [7; 32],
            next_capability: [8; 32],
            recovery: [9; 32],
            nonce_commitment: [10; 32],
            draft_server: server,
            server_nonce: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(13u64))?,
            blinded_challenge: Scalar::from(14u64).to_bytes().into(),
        },
        policy: [11; 32],
        origin_key: origin.verifying_key().to_bytes().into(),
        role_hashes: roles,
    };
    let bootstrap = BootstrapBinding {
        context,
        parent_funding: [12; 32],
        active_funding: [5; 32],
        initial_capability: [8; 32],
        parent_server: server,
        active_server: server,
        nonce_commitment: [13; 32],
        parent_nonce: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(15u64))?,
        blinded_challenge: Scalar::from(16u64).to_bytes().into(),
    };
    Ok((
        DepositBinding {
            authorization,
            bootstrap,
        },
        session,
        origin,
    ))
}

#[test]
fn deposit_binds_both_authorizations_and_rejects_cross_coin_or_nonce_reuse() -> Result<()> {
    let (binding, _, _) = fixture()?;
    let bytes = binding.encode()?;
    assert_eq!(bytes.len(), 1466);
    assert_eq!(binding.public_inputs()?, bytes);
    assert_eq!(DepositBinding::decode(&bytes)?.digest()?, binding.digest()?);
    assert!(DepositBinding::decode(&bytes[..1465]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(DepositBinding::decode(&trailing).is_err());
    for change in 0..7 {
        let mut b = DepositBinding::decode(&bytes)?;
        match change {
            0 => b.bootstrap.context.operation[0] ^= 1,
            1 => b.bootstrap.active_funding[0] ^= 1,
            2 => b.bootstrap.initial_capability[0] ^= 1,
            3 => {
                b.bootstrap.parent_server =
                    point_bytes(ProjectivePoint::GENERATOR * Scalar::from(17u64))?;
                b.bootstrap.active_server = b.bootstrap.parent_server;
            }
            4 => b.bootstrap.parent_nonce = b.authorization.signing.server_nonce,
            5 => b.bootstrap.nonce_commitment = b.authorization.signing.nonce_commitment,
            _ => {
                b.bootstrap.context.start_revision = 1;
                b.authorization.signing.context.start_revision = 1;
            }
        }
        assert!(b.encode().is_err(), "change {change}");
    }
    Ok(())
}

#[test]
fn origin_certificate_requires_both_responses_and_authenticated_attestation() -> Result<()> {
    let (binding, session, origin) = fixture()?;
    let partial = Scalar::from(13u64 + 14 * 12).to_bytes().into();
    let activation_partial = Scalar::from(15u64 + 16 * 12).to_bytes().into();
    let salt = [19; 32];
    let lineage = issued_lineage(&binding.authorization, partial, salt)?;
    let signature = origin
        .sign_raw(&lineage.origin_message()?, &[0; 32])?
        .to_bytes()
        .to_vec();
    let proof = vec![0; PROOF_BYTES];
    let make = || OwnerCertificate::OriginIssued {
        authorization: binding.encode().unwrap(),
        proof: proof.clone(),
        partial,
        activation_partial,
        server_salt: salt,
        origin_signature: signature.clone(),
    };
    let cert = make();
    assert_eq!(cert.lineage_binding()?.state, lineage.state);
    assert_eq!(
        OwnerCertificate::decode_private(&cert.encode_private()?)?
            .lineage_binding()?
            .state,
        lineage.state
    );
    for change in 0..5 {
        let mut bad = make();
        if let OwnerCertificate::OriginIssued {
            partial,
            activation_partial,
            server_salt,
            origin_signature,
            authorization,
            ..
        } = &mut bad
        {
            match change {
                0 => partial[31] ^= 1,
                1 => activation_partial[31] ^= 1,
                2 => server_salt[0] ^= 1,
                3 => origin_signature[0] ^= 1,
                _ => {
                    let mut d = DepositBinding::decode(authorization)?;
                    d.authorization.origin_key = SigningKey::from_bytes(&[21; 32])?
                        .verifying_key()
                        .to_bytes()
                        .into();
                    *authorization = d.encode()?;
                }
            }
        }
        assert!(bad.lineage_binding().is_err(), "change {change}");
    }
    let request = Request::sign(
        binding.authorization.signing.context.clone(),
        Command::IssueDeposit {
            statement: binding.encode()?,
            proof,
        },
        &session,
    )?;
    let record = IssuedOriginRecord::from_request(
        &request,
        &binding,
        partial,
        activation_partial,
        salt,
        lineage.state,
        signature,
    )?;
    let identity = record.identity()?;
    for change in 0..5 {
        let mut altered = record.clone();
        match change {
            0 => altered.activation_partial[31] ^= 1,
            1 => altered.partial[31] ^= 1,
            2 => altered.origin_signature[0] ^= 1,
            3 => altered.request_digest[0] ^= 1,
            _ => altered.state[0] ^= 1,
        }
        assert_ne!(altered.identity()?, identity);
    }
    Ok(())
}
