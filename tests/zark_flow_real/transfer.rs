//! Real-proof transfer orchestration with privacy assertions.
use super::*;

#[allow(clippy::too_many_arguments)] // Explicit isolated test actors and trust inputs.
pub(super) fn transfer(
    sender: &mut SenderDraft,
    invitation: &mut LocalInvitation,
    directory: &Path,
    label: &str,
    proofs: &Proofs,
    verifier: &PinnedVerifier,
    scratch: &Path,
    client: &dyn SignerClient,
    chain: &ChainConfig,
    control: &Digest,
    policy: &LineagePolicy,
) -> Result<ReceiverJournal> {
    let jobs_before: usize = proofs.counts.borrow().values().sum();
    let step = |suffix: &str| format!("{label}-{suffix}");
    sender.reserve(verifier, scratch, client, chain)?;
    sender.write_sender_witness(&proofs.input(&step("sender")), verifier, scratch)?;
    let sender_role = match sender.sender_role()? {
        zark_protocol::proof::Relation::SenderFromOrigin => "sender_from_origin",
        zark_protocol::proof::Relation::SenderFromTransfer => "sender_from_transfer",
        _ => anyhow::bail!("invalid sender proof role"),
    };
    let handover = proofs.prove(sender_role, &step("sender"))?;
    sender.authorize_handover(&handover, verifier, scratch, client, chain)?;
    let context = OfferContext {
        deployment: sender.context().deployment,
        coin: sender.context().coin,
        operation: sender.context().operation,
    };
    let offer = sender.offer_bytes()?;
    let run = directory
        .parent()
        .context("recipient privacy run directory")?;
    let canaries = PrivacyCanaries::capture(run, label)?;
    check_peer_schema(invitation, &context, &offer, &canaries)?;
    let mut hidden = HiddenPredecessors::hide(run, label)?;
    let hidden_count = hidden.moves.len();
    let receiver = ReceiverJournal::prepare(directory, invitation, &context, &offer, policy)?;
    drop(receiver);
    let mut receiver = ReceiverJournal::open(directory, invitation, &context, policy)?;
    receiver.authorize_and_reserve(invitation, verifier, scratch)?;
    receiver.claim(client)?;
    receiver.prepare_with_signer(1_000, client)?;
    invitation.write_receiver_authorization_witness(
        &receiver,
        verifier,
        scratch,
        &proofs.input(&step("issuance")),
    )?;
    let issuance = proofs.prove("receiver_authorization", &step("issuance"))?;
    let response_received = RefCell::new(None);
    struct BadIssueMetadata<'a>(&'a dyn SignerClient, &'a RefCell<Option<Instant>>);
    impl SignerClient for BadIssueMetadata<'_> {
        fn request(&self, request: &Request) -> Result<Value> {
            let mut response = self.0.request(request)?;
            if matches!(request.command, WireCommand::Issue { .. }) {
                *self.1.borrow_mut() = Some(Instant::now());
                response["capability"] = json!(vec![0; 32]);
            }
            Ok(response)
        }
    }
    ensure!(
        receiver
            .issue(
                &issuance,
                verifier,
                scratch,
                &BadIssueMetadata(client, &response_received),
                chain
            )
            .is_err(),
        "malformed issuance metadata accepted"
    );
    let recovery_saved_seconds = response_received
        .borrow()
        .context("issuance response was not received")?
        .elapsed()
        .as_secs_f64();
    ensure!(
        receiver.has_completed_recovery()?,
        "valid response scalar was discarded with bad metadata"
    );
    drop(receiver);
    let mut receiver = ReceiverJournal::open(directory, invitation, &context, policy)?;
    receiver.authorize_and_reserve(invitation, verifier, scratch)?;
    ensure!(
        receiver.has_completed_recovery()?,
        "recovery was not durable before certificate and acknowledgement"
    );
    let recovery = receiver.issue(&issuance, verifier, scratch, client, chain)?;
    ensure!(
        recovery.input.len() == 1 && !recovery.input[0].witness.is_empty(),
        "recipient recovery is not fully signed"
    );
    // A restart after irreversible issuance must retain the same own recovery.
    drop(receiver);
    let mut receiver = ReceiverJournal::open(directory, invitation, &context, policy)?;
    receiver.authorize_and_reserve(invitation, verifier, scratch)?;
    let replay = receiver.issue(&issuance, verifier, scratch, client, chain)?;
    ensure!(replay == recovery, "recipient restart changed its recovery");
    let certificate_started = Instant::now();
    receiver.freeze_certificate(verifier, scratch)?;
    let certificate_seconds = certificate_started.elapsed().as_secs_f64();
    // Neither a saved certificate nor an ACK may hold the recovery lock across
    // restart validation, and neither restart may generate another proof.
    drop(receiver);
    let mut receiver = ReceiverJournal::open(directory, invitation, &context, policy)?;
    receiver.authorize_and_reserve(invitation, verifier, scratch)?;
    let acknowledgement_started = Instant::now();
    let accepted = receiver.accept(verifier, scratch, client, chain, control)?;
    let acknowledgement_seconds = acknowledgement_started.elapsed().as_secs_f64();
    drop(receiver);
    let mut receiver = ReceiverJournal::open(directory, invitation, &context, policy)?;
    receiver.authorize_and_reserve(invitation, verifier, scratch)?;
    ensure!(
        receiver
            .accept(verifier, scratch, client, chain, control)?
            .encode()?
            == accepted.encode()?,
        "accepted recipient restart changed the exact acknowledged state"
    );
    receiver.export_recovery(&directory.join("portable-recovery.json"))?;
    check_own_export(directory, receiver.context(), &recovery, &canaries)?;
    hidden.require_hidden()?;
    let receiver_records = canaries.artifacts(directory)?;
    let receiver_proof_inputs = canaries.artifacts(&proofs.owner_directory(&step("claim")))?;
    hidden.restore()?;
    ensure!(
        sender.complete(client)?,
        "sender did not retire after recipient acceptance"
    );
    proofs.privacy_checks.borrow_mut().push(json!({"transfer":label,"peer_offer_exact_schema":true,
        "predecessor_private_values_checked":canaries.values,"predecessor_directories_unavailable_during_recipient_proving":hidden_count,
        "recipient_record_text_artifacts_checked":receiver_records,"recipient_prover_text_artifacts_checked":receiver_proof_inputs,
        "export_only_common_activation_and_own_recovery":true,
        "scope":"synthetic raw-record canaries and predecessor-path independence, not OS isolation or a cryptographic noninterference proof"}));
    proofs.transfer_timings.borrow_mut().push(json!({
        "transfer":label,"response_received_to_durable_recovery_seconds":recovery_saved_seconds,
        "certificate_verification_and_save_seconds":certificate_seconds,
        "acknowledgement_with_fresh_head_and_chain_seconds":acknowledgement_seconds,
        "certificate_and_acknowledgement_restart_checked":true,
        "scope":"local release-profile shared-wire workflow; recovery timing includes proof reverification and malformed-metadata rejection"
    }));
    ensure!(
        proofs.counts.borrow().values().sum::<usize>() == jobs_before + 2,
        "fresh Plan C transfer must create exactly two proof jobs"
    );
    Ok(receiver)
}
