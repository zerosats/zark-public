use anyhow::{Result, ensure};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
    hashes::Hash,
    secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature},
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction,
};

pub fn p2tr(output_key: &[u8; 32]) -> ScriptBuf {
    let mut script = vec![0x51, 0x20];
    script.extend(output_key);
    ScriptBuf::from_bytes(script)
}

pub fn backup(
    outpoint: OutPoint,
    amount: u64,
    fee: u64,
    destination: [u8; 32],
    locktime: u32,
) -> Result<Transaction> {
    ensure!(
        locktime > 0 && locktime <= 65535,
        "block-relative delay required"
    );
    ensure!(
        fee > 0 && fee <= 10_000 && amount > fee + 330 && amount <= 2_100_000_000_000_000,
        "fee/amount bounds"
    );
    Ok(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence(locktime),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount - fee),
            script_pubkey: p2tr(&destination),
        }],
    })
}

pub fn cooperative_exit(
    outpoint: OutPoint,
    amount: u64,
    fee: u64,
    destination: [u8; 32],
) -> Result<Transaction> {
    ensure!(
        fee > 0 && fee <= 10_000 && amount > fee + 330 && amount <= 2_100_000_000_000_000,
        "fee/amount bounds"
    );
    Ok(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount - fee),
            script_pubkey: p2tr(&destination),
        }],
    })
}

pub fn sighash(tx: &Transaction, amount: u64, output_key: [u8; 32]) -> Result<[u8; 32]> {
    let prev = [TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: p2tr(&output_key),
    }];
    Ok(SighashCache::new(tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prev), TapSighashType::Default)?
        .to_byte_array())
}

pub fn activation(
    input: OutPoint,
    amount: u64,
    outputs: &[(u64, [u8; 32])],
    delay: u32,
) -> Result<Transaction> {
    ensure!(outputs.len() == 1, "activation requires exactly one output");
    ensure!(amount <= 2_100_000_000_000_000, "amount bound");
    let sum = outputs.iter().try_fold(0u64, |sum, (value, _)| {
        ensure!(*value > 330, "child dust");
        sum.checked_add(*value)
            .ok_or_else(|| anyhow::anyhow!("amount overflow"))
    })?;
    ensure!(sum < amount && amount - sum <= 10_000, "activation fee");
    ensure!(delay == 0, "activation delay must be zero");
    Ok(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: input,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs
            .iter()
            .map(|(v, k)| TxOut {
                value: Amount::from_sat(*v),
                script_pubkey: p2tr(k),
            })
            .collect(),
    })
}

pub fn attach_signature(
    tx: &mut Transaction,
    amount: u64,
    key: [u8; 32],
    sig: &[u8; 64],
) -> Result<()> {
    ensure!(
        tx.input.len() == 1 && tx.input[0].witness.is_empty(),
        "unsigned single-input transaction required"
    );
    Secp256k1::verification_only().verify_schnorr(
        &Signature::from_slice(sig)?,
        &Message::from_digest(sighash(tx, amount, key)?),
        &XOnlyPublicKey::from_slice(&key)?,
    )?;
    tx.input[0].witness.push(sig);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_amount_and_relative_delay_bounds_reject_overflows() -> Result<()> {
        let outpoint = OutPoint::null();
        let destination = [1; 32];
        for fee in [0, 10_001, u64::MAX - 329, u64::MAX] {
            assert!(backup(outpoint, 50_000, fee, destination, 10).is_err());
        }
        for amount in [0, 1330, 2_100_000_000_000_001, u64::MAX] {
            assert!(backup(outpoint, amount, 1000, destination, 10).is_err());
        }
        for delay in [0, 65536, 1 << 22, 1 << 31, u32::MAX] {
            assert!(backup(outpoint, 50_000, 1000, destination, delay).is_err());
        }
        for delay in [1, 65535] {
            let tx = backup(outpoint, 50_000, 1000, destination, delay)?;
            assert_eq!(tx.input[0].sequence.to_consensus_u32(), delay);
            // BIP68-compatible block delays also signal BIP125 replacement;
            // SIGHASH_DEFAULT still commits to the exact fixed outputs.
            assert!(tx.input[0].sequence.to_consensus_u32() < 0xffff_fffe);
        }
        assert!(
            activation(
                outpoint,
                50_000,
                &[(u64::MAX, destination), (u64::MAX, destination)],
                10
            )
            .is_err()
        );
        assert!(
            activation(
                outpoint,
                50_000,
                &[(25_000, destination), (25_000, destination)],
                10
            )
            .is_err()
        );
        assert!(
            activation(
                outpoint,
                50_000,
                &[(24_500, destination), (24_500, destination)],
                u32::MAX
            )
            .is_err()
        );
        assert!(activation(outpoint, 50_000, &[(49_000, destination)], 1).is_err());
        Ok(())
    }

    #[test]
    fn activation_keeps_one_exact_output_and_rejects_split_even_with_valid_value() -> Result<()> {
        let outpoint = OutPoint::null();
        let destination = [1; 32];
        let tx = activation(outpoint, 50_000, &[(49_000, destination)], 0)?;
        assert_eq!(tx.version, transaction::Version::TWO);
        assert_eq!(tx.lock_time, absolute::LockTime::ZERO);
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output, outpoint);
        assert_eq!(tx.input[0].sequence, Sequence::MAX);
        assert!(tx.input[0].script_sig.is_empty() && tx.input[0].witness.is_empty());
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), 49_000);
        assert_eq!(tx.output[0].script_pubkey, p2tr(&destination));
        for delay in [0, 10] {
            assert!(activation(outpoint, 50_000, &[(24_500, destination); 2], delay).is_err());
        }
        assert!(activation(outpoint, 50_000, &[], 0).is_err());
        assert!(activation(outpoint, 50_000, &[(16_000, destination); 3], 0).is_err());
        Ok(())
    }

    #[test]
    fn signature_attachment_rejects_wrong_input_shape_before_indexing() -> Result<()> {
        let mut tx = backup(OutPoint::null(), 50_000, 1000, [1; 32], 10)?;
        tx.input.clear();
        assert!(attach_signature(&mut tx, 50_000, [1; 32], &[0; 64]).is_err());
        tx = backup(OutPoint::null(), 50_000, 1000, [1; 32], 10)?;
        tx.input[0].witness.push([0; 64]);
        assert!(attach_signature(&mut tx, 50_000, [1; 32], &[0; 64]).is_err());
        Ok(())
    }

    #[test]
    fn cooperative_exit_has_a_final_sequence_and_exact_fee() -> Result<()> {
        let tx = cooperative_exit(OutPoint::null(), 50_000, 1_000, [2; 32])?;
        assert_eq!(tx.input[0].sequence, Sequence::MAX);
        assert_eq!(tx.output[0].value.to_sat(), 49_000);
        assert!(cooperative_exit(OutPoint::null(), 50_000, 0, [2; 32]).is_err());
        Ok(())
    }
}
