//! Canonical bounded signer-coordinated atomic transfer manifest.
use crate::{
    handoff::{Digest, TransferContext},
    hash,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub const MAX_BATCH_MEMBERS: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub coin: Digest,
    pub previous_state: Digest,
    pub operation: Digest,
    pub recipient_claim: Digest,
    pub sender_session: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub id: Digest,
    pub deployment: Digest,
    pub expires_at: u64,
    /// Strict coin-ID order gives the same digest to both peers.
    #[serde(deserialize_with = "bounded_members")]
    pub members: Vec<Member>,
}

fn bounded_members<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Member>, D::Error> {
    struct Members;
    impl<'de> serde::de::Visitor<'de> for Members {
        type Value = Vec<Member>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("two to ten batch members")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            let mut members = Vec::with_capacity(MAX_BATCH_MEMBERS);
            while let Some(member) = sequence.next_element()? {
                if members.len() == MAX_BATCH_MEMBERS {
                    return Err(serde::de::Error::custom("too many batch members"));
                }
                members.push(member);
            }
            if members.len() < 2 {
                return Err(serde::de::Error::custom("too few batch members"));
            }
            Ok(members)
        }
    }
    deserializer.deserialize_seq(Members)
}

impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.id != [0; 32] && self.deployment != [0; 32],
            "empty batch identity"
        );
        ensure!(
            (2..=MAX_BATCH_MEMBERS).contains(&self.members.len()),
            "batch must contain between two and ten members"
        );
        ensure!(
            self.members
                .windows(2)
                .all(|pair| pair[0].coin < pair[1].coin),
            "batch members must have distinct sorted coin IDs"
        );
        let operations: std::collections::BTreeSet<_> =
            self.members.iter().map(|member| member.operation).collect();
        ensure!(
            operations.len() == self.members.len(),
            "duplicate batch operation"
        );
        ensure!(self.expires_at > 0, "empty batch expiry");
        for m in &self.members {
            ensure!(m.revision > 0, "empty batch revision");
            for field in [
                m.coin,
                m.previous_state,
                m.operation,
                m.recipient_claim,
                m.sender_session,
            ] {
                ensure!(field != [0; 32], "empty batch member field");
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest> {
        self.validate()?;
        Ok(hash(&[
            b"ZARK/multi-coin-batch/manifest/v2",
            &serde_json::to_vec(self)?,
        ]))
    }

    pub fn index(&self, ctx: &TransferContext, sender: bool) -> Result<usize> {
        self.validate()?;
        ensure!(
            ctx.deployment == self.deployment
                && ctx.scope
                    == crate::handoff::OperationScope::Batch {
                        manifest_digest: self.digest()?
                    },
            "batch deployment mismatch"
        );
        let i = self
            .members
            .iter()
            .position(|m| m.coin == ctx.coin)
            .ok_or_else(|| anyhow::anyhow!("coin absent from batch"))?;
        let m = &self.members[i];
        ensure!(
            ctx.start_revision == m.revision
                && ctx.previous_state == m.previous_state
                && ctx.operation == m.operation
                && ctx.recipient_claim == m.recipient_claim,
            "batch intent differs from request"
        );
        if sender {
            ensure!(
                ctx.session_auth == m.sender_session,
                "batch sender session mismatch"
            );
        }
        Ok(i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(count: usize) -> Manifest {
        Manifest {
            id: [1; 32],
            deployment: [2; 32],
            expires_at: 1,
            members: (0..count)
                .map(|index| Member {
                    coin: [index as u8 + 1; 32],
                    previous_state: [3; 32],
                    operation: [index as u8 + 20; 32],
                    recipient_claim: [5; 32],
                    sender_session: [6; 32],
                    revision: 1,
                })
                .collect(),
        }
    }

    #[test]
    fn generalized_manifest_is_bounded_canonical_and_binds_every_member() -> Result<()> {
        for count in 2..=MAX_BATCH_MEMBERS {
            let original = manifest(count);
            let bytes = serde_json::to_vec(&original)?;
            assert!(bytes.len() < 64 * 1024);
            let decoded: Manifest = serde_json::from_slice(&bytes)?;
            assert_eq!(original, decoded);
            let digest = original.digest()?;
            for index in 0..count {
                let mut altered = original.clone();
                altered.members[index].recipient_claim = [99; 32];
                assert_ne!(digest, altered.digest()?);
                altered = original.clone();
                altered.members[index].revision += 1;
                assert_ne!(digest, altered.digest()?);
            }
        }
        for count in [0, 1, 11] {
            let invalid = manifest(count);
            assert!(invalid.validate().is_err());
            assert!(serde_json::from_slice::<Manifest>(&serde_json::to_vec(&invalid)?).is_err());
        }
        let original = manifest(10);
        let mut invalid = original.clone();
        invalid.members.swap(0, 9);
        assert!(invalid.validate().is_err());
        invalid = original.clone();
        invalid.members[9].coin = invalid.members[8].coin;
        assert!(invalid.validate().is_err());
        invalid = original;
        invalid.members[9].operation = invalid.members[0].operation;
        assert!(invalid.validate().is_err());
        Ok(())
    }
}
