//! Eight-owner relative recovery schedule and live transfer window.
use super::INITIAL_OWNER_LIMIT;
use anyhow::{Result, ensure};

/// Block-only BIP68 recovery sequence. Private fields prevent unchecked creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryDelay(u16);

impl RecoveryDelay {
    pub fn from_sequence(sequence: u32) -> Result<Self> {
        ensure!(
            (1..=65535).contains(&sequence),
            "invalid block recovery sequence"
        );
        Ok(Self(sequence as u16))
    }

    pub fn blocks(self) -> u32 {
        self.0 as u32
    }
}

/// Research-policy contract. No block-count choice is a network safety guarantee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoverySchedule {
    pub initial: u32,
    pub gap: u32,
    pub margin: u32,
}

impl RecoverySchedule {
    pub fn validate(self) -> Result<()> {
        RecoveryDelay::from_sequence(self.initial)?;
        RecoveryDelay::from_sequence(self.gap)?;
        ensure!(
            self.margin > 0 && self.margin < self.gap,
            "invalid recovery margin"
        );
        let consumed = (INITIAL_OWNER_LIMIT - 1)
            .checked_mul(self.gap)
            .ok_or_else(|| anyhow::anyhow!("recovery budget overflow"))?;
        ensure!(
            self.initial
                .checked_sub(consumed)
                .is_some_and(|d| d >= self.margin),
            "insufficient eight-owner recovery budget"
        );
        Ok(())
    }

    /// `transfers` is local derived data, not a required public signer counter.
    pub fn delay_after(self, transfers: u32) -> Result<RecoveryDelay> {
        self.validate()?;
        ensure!(
            transfers < INITIAL_OWNER_LIMIT,
            "eight-owner protocol bound"
        );
        RecoveryDelay::from_sequence(self.initial - transfers * self.gap)
    }

    pub fn check_transition(self, previous: RecoveryDelay, next: RecoveryDelay) -> Result<()> {
        self.validate()?;
        let elapsed = self
            .initial
            .checked_sub(previous.blocks())
            .ok_or_else(|| anyhow::anyhow!("recovery exceeds initial delay"))?;
        ensure!(
            elapsed % self.gap == 0,
            "predecessor is off the fixed schedule"
        );
        let transfers = elapsed / self.gap;
        ensure!(
            transfers + 1 < INITIAL_OWNER_LIMIT,
            "eight-owner protocol bound"
        );
        ensure!(
            self.delay_after(transfers + 1)? == next,
            "recovery decrement must equal gap"
        );
        Ok(())
    }

    /// For a *confirmed* common activation, the earliest valid recovery block is
    /// activation_height + sequence. `tip` must come from a fresh authenticated
    /// node observation of the same active chain. This does not check unspentness
    /// or signer freshness. Call immediately before authorization and acceptance.
    /// After issuance, an error calls for recovery, never predecessor rollback.
    pub fn confirmed_transfer_window(
        self,
        previous: RecoveryDelay,
        next: RecoveryDelay,
        activation_height: u32,
        tip: u32,
        required_confirmations: u32,
    ) -> Result<TransferWindow> {
        self.check_transition(previous, next)?;
        ensure!(
            activation_height <= tip,
            "activation is not confirmed at this tip"
        );
        ensure!(
            required_confirmations > 0,
            "positive confirmations required"
        );
        let activation = u64::from(activation_height);
        let previous_maturity = activation + u64::from(previous.blocks());
        let next_maturity = activation + u64::from(next.blocks());
        let earliest_next_confirmation = (u64::from(tip) + 1).max(next_maturity);
        let last_required_confirmation =
            earliest_next_confirmation + u64::from(required_confirmations) - 1;
        ensure!(
            last_required_confirmation + u64::from(self.margin) <= previous_maturity,
            "relative recovery safety margin exhausted"
        );
        Ok(TransferWindow {
            previous_maturity,
            next_maturity,
            earliest_next_confirmation,
            last_required_confirmation,
            remaining_margin: previous_maturity - last_required_confirmation,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferWindow {
    pub previous_maturity: u64,
    pub next_maturity: u64,
    pub earliest_next_confirmation: u64,
    pub last_required_confirmation: u64,
    pub remaining_margin: u64,
}
