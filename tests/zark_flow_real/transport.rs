//! Durable signer transport that reopens storage on every request.
use super::*;

pub(super) struct DeploymentAdmission(Digest);
impl Admission for DeploymentAdmission {
    fn authorize(&self, context: &TransferContext) -> Result<()> {
        ensure!(context.deployment == self.0, "wrong integration deployment");
        Ok(())
    }
}

struct NoBatchTip;
impl zark_signer::engine::BatchTip for NoBatchTip {
    fn current_tip(&self) -> Result<Digest> {
        anyhow::bail!("single-coin test transport has no batch tip")
    }
}

/// The keys belong to this synthetic test server, never a client proof witness.
pub(super) struct DurableSigner<'a> {
    pub(super) run: PathBuf,
    pub(super) config: &'a Config,
    pub(super) manifest: &'a Manifest,
    pub(super) deployment: Deployment,
    pub(super) policy: LineagePolicy,
    pub(super) control: SigningKey,
    pub(super) origin: SigningKey,
    pub(super) calls: RefCell<BTreeMap<String, usize>>,
}

impl DurableSigner<'_> {
    fn request_once(&self, request: &Request) -> Result<Value> {
        self.open()?.handle_guarded(request, || Ok(()))
    }

    pub(super) fn open(&self) -> Result<Engine> {
        Engine::open(
            &self.run.join("server/signer.sqlite"),
            &self.run.join("checkpoint/floor.json"),
            self.policy.clone(),
            verifier(self.config, self.manifest, &self.deployment)?,
            Arc::new(DeploymentAdmission(self.policy.deployment)),
            Arc::new(NoBatchTip),
            self.control.clone(),
            self.origin.clone(),
        )
    }
}

impl SignerClient for DurableSigner<'_> {
    fn request(&self, request: &Request) -> Result<Value> {
        let wire = request.encode()?;
        let decoded = Request::decode(&wire)?;
        let response = self.request_once(&decoded)?;
        // Every mutation is retried after full engine teardown and floor reload.
        // This verifies exact durable response recovery with the real proof path.
        if !matches!(&decoded.command, WireCommand::Head { .. }) {
            let replay = self.request_once(&Request::decode(&wire)?)?;
            ensure!(
                replay == response,
                "durable signer retry changed its response"
            );
        }
        *self
            .calls
            .borrow_mut()
            .entry(format!("{:?}", decoded.command.purpose()))
            .or_default() += 1;
        Ok(response)
    }
}
