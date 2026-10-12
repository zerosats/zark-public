//! Optional actual Chromium fetch/CORS smoke against the built-in HTTPS listener.
use super::*;
use std::process::{Command as Process, Stdio};

#[test]
#[ignore = "requires explicit ZARK_TEST_NODE and ZARK_TEST_PLAYWRIGHT, plus Chrome"]
fn browser_fetch_uses_https_preflight_and_rejects_unlisted_origins() -> Result<()> {
    let mut f = Fixture::new()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let page = TcpListener::bind("127.0.0.1:0")?;
    let page_port = page.local_addr()?.port();
    drop(page);
    let mut config: Value = serde_json::from_slice(&fs::read(&f.dispatch.path)?)?;
    config["browser"]["allowed_origins"] = json!([format!("http://127.0.0.1:{page_port}")]);
    config["browser"]["allowed_hosts"] = json!([format!("localhost:{}", address.port())]);
    fs::write(&f.dispatch.path, serde_json::to_vec(&config)?)?;
    Listener {
        socket: listener,
        tls: f.tls.clone(),
    }
    .start(f.dispatch.clone(), 2, 4);
    let mail_config = HostedConfig::load(&f.dispatch.path)?.messaging.unwrap();
    let (_, replacement) = mpsc::sync_channel(1);
    let mail = std::mem::replace(&mut f.mail, replacement);
    thread::spawn(move || {
        // The process lock is deliberately thread-bound, just as in the host.
        let service = crate::mail::Service::open(&mail_config, [1; 32]).unwrap();
        while let Ok(job) = mail.recv() {
            job.reply.reject(service.handle(job.request, 100));
        }
    });
    let node = std::env::var("ZARK_TEST_NODE")?;
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/check-browser-transport.mjs");
    let mut child = Process::new(node)
        .arg(script)
        .arg(format!("https://localhost:{}", address.port()))
        .arg(page_port.to_string())
        .arg(f.root.join("certificate.pem"))
        .stdin(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(45);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("browser fetch test deadline");
        }
        thread::sleep(Duration::from_millis(50));
    };
    anyhow::ensure!(status.success(), "browser fetch test failed");
    Ok(())
}
