//! Exercise the actual durable mailbox service through the browser TLS boundary.
use super::*;
use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use zark_protocol::{
    address::{AddressNetwork, ReceivingAddress},
    hash,
    mail::registration_digest,
};

fn call(
    f: &Fixture,
    service: &crate::mail::Service,
    method: &str,
    path: &str,
    body: Value,
    bearer: Option<&str>,
) -> Result<Value> {
    let response = f.request(
        "/v1/mail",
        &serde_json::to_string(&json!({
            "version":1,"method":method,"path":path,"body":body,"bearer":bearer,
        }))?,
    )?;
    let job = f.mail.recv_timeout(Duration::from_secs(2))?;
    let value = service.handle(job.request, 100);
    job.reply.reject(value.clone());
    let reply = response.join().unwrap()?;
    assert!(reply.starts_with("HTTP/1.1 200"));
    assert!(reply.contains(&format!("Access-Control-Allow-Origin: {ORIGIN}")));
    let decoded: Value = serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1)?;
    assert_eq!(decoded, value);
    Ok(decoded)
}

#[test]
fn registration_delivery_restart_replay_and_authenticated_ack_use_the_existing_store() -> Result<()>
{
    let f = Fixture::new()?;
    let config = HostedConfig::load(&f.dispatch.path)?.messaging.unwrap();
    let service = crate::mail::Service::open(&config, [1; 32])?;
    let key = SigningKey::from_bytes(&[11; 32])?;
    let envelope = SecretKey::from_slice(&[12; 32])?
        .public_key()
        .to_encoded_point(true);
    let mut claim = [2; 33];
    claim[1..].copy_from_slice(&key.verifying_key().to_bytes());
    let address = ReceivingAddress::new(
        AddressNetwork::Test,
        [1; 32],
        envelope.as_bytes().try_into()?,
        claim,
    )?;
    let token = "13".repeat(32);
    let token_hash = hex::encode(hash(&[token.as_bytes()]));
    let signature = key.sign_raw(
        &registration_digest(&address, &token_hash, 10000)?,
        &[14; 32],
    )?;
    let registration = json!({"receiveAddress":address.encode(),"readTokenHash":token_hash,
        "ttlMs":10000,"signature":hex::encode(signature.to_bytes())});
    let mut forged = registration.clone();
    forged["readTokenHash"] = json!("ff".repeat(32));
    assert_eq!(
        call(&f, &service, "POST", "/v1/mailboxes", forged, None)?["ok"],
        false
    );
    let first = call(
        &f,
        &service,
        "POST",
        "/v1/mailboxes",
        registration.clone(),
        None,
    )?;
    assert_eq!(first["ok"], true);
    assert_eq!(
        call(&f, &service, "POST", "/v1/mailboxes", registration, None)?,
        first
    );
    let id = hex::encode(hash(&[address.encode().as_bytes()]));
    let path = format!("/v1/mailboxes/{id}/messages");
    let message_id = "15".repeat(32);
    let message = json!({"id":message_id,"ciphertext":"ab".repeat(100)});
    assert_eq!(
        call(&f, &service, "POST", &path, message.clone(), None)?["ok"],
        true
    );
    // The send response is observed only after the durable store can be reopened.
    drop(service);
    let service = crate::mail::Service::open(&config, [1; 32])?;
    assert_eq!(
        call(
            &f,
            &service,
            "GET",
            &path,
            Value::Null,
            Some(&"ff".repeat(32))
        )?["error"]["code"],
        "unauthorized"
    );
    assert_eq!(
        call(&f, &service, "GET", &path, Value::Null, Some(&token))?["result"]["messages"][0]["id"],
        message_id
    );
    assert_eq!(
        call(&f, &service, "POST", &path, message.clone(), None)?["error"]["code"],
        "message_replayed"
    );
    let ack = format!("{path}/{message_id}");
    assert_eq!(
        call(
            &f,
            &service,
            "DELETE",
            &ack,
            Value::Null,
            Some(&"ff".repeat(32))
        )?["error"]["code"],
        "unauthorized"
    );
    assert_eq!(
        call(&f, &service, "DELETE", &ack, Value::Null, Some(&token))?["result"]["acknowledged"],
        true
    );
    drop(service);
    let service = crate::mail::Service::open(&config, [1; 32])?;
    assert_eq!(
        call(&f, &service, "DELETE", &ack, Value::Null, Some(&token))?["result"]["acknowledged"],
        true
    );
    assert_eq!(
        call(&f, &service, "POST", &path, message, None)?["error"]["code"],
        "message_replayed"
    );
    assert!(f.ordinary.try_recv().is_err() && f.recovered.try_recv().is_err());
    Ok(())
}
