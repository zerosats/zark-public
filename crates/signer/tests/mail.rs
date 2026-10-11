use anyhow::Result;
use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint, schnorr::SigningKey};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};
use zark_protocol::{
    address::{AddressNetwork, ReceivingAddress},
    hash,
    mail::{Request, registration_digest},
    random32,
};
use zark_signer::mail::{Config, Service};

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("zark-mail-{}", hex::encode(random32()))))
    }
    fn config(&self) -> Config {
        Config {
            directory: self.0.clone(),
            requests_per_minute: 600,
            max_inflight: 2,
            peer_max_inflight: 2,
            peer_requests_per_minute: 240,
        }
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn call(
    s: &Service,
    method: &str,
    path: &str,
    body: Value,
    token: Option<&str>,
    now: u64,
) -> Value {
    s.handle(
        Request {
            version: 1,
            method: method.into(),
            path: path.into(),
            body,
            bearer: token.map(str::to_owned),
        },
        now,
    )
}
fn account(n: u8) -> (ReceivingAddress, SigningKey, String, String) {
    let k = SigningKey::from_bytes(&[n; 32]).unwrap();
    let envelope = SecretKey::from_slice(&[n + 30; 32])
        .unwrap()
        .public_key()
        .to_encoded_point(true);
    let mut claim = [0; 33];
    claim[0] = 2;
    claim[1..].copy_from_slice(&k.verifying_key().to_bytes());
    let address = ReceivingAddress::new(
        AddressNetwork::Test,
        [1; 32],
        envelope.as_bytes().try_into().unwrap(),
        claim,
    )
    .unwrap();
    let id = hex::encode(hash(&[address.encode().as_bytes()]));
    (address, k, hex::encode([n; 32]), id)
}
fn registration(a: &ReceivingAddress, k: &SigningKey, token: &str, ttl: u64) -> Value {
    let token_hash = hex::encode(hash(&[token.as_bytes()]));
    let sig = k
        .sign_raw(
            &registration_digest(a, &token_hash, ttl).unwrap(),
            &random32(),
        )
        .unwrap();
    json!({"receiveAddress":a.encode(),"readTokenHash":token_hash,"ttlMs":ttl,"signature":hex::encode(sig.to_bytes())})
}
#[test]
fn mailbox_possession_encrypted_only_replay_restart_and_expiry() -> Result<()> {
    let home = Home::new();
    let s = Service::open(&home.config(), [1; 32])?;
    let (a, k, token, id) = account(1);
    let body = registration(&a, &k, &token, 10000);
    let mut forged = body.clone();
    forged["readTokenHash"] = "ff".repeat(32).into();
    assert_eq!(
        call(&s, "POST", "/v1/mailboxes", forged, None, 100)["ok"],
        false
    );
    let first = call(&s, "POST", "/v1/mailboxes", body.clone(), None, 100);
    assert_eq!(first["ok"], true);
    assert_eq!(
        call(&s, "POST", "/v1/mailboxes", body.clone(), None, 200),
        first
    );
    let path = format!("/v1/mailboxes/{id}/messages");
    let ciphertext = "ab".repeat(100);
    let message = json!({"id":"01".repeat(32),"ciphertext":ciphertext});
    let mut malformed_id = message.clone();
    malformed_id["id"] = "not-a-digest".into();
    assert_eq!(
        call(&s, "POST", &path, malformed_id, None, 200)["ok"],
        false
    );
    let mut leaking = message.clone();
    leaking["amountSat"] = 10.into();
    assert_eq!(call(&s, "POST", &path, leaking, None, 200)["ok"], false);
    assert_eq!(
        call(&s, "POST", &path, message.clone(), None, 200)["ok"],
        true
    );
    assert_eq!(
        call(&s, "GET", &path, Value::Null, Some(&"ff".repeat(32)), 200)["error"]["code"],
        "unauthorized"
    );
    assert_eq!(
        call(&s, "GET", &path, Value::Null, Some(&token), 200)["result"]["messages"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    drop(s);
    let s = Service::open(&home.config(), [1; 32])?;
    assert_eq!(
        call(&s, "POST", &path, message.clone(), None, 300)["error"]["code"],
        "message_replayed"
    );
    assert_eq!(
        call(
            &s,
            "DELETE",
            &format!("{path}/{}", "01".repeat(32)),
            Value::Null,
            Some(&token),
            300
        )["ok"],
        true
    );
    assert_eq!(
        call(&s, "POST", &path, message.clone(), None, 400)["error"]["code"],
        "message_replayed"
    );
    let mut different = message;
    different["ciphertext"] = "cd".repeat(100).into();
    assert_eq!(
        call(&s, "POST", &path, different, None, 400)["error"]["code"],
        "message_conflict"
    );
    assert_eq!(
        call(&s, "POST", "/v1/mailboxes", body, None, 20000)["error"]["code"],
        "mailbox_expired"
    );
    drop(s);
    assert!(Service::open(&home.config(), [2; 32]).is_err());
    Ok(())
}
#[test]
fn offer_claim_is_exclusive_authenticated_and_durable() -> Result<()> {
    let home = Home::new();
    let s = Service::open(&home.config(), [1; 32])?;
    let (a, ak, at, ai) = account(2);
    let (b, bk, bt, bi) = account(3);
    let (c, ck, ct, ci) = account(4);
    for (a, k, t) in [(&a, &ak, &at), (&b, &bk, &bt), (&c, &ck, &ct)] {
        assert_eq!(
            call(
                &s,
                "POST",
                "/v1/mailboxes",
                registration(a, k, t, 10000),
                None,
                100
            )["ok"],
            true
        );
    }
    let owner = "dd".repeat(32);
    let claim = "ee".repeat(32);
    let offer = json!({"amountSat":50000,"receiveAddress":a.encode(),"addressHash":ai,"ownerTokenHash":hex::encode(hash(&[owner.as_bytes()]))});
    assert_eq!(
        call(&s, "POST", "/v1/offers", offer.clone(), Some(&bt), 100)["error"]["code"],
        "unauthorized"
    );
    let created = call(&s, "POST", "/v1/offers", offer.clone(), Some(&at), 100);
    assert_eq!(created["ok"], true);
    assert_eq!(
        call(&s, "POST", "/v1/offers", offer, Some(&at), 101),
        created
    );
    let path = format!("/v1/offers/{}", created["result"]["id"].as_str().unwrap());
    let request = json!({"receiveAddress":b.encode(),"addressHash":bi,"claimTokenHash":hex::encode(hash(&[claim.as_bytes()]))});
    assert_eq!(
        call(
            &s,
            "POST",
            &format!("{path}/claim"),
            request.clone(),
            Some(&bt),
            102
        )["ok"],
        true
    );
    let other = json!({"receiveAddress":c.encode(),"addressHash":ci,"claimTokenHash":hex::encode(hash(&[ct.as_bytes()]))});
    assert_eq!(
        call(&s, "POST", &format!("{path}/claim"), other, Some(&ct), 103)["error"]["code"],
        "offer_unavailable"
    );
    assert_eq!(
        call(&s, "GET", "/v1/offers", Value::Null, None, 103)["result"]["offers"],
        json!([])
    );
    drop(s);
    let s = Service::open(&home.config(), [1; 32])?;
    assert_eq!(
        call(
            &s,
            "POST",
            &format!("{path}/claim"),
            request,
            Some(&bt),
            104
        )["ok"],
        true
    );
    assert_eq!(
        call(&s, "DELETE", &path, Value::Null, Some(&owner), 104)["error"]["code"],
        "offer_claimed"
    );
    assert_eq!(
        call(&s, "GET", &path, Value::Null, Some(&claim), 104)["result"]["claim"]["addressHash"],
        bi
    );
    let public = call(&s, "GET", &path, Value::Null, Some(&owner), 104).to_string();
    assert!(!public.contains("TokenHash"));
    Ok(())
}
#[test]
fn multi_coin_offer_requires_matching_handshake_before_claim() -> Result<()> {
    let home = Home::new();
    let s = Service::open(&home.config(), [1; 32])?;
    let (a, ak, at, ai) = account(10);
    let (b, bk, bt, bi) = account(11);
    for (a, k, token) in [(&a, &ak, &at), (&b, &bk, &bt)] {
        assert_eq!(
            call(
                &s,
                "POST",
                "/v1/mailboxes",
                registration(a, k, token, 10000),
                None,
                100
            )["ok"],
            true
        );
    }
    let owner = "dc".repeat(32);
    let offer = json!({"amountSat":45000,"swapVersion":2,"receiveAddress":a.encode(),"addressHash":ai,"ownerTokenHash":hex::encode(hash(&[owner.as_bytes()]))});
    let mut unsupported = offer.clone();
    unsupported["swapVersion"] = 3.into();
    assert_eq!(
        call(&s, "POST", "/v1/offers", unsupported, Some(&at), 100)["ok"],
        false
    );
    let created = call(&s, "POST", "/v1/offers", offer.clone(), Some(&at), 100);
    assert_eq!(created["ok"], true);
    assert_eq!(created["result"]["swapVersion"], 2);
    let mut changed = offer.clone();
    changed["swapVersion"] = 1.into();
    assert_eq!(
        call(&s, "POST", "/v1/offers", changed, Some(&at), 101)["error"]["code"],
        "offer_terms_conflict"
    );
    let path = format!(
        "/v1/offers/{}/claim",
        created["result"]["id"].as_str().unwrap()
    );
    let mut claim =
        json!({"receiveAddress":b.encode(),"addressHash":bi,"claimTokenHash":"ef".repeat(32)});
    assert_eq!(
        call(&s, "POST", &path, claim.clone(), Some(&bt), 102)["error"]["code"],
        "unsupported_swap_version"
    );
    let public = call(&s, "GET", "/v1/offers", Value::Null, None, 102);
    assert_eq!(public["result"]["offers"][0]["status"], "open");
    assert_eq!(public["result"]["offers"][0]["swapVersion"], 2);
    claim["swapVersion"] = 2.into();
    assert_eq!(
        call(&s, "POST", &path, claim.clone(), Some(&bt), 103)["ok"],
        true
    );
    drop(s);
    let s = Service::open(&home.config(), [1; 32])?;
    assert_eq!(
        call(&s, "POST", &path, claim, Some(&bt), 104)["result"]["swapVersion"],
        2
    );
    assert_eq!(
        call(&s, "POST", "/v1/offers", offer, Some(&at), 104)["result"]["status"],
        "claimed"
    );
    Ok(())
}

#[test]
fn queued_messages_are_bounded_and_expired_messages_do_not_reappear() -> Result<()> {
    let home = Home::new();
    let s = Service::open(&home.config(), [1; 32])?;
    let (a, k, t, id) = account(5);
    call(
        &s,
        "POST",
        "/v1/mailboxes",
        registration(&a, &k, &t, 10000),
        None,
        100,
    );
    let path = format!("/v1/mailboxes/{id}/messages");
    for i in 0..32 {
        assert_eq!(
            call(
                &s,
                "POST",
                &path,
                json!({"id":format!("{i:064x}"),"ciphertext":"ab".repeat(100),"ttlMs":100}),
                None,
                100
            )["ok"],
            true
        );
    }
    assert_eq!(
        call(
            &s,
            "POST",
            &path,
            json!({"id":"ff".repeat(32),"ciphertext":"ab".repeat(100)}),
            None,
            150
        )["error"]["code"],
        "storage_quota"
    );
    assert_eq!(
        call(&s, "GET", &path, Value::Null, Some(&t), 201)["result"]["messages"],
        json!([])
    );
    assert_eq!(
        call(
            &s,
            "POST",
            &path,
            json!({"id":"00".repeat(32),"ciphertext":"ab".repeat(100),"ttlMs":100}),
            None,
            201
        )["error"]["code"],
        "message_replayed"
    );
    Ok(())
}
