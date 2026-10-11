use super::*;
use zark_protocol::random32;

struct Fixture(std::path::PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn pin(root: &Path, name: &str) -> BinaryPin {
    let path = root.join(name);
    std::fs::write(&path, format!("synthetic {name}")).unwrap();
    BinaryPin {
        sha256: hex::encode(hash(&[&std::fs::read(&path).unwrap()])),
        path,
    }
}

fn runtime() -> (Fixture, FastRuntime) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("work")
        .join(format!("fast-runtime-{}", hex::encode(random32())));
    std::fs::create_dir_all(&root).unwrap();
    let runtime = FastRuntime {
        executor: pin(&root, "executor"),
        prover: pin(&root, "prover"),
        helper: pin(&root, "helper"),
        witness_threads: 8,
        prove_threads: 16,
        verify_threads: 8,
        extended_native_hints: false,
    };
    (Fixture(root), runtime)
}

#[test]
fn extended_hints_are_opt_in_and_preserve_existing_runtime_bytes() {
    let (_fixture, mut runtime) = runtime();
    let original = serde_json::to_value(&runtime).unwrap();
    assert!(original.get("extended_native_hints").is_none());
    let decoded: FastRuntime = serde_json::from_value(original.clone()).unwrap();
    assert!(!decoded.extended_native_hints);
    assert_eq!(serde_json::to_value(decoded).unwrap(), original);
    let identity = runtime.identity().unwrap();
    runtime.extended_native_hints = true;
    assert_ne!(runtime.identity().unwrap(), identity);
}

#[test]
fn the_helper_binary_is_authenticated_like_the_other_executables() {
    let (_fixture, runtime) = runtime();
    let assets = runtime.authenticate().unwrap();
    assets.check().unwrap();
    std::fs::write(&runtime.helper.path, b"changed helper").unwrap();
    assert!(assets.check().is_err());
    assert!(runtime.authenticate().is_err());
    let mut repinned = runtime.clone();
    repinned.helper.sha256 = hex::encode(hash(&[b"changed helper"]));
    repinned.authenticate().unwrap();
    assert_ne!(repinned.identity().unwrap(), runtime.identity().unwrap());
}

#[test]
fn retired_python_helper_configuration_is_rejected() {
    let (_fixture, runtime) = runtime();
    let mut value = serde_json::to_value(&runtime).unwrap();
    assert!(serde_json::from_value::<FastRuntime>(value.clone()).is_ok());
    for (key, legacy) in [
        ("python", serde_json::to_value(&runtime.executor).unwrap()),
        ("python_assets", serde_json::json!({})),
        ("helper_directory", serde_json::json!("/tmp")),
        ("helper_sha256", serde_json::json!({})),
    ] {
        let mut legacy_value = value.clone();
        legacy_value[key] = legacy;
        assert!(
            serde_json::from_value::<FastRuntime>(legacy_value).is_err(),
            "{key}"
        );
    }
    value.as_object_mut().unwrap().remove("helper");
    assert!(serde_json::from_value::<FastRuntime>(value).is_err());
}

#[test]
fn wallet_configurations_pinning_the_python_helper_are_named_explicitly() {
    let (_fixture, runtime) = runtime();
    let config = |fast_runtime| {
        serde_json::to_vec(&serde_json::json!({"version": 10, "fast_runtime": fast_runtime}))
            .unwrap()
    };
    FastRuntime::reject_retired(&config(serde_json::to_value(&runtime).unwrap())).unwrap();
    FastRuntime::reject_retired(br#"{"version": 10}"#).unwrap();
    FastRuntime::reject_retired(b"not json").unwrap();
    for key in RETIRED_KEYS {
        let mut legacy = serde_json::to_value(&runtime).unwrap();
        legacy.as_object_mut().unwrap().remove("helper");
        legacy[key] = serde_json::json!({});
        let error = FastRuntime::reject_retired(&config(legacy)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("retired Python fast-prover helper"),
            "{key}"
        );
    }
}

#[test]
fn worker_profiles_stay_bounded() {
    let (_fixture, runtime) = runtime();
    let edits: [fn(&mut FastRuntime); 3] = [
        |r| r.witness_threads = 0,
        |r| r.prove_threads = 65,
        |r| r.verify_threads = 9,
    ];
    for edit in edits {
        let mut changed = runtime.clone();
        edit(&mut changed);
        assert!(changed.authenticate().is_err());
    }
}

#[test]
fn helper_routing_matches_the_source_lock_native_roles() {
    let lock: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../runtime/fast-prover/source-lock.json"))
            .unwrap();
    let roles = lock["roles"].as_object().unwrap();
    assert_eq!(roles.len(), 6);
    for (role, pin) in roles {
        assert_eq!(
            super::needs_helper(role),
            pin["native"].as_bool().unwrap(),
            "{role}"
        );
    }
}
