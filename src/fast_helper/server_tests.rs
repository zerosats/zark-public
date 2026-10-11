use super::*;

fn port(args: &[&str]) -> Option<u16> {
    port_argument(args.iter().map(OsString::from))
}

#[test]
fn port_arguments_match_the_reference_command_line() {
    assert_eq!(port(&[]), Some(0));
    assert_eq!(port(&["--port", "0"]), Some(0));
    assert_eq!(port(&["--port=8080"]), Some(8080));
    assert_eq!(port(&["--port", "1", "--port", "65535"]), Some(65535));
    for bad in [
        &["--port"][..],
        &["--port", "65536"],
        &["--port", "-1"],
        &["--port", ""],
        &["--port", "+1"],
        &["--port=x"],
        &["--other"],
        &["0"],
    ] {
        assert_eq!(port(bad), None, "{bad:?}");
    }
}

#[test]
fn binding_is_loopback_only_with_an_ephemeral_port() {
    let (listener, port) = bind(0).unwrap();
    assert_ne!(port, 0);
    assert_eq!(
        listener.local_addr().unwrap(),
        SocketAddr::from((BIND, port))
    );
    // Without SO_REUSEADDR a second listener cannot share the port.
    assert!(bind(port).is_err());
}
