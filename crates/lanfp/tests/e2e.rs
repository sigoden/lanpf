//! Loopback end-to-end tests: two daemons, authorization, sessions, forwarding and
//! the CLI surface.
#![cfg(unix)]

use lanfp_core::frame::{read_json, write_json};
use lanfp_core::ipc::*;
use lanfp_core::protocol::{ExposeMode, PortRange, RuleState};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::net::UnixStream;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lanfp"))
}

fn run_cli(args: &[&str]) -> std::process::Output {
    StdCommand::new(bin())
        .args(args)
        .output()
        .expect("run lanfp cli")
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

struct Node {
    home: TempDir,
    port: u16,
    child: Child,
}

impl Node {
    async fn start() -> Node {
        Self::start_with_expose_ports(&[]).await
    }

    /// Start with `agent.expose_ports` (the exposure whitelist) preset to
    /// `entries` before the daemon boots.
    async fn start_with_expose_ports(entries: &[String]) -> Node {
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("config")).unwrap();
        let port = free_port();
        let whitelist = entries
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config = format!(
            "[agent]\nlisten = \"127.0.0.1:{port}\"\nexpose_ports = [{whitelist}]\n\n[discovery]\nmdns = false\n\n[inventory]\ninterval_ms = 200\n"
        );
        std::fs::write(home.path().join("config/config.toml"), config).unwrap();
        let log = std::fs::File::create(home.path().join("serve.log")).unwrap();
        let child = StdCommand::new(bin())
            .arg("serve")
            .env("LANFP_HOME", home.path())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn lanfp serve");
        let node = Node { home, port, child };
        node.wait_ipc().await;
        node
    }

    fn socket(&self) -> PathBuf {
        self.home.path().join("run/ctl.sock")
    }

    async fn wait_ipc(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if UnixStream::connect(self.socket()).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!(
            "daemon did not start; log:\n{}",
            std::fs::read_to_string(self.home.path().join("serve.log")).unwrap_or_default()
        );
    }

    async fn call(&self, command: Command) -> Response {
        let mut stream = UnixStream::connect(self.socket())
            .await
            .expect("connect ipc");
        let request = Request {
            id: 42,
            cmd: command,
        };
        write_json(&mut stream, &request).await.unwrap();
        read_json(&mut stream).await.unwrap()
    }

    async fn call_ok<T: serde::de::DeserializeOwned>(&self, command: Command) -> T {
        let response = self.call(command).await;
        assert!(response.ok, "command failed: {:?}", response.error);
        serde_json::from_value(response.data.unwrap()).unwrap()
    }

    async fn call_err(&self, command: Command) -> IpcError {
        let response = self.call(command).await;
        assert!(!response.ok, "command unexpectedly succeeded");
        response.error.unwrap()
    }

    async fn status(&self) -> StatusInfo {
        self.call_ok(Command::Status).await
    }

    async fn device_id(&self) -> String {
        self.status().await.device_id.to_string()
    }

    async fn wait_online(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let status = self.status().await;
            if status.online >= count {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {count} online session(s): {status:?}\nserve.log:\n{}\nserve2.log:\n{}",
                std::fs::read_to_string(self.home.path().join("serve.log")).unwrap_or_default(),
                std::fs::read_to_string(self.home.path().join("serve2.log")).unwrap_or_default(),
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn cli(&self, args: &[&str]) -> std::process::Output {
        StdCommand::new(bin())
            .args(args)
            .env("LANFP_HOME", self.home.path())
            .output()
            .expect("run lanfp cli")
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Grant the first node access on the second node, then return the second
/// node's selector as seen by the consumer. The first argument is the
/// consumer (rule owner); the second is the exposing host.
async fn pair(consumer: &Node, host: &Node) -> String {
    let result: PeerGrantResult = host
        .call_ok(Command::PeerGrant {
            peers: vec![format!("127.0.0.1:{}", consumer.port)],
            force: false,
        })
        .await;
    assert!(
        result.failed.is_empty(),
        "grant failed: {:?}",
        result.failed
    );
    consumer.wait_online(1).await;
    format!("127.0.0.1:{}", host.port)
}

/// A tiny blocking echo server used as the forwarding target.
fn start_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    spawn_echo_listener(listener);
    port
}

fn start_echo_server_on(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    spawn_echo_listener(listener);
}

fn spawn_echo_listener(listener: TcpListener) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
}

fn echo_roundtrip(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect forwarded port");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(payload).unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).unwrap();
    buf
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pair_forward_and_remove() {
    let a = Node::start().await;
    let b = Node::start().await;
    let peer = pair(&a, &b).await;
    a.wait_online(1).await;

    let echo_port = start_echo_server();
    // Give the peer's inventory poller time to see the echo listener.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let listen_port = free_port();
    let add: ForwardAddResult = a
        .call_ok(Command::ForwardAdd {
            peer: peer.clone(),
            target_port: echo_port,
            listen: Some(listen_port),
        })
        .await;
    assert_eq!(add.local, listen_port);
    assert_eq!(add.target, echo_port);
    assert_eq!(add.state, RuleState::Active);

    assert_eq!(
        echo_roundtrip(listen_port, b"hello lanfp"),
        b"hello lanfp".to_vec()
    );

    // `lanfp remote` shows the forwarded column.
    let remote: RemoteResult = a.call_ok(Command::Remote { peer: Some(peer) }).await;
    assert_eq!(remote.peers.len(), 1);
    let row = remote.peers[0]
        .ports
        .iter()
        .find(|p| p.port == echo_port)
        .expect("target port listed");
    assert_eq!(row.forwarded, vec![listen_port]);

    // The serving side sees the inbound reference.
    let inbound: InboundResult = b.call_ok(Command::Inbound).await;
    assert!(inbound
        .inbound
        .iter()
        .any(|i| i.my_port == echo_port && i.peer_listen == listen_port && i.online));

    let removed: ForwardRemoveResult = a
        .call_ok(Command::ForwardRemove {
            local_port: listen_port,
        })
        .await;
    assert_eq!(removed.removed, listen_port);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        TcpStream::connect(("127.0.0.1", listen_port)).is_err(),
        "listener should be closed after removal"
    );

    let inbound: InboundResult = b.call_ok(Command::Inbound).await;
    assert!(inbound.inbound.iter().all(|i| i.peer_listen != listen_port));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_add_auto_listen_port() {
    let a = Node::start().await;
    let b = Node::start().await;
    let peer = pair(&a, &b).await;
    a.wait_online(1).await;
    let echo_port = start_echo_server();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Exercise clap, IPC and the daemon's automatic bind through the CLI.
    let output = a.cli(&[
        "forward",
        "add",
        &peer,
        &echo_port.to_string(),
        "--listen",
        "0",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let first: ForwardAddResult = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(first.local, 0);
    assert_ne!(first.local, a.port);
    assert!(first.local >= 1024, "unexpected port {}", first.local);
    assert_eq!(first.target, echo_port);
    assert_eq!(first.state, RuleState::Active);
    assert_eq!(
        echo_roundtrip(first.local, b"auto one"),
        b"auto one".to_vec()
    );

    // A second automatic rule must get a different port and serve traffic too.
    let second: ForwardAddResult = a
        .call_ok(Command::ForwardAdd {
            peer,
            target_port: echo_port,
            listen: Some(0),
        })
        .await;
    assert_ne!(second.local, first.local);
    assert_ne!(second.local, 0);
    assert_eq!(
        echo_roundtrip(second.local, b"auto two"),
        b"auto two".to_vec()
    );
    assert_eq!(
        echo_roundtrip(first.local, b"still one"),
        b"still one".to_vec()
    );

    let list: ForwardListResult = a.call_ok(Command::ForwardList).await;
    for port in [first.local, second.local] {
        let rule = list
            .forwards
            .iter()
            .find(|f| f.local == port)
            .unwrap_or_else(|| panic!("missing rule for auto port {port}"));
        assert_eq!(rule.target, echo_port);
    }

    // The chosen port is the rule ID used for removal.
    let removed: ForwardRemoveResult = a
        .call_ok(Command::ForwardRemove {
            local_port: first.local,
        })
        .await;
    assert_eq!(removed.removed, first.local);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        TcpStream::connect(("127.0.0.1", first.local)).is_err(),
        "auto listener should be closed after removal"
    );
    let list: ForwardListResult = a.call_ok(Command::ForwardList).await;
    assert!(list.forwards.iter().all(|f| f.local != first.local));
    assert!(list.forwards.iter().any(|f| f.local == second.local));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_transfer_half_close_and_concurrency() {
    let a = Node::start().await;
    let b = Node::start().await;
    let peer = pair(&a, &b).await;
    a.wait_online(1).await;
    let echo_port = start_echo_server();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let listen_port = free_port();
    let _: ForwardAddResult = a
        .call_ok(Command::ForwardAdd {
            peer,
            target_port: echo_port,
            listen: Some(listen_port),
        })
        .await;

    // 100 MiB round trip. The echo service cannot drain its socket while we
    // block on writing the whole payload, so read concurrently.
    let payload: Vec<u8> = (0..100 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let mut stream = TcpStream::connect(("127.0.0.1", listen_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let mut reader = stream.try_clone().unwrap();
    let expected_len = payload.len();
    let reader_handle = std::thread::spawn(move || {
        let mut buf = vec![0u8; expected_len];
        reader.read_exact(&mut buf).unwrap();
        buf
    });
    stream.write_all(&payload).unwrap();
    let received = reader_handle.join().unwrap();
    assert_eq!(received, payload);

    // Half-close: shutdown write, then read the echo until EOF.
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    drop(stream);

    // 100 concurrent connections (wait for a fresh per-second stream window).
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut handles = Vec::new();
    for i in 0..100 {
        handles.push(std::thread::spawn(move || {
            let msg = format!("concurrent-{i}").into_bytes();
            echo_roundtrip(listen_port, &msg) == msg
        }));
    }
    for handle in handles {
        assert!(handle.join().unwrap());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unpaired_tls_client_is_rejected() {
    lanfp_crypto::install_crypto_provider();
    let node = Node::start().await;
    let cert = std::fs::read(node.home.path().join("data/identity.crt")).unwrap();
    let server_key = lanfp_crypto::tls::ed25519_pubkey_from_cert(&cert).unwrap();
    let rogue = lanfp_crypto::Identity::generate().unwrap();
    let config = lanfp_crypto::client_config(&rogue, server_key).unwrap();
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", node.port))
        .await
        .unwrap();
    let server_name =
        tokio_rustls::rustls::pki_types::ServerName::try_from("lanfp.invalid").unwrap();
    match connector.connect(server_name, tcp).await {
        Err(_) => {}
        Ok(mut tls) => {
            // In TLS 1.3 the client can finish its side before the server's
            // client-certificate rejection arrives; probe the connection.
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _ = tls.write_all(b"hello").await;
            let mut buf = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(3), tls.read(&mut buf)).await;
            assert!(
                matches!(read, Ok(Ok(0)) | Ok(Err(_)) | Err(_)),
                "server kept the connection open for an unpaired device"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipc_socket_is_private() {
    let node = Node::start().await;
    let socket = node.socket();
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "IPC socket must be 0600");
    let runtime_mode = std::fs::metadata(node.home.path().join("run"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(runtime_mode, 0o700, "runtime directory must be 0700");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_reports_documented_exit_codes() {
    let a = Node::start().await;
    let b = Node::start().await;

    // The old pairing commands are gone.
    assert_eq!(a.cli(&["peer", "add"]).status.code(), Some(2));
    assert_eq!(a.cli(&["peer", "wait"]).status.code(), Some(2));

    // No known server: the hint must name the two commands that can change
    // that state, not a read-only scan that cannot create a server record.
    let empty = a.cli(&["remote"]);
    assert_eq!(empty.status.code(), Some(4), "{empty:?}");
    let stderr = String::from_utf8_lossy(&empty.stderr);
    assert!(stderr.contains("lanfp remote <ip>"), "{stderr}");
    assert!(!stderr.contains("`lanfp scan`"), "{stderr}");

    // A malformed selector is a usage error, not "device not found".
    assert_eq!(a.cli(&["remote", ""]).status.code(), Some(2));

    // A consumer that has not been granted access is rejected.
    let not_granted = a
        .call_err(Command::Remote {
            peer: Some(format!("127.0.0.1:{}", b.port)),
        })
        .await;
    assert_eq!(not_granted.code, 4, "{not_granted:?}");

    let peer = pair(&a, &b).await;
    a.wait_online(1).await;
    let echo_port = start_echo_server();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Port 0 is only special for --listen; a target port of 0 stays invalid.
    let err = a
        .call_err(Command::ForwardAdd {
            peer: peer.clone(),
            target_port: 0,
            listen: Some(0),
        })
        .await;
    assert_eq!(err.code, 2);

    // Unreachable peer.
    let err = a
        .call_err(Command::ForwardAdd {
            peer: "10.99.99.99".into(),
            target_port: echo_port,
            listen: Some(free_port()),
        })
        .await;
    assert_eq!(err.code, 4);

    // Port not listening on the peer.
    let closed_port = free_port();
    let err = a
        .call_err(Command::ForwardAdd {
            peer: peer.clone(),
            target_port: closed_port,
            listen: Some(free_port()),
        })
        .await;
    assert_eq!(err.code, 8);

    // Listen conflict: occupy a local port first.
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let err = a
        .call_err(Command::ForwardAdd {
            peer: peer.clone(),
            target_port: echo_port,
            listen: Some(occupied_port),
        })
        .await;
    assert_eq!(err.code, 5);
    drop(occupied);

    // Privileged port (tests run unprivileged).
    if unsafe { libc::geteuid() } != 0 {
        let err = a
            .call_err(Command::ForwardAdd {
                peer,
                target_port: echo_port,
                listen: Some(80),
            })
            .await;
        assert_eq!(err.code, 7);
    }

    // `remote` with all peers offline returns 4.
    let b_socket = b.socket();
    drop(b);
    let deadline = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(&b_socket).await.is_ok() {
        assert!(Instant::now() < deadline, "peer daemon did not stop");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while a.status().await.online > 0 {
        assert!(Instant::now() < deadline, "session did not drop");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let remote = a.cli(&["remote"]);
    assert_eq!(remote.status.code(), Some(4), "{remote:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_outputs_and_single_instance() {
    let a = Node::start().await;

    let local = a.cli(&["local", "--json"]);
    assert!(local.status.success());
    let value: serde_json::Value = serde_json::from_slice(&local.stdout).expect("valid json");
    assert_eq!(value["schema"], 2);
    assert!(value["ports"].is_array());

    let scan = a.cli(&["scan", "--timeout", "100ms", "--json"]);
    assert!(scan.status.success());
    let value: serde_json::Value = serde_json::from_slice(&scan.stdout).expect("valid json");
    assert_eq!(value["schema"], 2);

    let forwards = a.cli(&["forward", "list", "--json"]);
    assert!(forwards.status.success());
    let value: serde_json::Value = serde_json::from_slice(&forwards.stdout).unwrap();
    assert_eq!(value["schema"], 2);

    let inbound = a.cli(&["inbound", "--json"]);
    assert!(inbound.status.success());
    let value: serde_json::Value = serde_json::from_slice(&inbound.stdout).unwrap();
    assert_eq!(value["schema"], 2);

    // A second `serve` must detect the running instance and exit 0.
    let second = a.cli(&["serve"]);
    assert!(second.status.success(), "{second:?}");
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(stdout.contains("already running"), "{stdout}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rules_survive_daemon_restart() {
    let a = Node::start().await;
    let b = Node::start().await;
    let peer = pair(&a, &b).await;
    a.wait_online(1).await;
    let echo_port = start_echo_server();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let listen_port = free_port();
    let _: ForwardAddResult = a
        .call_ok(Command::ForwardAdd {
            peer,
            target_port: echo_port,
            listen: Some(listen_port),
        })
        .await;
    assert_eq!(echo_roundtrip(listen_port, b"before"), b"before".to_vec());

    // Stop and restart the rule-owning daemon through the CLI.
    let stop = a.cli(&["daemon", "stop"]);
    assert!(stop.status.success(), "{stop:?}");
    let deadline = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(a.socket()).await.is_ok() {
        assert!(Instant::now() < deadline, "daemon did not stop");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Replace the killed child with a fresh `serve` process.
    let log = std::fs::File::create(a.home.path().join("serve2.log")).unwrap();
    let child = StdCommand::new(bin())
        .arg("serve")
        .env("LANFP_HOME", a.home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    // SAFETY: the test owns the node and replaces the process handle.
    let mut a = a;
    a.child = child;
    a.wait_ipc().await;
    a.wait_online(1).await;

    let forwards: ForwardListResult = a.call_ok(Command::ForwardList).await;
    assert_eq!(forwards.forwards.len(), 1);
    assert_eq!(forwards.forwards[0].local, listen_port);
    assert_eq!(forwards.forwards[0].state, RuleState::Active);
    assert_eq!(
        echo_roundtrip(listen_port, b"after restart"),
        b"after restart".to_vec()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_set_address_updates_the_record() {
    let a = Node::start().await;
    let b = Node::start().await;
    let peer = pair(&a, &b).await;
    a.wait_online(1).await;
    let remote: RemoteResult = a.call_ok(Command::Remote { peer: None }).await;
    let entry = remote.peers[0].clone();
    let peer_name = entry.name.clone();

    // Repoint the server at a port that is not listening and check the CLI
    // reports the stored address while the current session stays up.
    let wrong_port = free_port();
    let wrong = format!("127.0.0.1:{wrong_port}");
    let output = a.cli(&["peer", "set-address", &peer, &wrong, "--json"]);
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(value["schema"], 2);
    assert_eq!(value["address"], wrong);
    assert_eq!(value["online"], true);

    let remote: RemoteResult = a
        .call_ok(Command::Remote {
            peer: Some(peer_name.clone()),
        })
        .await;
    assert_eq!(remote.peers[0].port, wrong_port);

    // Put the real address back.
    let good = format!("127.0.0.1:{}", b.port);
    let output = a.cli(&["peer", "set-address", &peer_name, &good]);
    assert!(output.status.success(), "{output:?}");
    let remote: RemoteResult = a
        .call_ok(Command::Remote {
            peer: Some(peer_name.clone()),
        })
        .await;
    assert_eq!(remote.peers[0].port, b.port);

    // Names are not addresses, and an unknown peer is exit code 3.
    let bad = a.cli(&["peer", "set-address", &peer_name, "lanfp.local"]);
    assert_eq!(bad.status.code(), Some(2), "{bad:?}");
    let missing = a.cli(&["peer", "set-address", "nobody", "127.0.0.1"]);
    assert_eq!(missing.status.code(), Some(3), "{missing:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_list_and_selector_forms() {
    let a = Node::start().await;
    let b = Node::start().await;
    let _ = pair(&a, &b).await;
    a.wait_online(1).await;

    // Authorization is one-way: the host lists the consumer, the consumer
    // does not list the host as an authorized device.
    let allowed: PeerListResult = b.call_ok(Command::PeerList).await;
    assert_eq!(allowed.peers.len(), 1);
    assert_eq!(allowed.peers[0].port, a.port);
    let consumer: PeerListResult = a.call_ok(Command::PeerList).await;
    assert!(consumer.peers.is_empty());

    let remote: RemoteResult = a.call_ok(Command::Remote { peer: None }).await;
    let entry = &remote.peers[0];
    assert_eq!(entry.address, "127.0.0.1");
    assert_eq!(entry.port, b.port);
    assert!(entry.online);
    let full = entry.id;
    let short = lanfp_core::short_id(full);

    let text = b.cli(&["peer", "list"]);
    assert!(text.status.success(), "{text:?}");
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.contains("ID"), "{stdout}");
    assert!(stdout.contains(&a.device_id().await), "{stdout}");

    let simple = full.simple().to_string();
    let selectors = vec![
        full.to_string(),
        simple.clone(),
        short.clone(),
        entry.name.clone(),
        format!("{}@127.0.0.1:{}", entry.name, b.port),
        format!("127.0.0.1:{}", b.port),
        simple[..4].to_string(),
    ];
    for selector in selectors {
        let remote: RemoteResult = a
            .call_ok(Command::Remote {
                peer: Some(selector.clone()),
            })
            .await;
        assert_eq!(remote.peers[0].id, full, "selector `{selector}`");
    }

    let err = a
        .call_err(Command::Remote {
            peer: Some("nobody".into()),
        })
        .await;
    assert_eq!(err.code, 3, "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_names_are_ambiguous() {
    let a = Node::start().await;
    let b = Node::start().await;
    let c = Node::start().await;
    let _ = pair(&a, &b).await;
    let _ = pair(&a, &c).await;
    a.wait_online(2).await;

    let remote: RemoteResult = a.call_ok(Command::Remote { peer: None }).await;
    assert_eq!(remote.peers.len(), 2);
    let name = remote.peers[0].name.clone();
    assert_eq!(remote.peers[1].name, name);

    let err = a
        .call_err(Command::Remote {
            peer: Some(name.clone()),
        })
        .await;
    assert_eq!(err.code, 2, "{err:?}");
    assert!(err.message.contains("matches 2 devices"), "{err:?}");
    assert!(
        err.message
            .contains(&lanfp_core::short_id(remote.peers[0].id)),
        "{err:?}"
    );

    // The stable ID disambiguates, and so does the full address.
    let chosen = &remote.peers[1];
    let listed: RemoteResult = a
        .call_ok(Command::Remote {
            peer: Some(lanfp_core::short_id(chosen.id)),
        })
        .await;
    assert_eq!(listed.peers[0].id, chosen.id);
    let listed: RemoteResult = a
        .call_ok(Command::Remote {
            peer: Some(format!("127.0.0.1:{}", chosen.port)),
        })
        .await;
    assert_eq!(listed.peers[0].id, chosen.id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_is_one_way() {
    let a = Node::start().await;
    let b = Node::start().await;
    let _ = pair(&a, &b).await;
    a.wait_online(1).await;

    let host_view: PeerListResult = b.call_ok(Command::PeerList).await;
    assert_eq!(host_view.peers.len(), 1);
    assert_eq!(host_view.peers[0].port, a.port);
    let consumer_view: PeerListResult = a.call_ok(Command::PeerList).await;
    assert!(consumer_view.peers.is_empty());

    let remote: RemoteResult = a.call_ok(Command::Remote { peer: None }).await;
    assert_eq!(remote.peers.len(), 1);
    assert_eq!(remote.peers[0].id, b.status().await.device_id);
    assert_eq!(remote.peers[0].mode, ExposeMode::All);
    assert!(remote.peers[0].ports.iter().all(|p| p.listening));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_grant_names_the_granted_device() {
    let consumer = Node::start().await;
    let host = Node::start().await;
    let output = host.cli(&["peer", "grant", &format!("127.0.0.1:{}", consumer.port)]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("may now connect and forward exposed ports on this machine"),
        "{stdout}"
    );
    assert!(!stdout.contains("this device may now connect"), "{stdout}");
    consumer.wait_online(1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_whitelist_from_config_and_non_listening() {
    // Ports must exist before the daemon boots: the whitelist is config-owned.
    let p1 = start_echo_server();
    let p3 = start_echo_server();
    let p2 = free_port(); // a whitelist port that is not listening yet
    let a = Node::start().await;
    let b = Node::start_with_expose_ports(&[p1.to_string(), p2.to_string()]).await;
    let peer = pair(&a, &b).await;
    a.wait_online(1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let remote: RemoteResult = a.call_ok(Command::Remote { peer: None }).await;
    let view = &remote.peers[0];
    assert_eq!(view.mode, ExposeMode::Whitelist);
    // The daemon stores and sends the whitelist sorted.
    let mut expected_ranges = vec![PortRange::new(p1, p1), PortRange::new(p2, p2)];
    expected_ranges.sort_unstable();
    assert_eq!(view.ranges, expected_ranges);
    // Only listening whitelist entries appear with details; p2 is covered by
    // the whitelist but not listening, p3 is not in the whitelist at all.
    let ports: Vec<u16> = view.ports.iter().map(|p| p.port).collect();
    assert_eq!(ports, vec![p1]);
    assert!(!ports.contains(&p2));
    assert!(!ports.contains(&p3));

    // A listening port that is also a one-port whitelist entry is listed once,
    // not again as a range row.
    let text = a.cli(&["remote"]);
    let stdout = String::from_utf8_lossy(&text.stdout);
    let p1_text = p1.to_string();
    let rows = stdout
        .lines()
        .filter(|line| line.split_whitespace().nth(2) == Some(p1_text.as_str()))
        .count();
    assert_eq!(rows, 1, "{stdout}");

    // The whitelist may contain a port before it listens.
    let listen_port = free_port();
    let added: ForwardAddResult = a
        .call_ok(Command::ForwardAdd {
            peer: peer.clone(),
            target_port: p2,
            listen: Some(listen_port),
        })
        .await;
    assert_eq!(added.state, RuleState::TargetGone);

    // The text table must show why the rule is not active.
    let listed = a.cli(&["forward", "list"]);
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(stdout.contains("target_gone"), "{stdout}");
    assert!(stdout.contains("ERROR"), "{stdout}");
    assert!(stdout.contains("listening on the peer"), "{stdout}");

    // A listening but unexposed port is rejected.
    let err = a
        .call_err(Command::ForwardAdd {
            peer: peer.clone(),
            target_port: p3,
            listen: Some(free_port()),
        })
        .await;
    assert_eq!(err.code, 8, "{err:?}");

    // Start the target; the pre-created rule becomes active and inbound
    // appears only once the forwarding is real.
    start_echo_server_on(p2);
    tokio::time::sleep(Duration::from_millis(900)).await;
    let list: ForwardListResult = a.call_ok(Command::ForwardList).await;
    let rule = list
        .forwards
        .iter()
        .find(|f| f.local == listen_port)
        .expect("rule");
    assert_eq!(rule.state, RuleState::Active);
    let inbound: InboundResult = b.call_ok(Command::Inbound).await;
    assert!(inbound
        .inbound
        .iter()
        .any(|i| i.my_port == p2 && i.peer_listen == listen_port && i.online));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_range_covers_non_listening_ports() {
    let lo = free_port();
    let hi = lo + 100;
    let inside_listening = lo + 10;
    let inside_not_listening = lo + 50;
    start_echo_server_on(inside_listening);
    let a = Node::start().await;
    let b = Node::start_with_expose_ports(&[format!("{lo}-{hi}")]).await;
    let peer = pair(&a, &b).await;
    a.wait_online(1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let remote: RemoteResult = a.call_ok(Command::Remote { peer: None }).await;
    let view = &remote.peers[0];
    assert_eq!(view.mode, ExposeMode::Whitelist);
    assert_eq!(view.ranges, vec![PortRange::new(lo, hi)]);
    // Stray listeners from other tests may fall into the range; every
    // reported listening port must at least be whitelisted.
    let ports: Vec<u16> = view.ports.iter().map(|p| p.port).collect();
    assert!(ports.contains(&inside_listening), "{ports:?}");
    assert!(ports.iter().all(|p| *p >= lo && *p <= hi), "{ports:?}");

    // The direct rule starts active and forwards end to end.
    let listen_direct = free_port();
    let added: ForwardAddResult = a
        .call_ok(Command::ForwardAdd {
            peer: peer.clone(),
            target_port: inside_listening,
            listen: Some(listen_direct),
        })
        .await;
    assert_eq!(added.state, RuleState::Active);
    assert_eq!(
        echo_roundtrip(listen_direct, b"range roundtrip"),
        b"range roundtrip".to_vec()
    );

    // A target inside the range may be pre-created before it listens.
    let listen_future = free_port();
    let added: ForwardAddResult = a
        .call_ok(Command::ForwardAdd {
            peer: peer.clone(),
            target_port: inside_not_listening,
            listen: Some(listen_future),
        })
        .await;
    assert_eq!(added.state, RuleState::TargetGone);

    // Start it: the rule recovers and forwarding works.
    start_echo_server_on(inside_not_listening);
    tokio::time::sleep(Duration::from_millis(900)).await;
    let list: ForwardListResult = a.call_ok(Command::ForwardList).await;
    let rule = list
        .forwards
        .iter()
        .find(|f| f.local == listen_future)
        .expect("rule");
    assert_eq!(rule.state, RuleState::Active);
    assert_eq!(
        echo_roundtrip(listen_future, b"recovered"),
        b"recovered".to_vec()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_add_rejects_the_agent_port_inside_a_whitelist_range() {
    let a = Node::start().await;
    let b = Node::start().await;
    let peer = pair(&a, &b).await;
    a.wait_online(1).await;

    // The range covers the host's agent port, so the exposure check alone
    // would accept it; the agent port itself must still be rejected.
    let lo = b.port.saturating_sub(1);
    let hi = b.port.saturating_add(1);
    let config = format!(
        "[agent]\nlisten = \"127.0.0.1:{}\"\nexpose_ports = [\"{lo}-{hi}\"]\n\n[discovery]\nmdns = false\n\n[inventory]\ninterval_ms = 200\n",
        b.port
    );
    std::fs::write(b.home.path().join("config/config.toml"), config).unwrap();

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let remote: RemoteResult = a.call_ok(Command::Remote { peer: None }).await;
        if remote.peers[0].mode == ExposeMode::Whitelist {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "whitelist did not reach the consumer in time"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let err = a
        .call_err(Command::ForwardAdd {
            peer: peer.clone(),
            target_port: b.port,
            listen: Some(free_port()),
        })
        .await;
    assert_eq!(err.code, 8, "{err:?}");
    assert!(err.message.contains("agent port"), "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ports_hot_reload_updates_the_view() {
    let echo_port = start_echo_server();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let a = Node::start().await;
    let b = Node::start().await;
    let _peer = pair(&a, &b).await;
    a.wait_online(1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Empty whitelist: blanket mode.
    let remote: RemoteResult = a.call_ok(Command::Remote { peer: None }).await;
    let view = &remote.peers[0];
    assert_eq!(view.mode, ExposeMode::All);
    assert!(!view.ports.is_empty());

    // Rewrite the config with a whitelist; the watcher applies it live.
    let config = format!(
        "[agent]\nlisten = \"127.0.0.1:{}\"\nexpose_ports = [\"{}\"]\n\n[discovery]\nmdns = false\n\n[inventory]\ninterval_ms = 200\n",
        b.port, echo_port
    );
    std::fs::write(b.home.path().join("config/config.toml"), config).unwrap();

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let remote: RemoteResult = a.call_ok(Command::Remote { peer: None }).await;
        if remote.peers[0].mode == ExposeMode::Whitelist {
            assert_eq!(
                remote.peers[0].ranges,
                vec![PortRange::new(echo_port, echo_port)]
            );
            let ports: Vec<u16> = remote.peers[0].ports.iter().map(|p| p.port).collect();
            assert_eq!(ports, vec![echo_port]);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "hot reload did not reach the consumer in time"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // The consumer can now only forward to whitelisted ports.
    let err = a
        .call_err(Command::ForwardAdd {
            peer: format!("127.0.0.1:{}", b.port),
            target_port: b.port, // the agent port is never exposed
            listen: Some(free_port()),
        })
        .await;
    assert_eq!(err.code, 8, "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_drops_session_and_inbound() {
    let a = Node::start().await;
    let b = Node::start().await;
    let peer = pair(&a, &b).await;
    a.wait_online(1).await;
    let echo_port = start_echo_server();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let listen_port = free_port();
    let _: ForwardAddResult = a
        .call_ok(Command::ForwardAdd {
            peer: peer.clone(),
            target_port: echo_port,
            listen: Some(listen_port),
        })
        .await;
    assert_eq!(
        echo_roundtrip(listen_port, b"before revoke"),
        b"before revoke".to_vec()
    );

    let revoked: PeerRevokeResult = b
        .call_ok(Command::PeerRevoke {
            peers: vec![format!("127.0.0.1:{}", a.port)],
        })
        .await;
    assert_eq!(revoked.revoked.len(), 1);

    let deadline = Instant::now() + Duration::from_secs(10);
    while a.status().await.online > 0 {
        assert!(Instant::now() < deadline, "session did not drop");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let inbound: InboundResult = b.call_ok(Command::Inbound).await;
    assert!(inbound.inbound.is_empty());
    let err = a.call_err(Command::Remote { peer: Some(peer) }).await;
    assert_eq!(err.code, 4, "{err:?}");
}

#[test]
fn cli_surface_is_noun_grouped() {
    let help = run_cli(&["--help"]);
    assert!(help.status.success(), "{help:?}");
    let text = String::from_utf8_lossy(&help.stdout);
    for group in ["peer", "forward", "daemon"] {
        assert!(text.contains(&format!("\n  {group} ")), "{text}");
    }
    assert!(!text.contains("\n  pair "), "{text}");

    let peer = run_cli(&["peer", "--help"]);
    assert!(peer.status.success(), "{peer:?}");
    let text = String::from_utf8_lossy(&peer.stdout);
    for sub in ["list", "grant", "revoke", "set-address"] {
        assert!(text.contains(sub), "{text}");
    }
    assert!(!text.contains("\n  add "), "{text}");
    assert!(!text.contains("\n  wait "), "{text}");

    let grant = run_cli(&["peer", "grant", "--help"]);
    assert!(grant.status.success(), "{grant:?}");
    let text = String::from_utf8_lossy(&grant.stdout);
    for option in ["PEER", "--force", "--json"] {
        assert!(text.contains(option), "{text}");
    }

    // The old commands are gone; the whitelist moved to `agent.expose_ports`.
    assert_eq!(run_cli(&["pair", "127.0.0.1:1"]).status.code(), Some(2));
    assert_eq!(run_cli(&["expose"]).status.code(), Some(2));
    assert_eq!(run_cli(&["expose", "list"]).status.code(), Some(2));
    assert_eq!(run_cli(&["expose", "add", "3000"]).status.code(), Some(2));
    assert_eq!(run_cli(&["peer", "add"]).status.code(), Some(2));
    assert_eq!(run_cli(&["peer", "wait"]).status.code(), Some(2));
}
