//! Loopback end-to-end tests: two daemons, pairing, sessions, forwarding and
//! the CLI surface.
#![cfg(unix)]

use lanfp_core::frame::{read_json, write_json};
use lanfp_core::ipc::*;
use lanfp_core::protocol::RuleState;
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
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join("config")).unwrap();
        let port = free_port();
        let config = format!(
            "[agent]\nlisten = \"127.0.0.1:{port}\"\n\n[discovery]\nmdns = false\n\n[inventory]\ninterval_ms = 200\n"
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

    async fn wait_online(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let status = self.status().await;
            if status.peers_online >= count {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {count} online session(s): {status:?}"
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

async fn pair(a: &Node, b: &Node) -> String {
    let wait: PairWaitStartResult = b.call_ok(Command::PairWaitStart { timeout_secs: 60 }).await;
    let start: PairStartResult = a
        .call_ok(Command::PairStart {
            peer: format!("127.0.0.1:{}", b.port),
        })
        .await;
    let _: PairFinishResult = a
        .call_ok(Command::PairFinish {
            token: start.token,
            code: wait.code.clone(),
            force: false,
        })
        .await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let poll: PairWaitPollResult = b.call_ok(Command::PairWaitPoll { token: wait.token }).await;
        match poll.state {
            PairWaitState::Paired => break,
            PairWaitState::Failed => panic!("pairing failed: {:?}", poll.message),
            _ => {}
        }
        assert!(Instant::now() < deadline, "pairing did not complete");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    start.peer
}

/// A tiny blocking echo server used as the forwarding target.
fn start_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
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
    port
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
async fn pairing_survives_slow_code_entry() {
    let a = Node::start().await;
    let b = Node::start().await;

    let wait: PairWaitStartResult = b.call_ok(Command::PairWaitStart { timeout_secs: 60 }).await;
    let start: PairStartResult = a
        .call_ok(Command::PairStart {
            peer: format!("127.0.0.1:{}", b.port),
        })
        .await;

    // A human has to read the code from the other terminal and type it; this
    // takes longer than a network round trip and must not abort the exchange.
    tokio::time::sleep(Duration::from_secs(12)).await;

    let _: PairFinishResult = a
        .call_ok(Command::PairFinish {
            token: start.token,
            code: wait.code.clone(),
            force: false,
        })
        .await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let poll: PairWaitPollResult = b.call_ok(Command::PairWaitPoll { token: wait.token }).await;
        match poll.state {
            PairWaitState::Paired => break,
            PairWaitState::Failed => panic!("pairing failed: {:?}", poll.message),
            _ => {}
        }
        assert!(Instant::now() < deadline, "pairing did not complete");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    a.wait_online(1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_code_attempts_are_limited() {
    let a = Node::start().await;
    let b = Node::start().await;

    let wait: PairWaitStartResult = b.call_ok(Command::PairWaitStart { timeout_secs: 60 }).await;
    for attempt in 0..5 {
        let start: PairStartResult = a
            .call_ok(Command::PairStart {
                peer: format!("127.0.0.1:{}", b.port),
            })
            .await;
        let err = a
            .call_err(Command::PairFinish {
                token: start.token,
                code: "000000".into(),
                force: false,
            })
            .await;
        assert_eq!(err.code, 9, "attempt {attempt}");
        let poll: PairWaitPollResult = b.call_ok(Command::PairWaitPoll { token: wait.token }).await;
        if attempt < 4 {
            assert_eq!(poll.state, PairWaitState::Waiting);
            assert_eq!(poll.attempts_left, Some(4 - attempt as u32));
        } else {
            assert_eq!(poll.state, PairWaitState::Failed);
            assert_eq!(poll.exit_code, Some(9));
        }
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

    // Pairing without `pair wait` fails with code 6.
    let started = Instant::now();
    let output = a.cli(&["pair", &format!("127.0.0.1:{}", b.port), "--code", "123456"]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert!(started.elapsed() < Duration::from_secs(5));

    let peer = pair(&a, &b).await;
    a.wait_online(1).await;
    let echo_port = start_echo_server();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Unknown peer.
    let err = a
        .call_err(Command::ForwardAdd {
            peer: "10.99.99.99".into(),
            target_port: echo_port,
            listen: Some(free_port()),
        })
        .await;
    assert_eq!(err.code, 3);

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
    while a.status().await.peers_online > 0 {
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
    assert_eq!(value["schema"], 1);
    assert!(value["ports"].is_array());

    let scan = a.cli(&["scan", "--timeout", "100ms", "--json"]);
    assert!(scan.status.success());
    let value: serde_json::Value = serde_json::from_slice(&scan.stdout).expect("valid json");
    assert_eq!(value["schema"], 1);

    let forwards = a.cli(&["forward", "list", "--json"]);
    assert!(forwards.status.success());
    let value: serde_json::Value = serde_json::from_slice(&forwards.stdout).unwrap();
    assert_eq!(value["schema"], 1);

    let inbound = a.cli(&["inbound", "--json"]);
    assert!(inbound.status.success());
    let value: serde_json::Value = serde_json::from_slice(&inbound.stdout).unwrap();
    assert_eq!(value["schema"], 1);

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
    let peer_name = peer.split('@').next().unwrap().to_string();
    a.wait_online(1).await;

    // Repoint the peer at a port that is not listening and check the CLI
    // reports the stored address while the current session stays up.
    let wrong_port = free_port();
    let wrong = format!("127.0.0.1:{wrong_port}");
    let output = a.cli(&["peer", "set-address", &peer, &wrong, "--json"]);
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(value["schema"], 1);
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

    let list: PeerListResult = a.call_ok(Command::PeerList).await;
    assert_eq!(list.peers.len(), 1);
    let entry = &list.peers[0];
    assert_eq!(entry.address, "127.0.0.1");
    assert_eq!(entry.port, b.port);
    assert!(entry.online);
    let full = entry.id;
    let short = lanfp_core::short_id(full);

    let text = a.cli(&["peer", "list"]);
    assert!(text.status.success(), "{text:?}");
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.contains("ID"), "{stdout}");
    assert!(stdout.contains(&full.to_string()), "{stdout}");

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

    // A stale name@address is reported with the current location.
    let stale = format!("{}@127.0.0.1:{}", entry.name, free_port());
    let err = a
        .call_err(Command::Remote {
            peer: Some(stale.clone()),
        })
        .await;
    assert_eq!(err.code, 3, "{err:?}");
    assert!(err.message.contains("currently at"), "{err:?}");
    assert!(err.message.contains(&short), "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_names_are_ambiguous() {
    let a = Node::start().await;
    let b = Node::start().await;
    let c = Node::start().await;
    let _ = pair(&a, &b).await;
    let _ = pair(&a, &c).await;
    a.wait_online(2).await;

    let list: PeerListResult = a.call_ok(Command::PeerList).await;
    assert_eq!(list.peers.len(), 2);
    let name = list.peers[0].name.clone();
    assert_eq!(list.peers[1].name, name);

    let err = a
        .call_err(Command::Remote {
            peer: Some(name.clone()),
        })
        .await;
    assert_eq!(err.code, 2, "{err:?}");
    assert!(err.message.contains("matches 2 devices"), "{err:?}");
    assert!(
        err.message
            .contains(&lanfp_core::short_id(list.peers[0].id)),
        "{err:?}"
    );

    // The stable ID disambiguates, and so does the full address.
    let chosen = &list.peers[1];
    let remote: RemoteResult = a
        .call_ok(Command::Remote {
            peer: Some(lanfp_core::short_id(chosen.id)),
        })
        .await;
    assert_eq!(remote.peers[0].id, chosen.id);
    let remote: RemoteResult = a
        .call_ok(Command::Remote {
            peer: Some(format!("127.0.0.1:{}", chosen.port)),
        })
        .await;
    assert_eq!(remote.peers[0].id, chosen.id);
}
