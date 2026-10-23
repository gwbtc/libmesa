mod support;
use mesa_flow::Outcome;
use mesa_store::{Limits, Store};
use std::{
    fs::File,
    net::{SocketAddr, TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use support::*;
struct Peer {
    child: Child,
    log: PathBuf,
    marker: PathBuf,
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Peer {
    fn spawn(
        root: &Path,
        id: usize,
        mode: &str,
        addresses: [SocketAddr; 2],
        gate: &str,
        round: usize,
    ) -> Self {
        let log = root.join(format!("peer-{id}-{round}.log"));
        let marker = root.join(format!("peer-{id}-{round}"));
        let out = File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_persistent-peer"))
            .arg("run")
            .arg(id.to_string())
            .arg(mode)
            .arg(root.join(format!("{id}.sqlite")))
            .arg(addresses[id].to_string())
            .arg(addresses[1 - id].to_string())
            .arg(gate)
            .arg(&marker)
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .unwrap();
        Self { child, log, marker }
    }
    fn file(&self, suffix: &str) -> PathBuf {
        PathBuf::from(format!("{}.{suffix}", self.marker.display()))
    }
    fn alive(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "peer exited: {}",
            std::fs::read_to_string(&self.log).unwrap()
        );
    }
    fn kill(&mut self) {
        self.child.kill().unwrap();
        let status = self.child.wait().unwrap();
        assert!(!status.success());
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9), "must kill without unwinding");
        }
    }
}
fn addresses(mode: &str) -> [SocketAddr; 2] {
    if mode == "udp" {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        [a.local_addr().unwrap(), b.local_addr().unwrap()]
    } else {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let b = TcpListener::bind("127.0.0.1:0").unwrap();
        [a.local_addr().unwrap(), b.local_addr().unwrap()]
    }
}
fn wait(peers: &mut [Peer; 2], gate: bool) {
    let start = Instant::now();
    loop {
        for p in peers.iter_mut() {
            p.alive();
        }
        if gate && peers[0].file("gate").exists()
            || !gate && peers.iter().all(|p| p.file("done").exists())
        {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "wait timed out: {:?}",
            peers
                .iter()
                .map(|p| std::fs::read_to_string(&p.log).unwrap())
                .collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn assert_final(root: &Path) {
    for id in 0..2 {
        let snapshot =
            Store::inspect(root.join(format!("{id}.sqlite")), Limits::default()).unwrap();
        let flow = snapshot.checkpoint.flow(7).unwrap();
        assert_eq!(snapshot.checkpoint.revision, 12);
        assert_eq!(flow.next_send, 4);
        assert!(flow.outbox.is_empty());
        assert_eq!(flow.settled.len(), 4);
        assert_eq!(flow.received.len(), 4);
        assert_eq!(snapshot.deliveries.len(), 4);
        assert_eq!(
            snapshot
                .deliveries
                .iter()
                .filter(|r| r.outcome == Outcome::Accepted)
                .count(),
            3
        );
        let sizes = [0, 1024, 1025, 17425];
        for (sequence, record) in snapshot.deliveries.iter().enumerate() {
            assert_eq!(record.id.sequence, sequence as u64);
            assert_eq!(record.bytes, fixture::payload(sizes[sequence]));
            let outcome = if sequence == 1 {
                Outcome::Rejected(23)
            } else {
                Outcome::Accepted
            };
            assert_eq!(record.outcome, outcome);
            assert_eq!(flow.settled[&(sequence as u64)], outcome);
        }
    }
}
fn case(mode: &str, kind: &str, phase: &str) {
    let tmp = Temp::new();
    let root = &tmp.0;
    for id in 0..2 {
        Store::create(
            root.join(format!("{id}.sqlite")),
            &initial(id),
            Limits::default(),
        )
        .unwrap();
    }
    let routes = addresses(mode);
    let mut peers = [
        Peer::spawn(root, 0, mode, routes, &format!("{kind}/{phase}"), 0),
        Peer::spawn(root, 1, mode, routes, "none", 0),
    ];
    wait(&mut peers, true);
    let receipt = std::fs::read_to_string(peers[0].file("gate")).unwrap();
    let proposed: u64 = receipt.rsplit('/').next().unwrap().parse().unwrap();
    let before = Store::inspect(root.join("0.sqlite"), Limits::default()).unwrap();
    let committed = matches!(phase, "committed" | "callback");
    assert_eq!(
        before.checkpoint.revision,
        proposed - u64::from(!committed),
        "{mode} {kind}/{phase}"
    );
    if kind == "enqueue" {
        assert_eq!(before.checkpoint.flows[0].next_send, u64::from(committed));
    }
    if kind == "deliver" {
        assert_eq!(before.deliveries.len(), usize::from(committed));
        assert_eq!(
            before.checkpoint.flows[0].received.len(),
            usize::from(committed)
        );
    }
    if kind == "settle" {
        assert_eq!(
            before.checkpoint.flows[0].settled.len(),
            usize::from(committed)
        );
    }
    if phase != "callback" {
        let remote = Store::inspect(root.join("1.sqlite"), Limits::default()).unwrap();
        if kind == "enqueue" {
            assert!(
                remote.checkpoint.flows[0].received.is_empty(),
                "unpublished outbox cannot be delivered"
            );
        }
        if kind == "deliver" {
            assert!(
                remote.checkpoint.flows[0].settled.is_empty(),
                "receiver cannot acknowledge before its commit callback"
            );
        }
    }
    peers[0].kill();
    peers[1].kill();
    assert_eq!(
        Store::inspect(root.join("0.sqlite"), Limits::default()).unwrap(),
        before,
        "killed process must recover authoritative transaction"
    );
    let routes = addresses(mode);
    let mut peers = [
        Peer::spawn(root, 0, mode, routes, "none", 1),
        Peer::spawn(root, 1, mode, routes, "none", 1),
    ];
    wait(&mut peers, false);
    assert_final(root);
    peers[0].kill();
    peers[1].kill();
    // Replay a completed database once more: no new accepted or rejected effect.
    let expected = [
        Store::inspect(root.join("0.sqlite"), Limits::default()).unwrap(),
        Store::inspect(root.join("1.sqlite"), Limits::default()).unwrap(),
    ];
    let routes = addresses(mode);
    let mut peers = [
        Peer::spawn(root, 0, mode, routes, "none", 2),
        Peer::spawn(root, 1, mode, routes, "none", 2),
    ];
    wait(&mut peers, false);
    assert_final(root);
    for (id, snapshot) in expected.iter().enumerate() {
        assert_eq!(
            &Store::inspect(root.join(format!("{id}.sqlite")), Limits::default()).unwrap(),
            snapshot
        );
    }
}
#[test]
fn udp_process_crashes_at_every_transaction_boundary() {
    for kind in ["enqueue", "deliver", "settle"] {
        for phase in ["before", "prepared", "committed", "callback"] {
            case("udp", kind, phase);
        }
    }
}
#[test]
fn tcp_process_crashes_at_every_transaction_boundary() {
    for kind in ["enqueue", "deliver", "settle"] {
        for phase in ["before", "prepared", "committed", "callback"] {
            case("tcp", kind, phase);
        }
    }
}

#[test]
fn writer_takeover_fences_a_live_stale_process_before_storage_commit() {
    let tmp = Temp::new();
    let root = &tmp.0;
    for id in 0..2 {
        Store::create(
            root.join(format!("{id}.sqlite")),
            &initial(id),
            Limits::default(),
        )
        .unwrap();
    }
    let routes = addresses("udp");
    let mut peers = [
        Peer::spawn(root, 0, "udp", routes, "enqueue/before", 0),
        Peer::spawn(root, 1, "udp", routes, "none", 0),
    ];
    wait(&mut peers, true);
    let owner = Store::open(root.join("0.sqlite"), &initial(0), Limits::default()).unwrap();
    assert_eq!(owner.checkpoint().unwrap().revision, 0);
    std::fs::write(peers[0].file("release"), "resume old writer").unwrap();
    let start = Instant::now();
    loop {
        if let Some(status) = peers[0].child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }
    let log = std::fs::read_to_string(&peers[0].log).unwrap();
    assert!(log.contains("Fenced"), "{log}");
    assert_eq!(
        Store::inspect(root.join("0.sqlite"), Limits::default())
            .unwrap()
            .checkpoint,
        initial(0)
    );
    assert!(Store::inspect(root.join("1.sqlite"), Limits::default())
        .unwrap()
        .checkpoint
        .flows[0]
        .received
        .is_empty());
}
