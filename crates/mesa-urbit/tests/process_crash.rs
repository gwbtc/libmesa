//! Real process loss around host-owned fsync/rename/confirm boundaries.
#![cfg(unix)]
use mesa_crypto::KeyPair;
use serde_json::{json, Value};
use std::{
    fs,
    net::UdpSocket,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn launch(config: &Path) -> ChildGuard {
    ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_mesa-peer"))
            .arg(config)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
fn write(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn case(root: &Path, change: &str, point: &str, reject: bool, close: bool) {
    let dir = root.join(format!("{change}-{point}-{reject}-{close}"));
    fs::create_dir_all(&dir).unwrap();
    let sockets = [
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
    ];
    let addresses = [
        sockets[0].local_addr().unwrap(),
        sockets[1].local_addr().unwrap(),
    ];
    drop(sockets);
    let marker = dir.join("boundary");
    let names = ["~zod", "~nec"];
    let mut configs:Vec<Value>=(0..2).map(|i|json!({"session":true,"local":names[i],"remote":names[1-i],"seed":hex(&[i as u8;32]),"remote_key":hex(KeyPair::from_seed(&[(1-i) as u8;32]).public_key().as_bytes()),"bind":addresses[i].to_string(),"address":addresses[1-i].to_string(),"world":dir.join(format!("world-{i}.json")),"report":dir.join(format!("report-{i}.json")),"duration_ms":3000,"max_attempts":100,"retry_ms":20,"timeout_ms":10000})).collect();
    configs[0]["send"] = json!(hex(&vec![7; 4100]));
    configs[0]["close"] = json!(close);
    configs[1]["reject"] = json!(reject);
    let victim = usize::from(change == "accept" || change == "closed");
    configs[victim]["stop_at"] = json!({"change":change,"point":point,"marker":marker});
    let paths: [PathBuf; 2] = [dir.join("a.json"), dir.join("b.json")];
    for i in 0..2 {
        write(&paths[i], &configs[i]);
    }
    let mut children = [launch(&paths[0]), launch(&paths[1])];
    let start = Instant::now();
    while !marker.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "missing {change}/{point} marker in {}",
            dir.display()
        );
        assert!(children[victim].0.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(2));
    }
    children[victim].0.kill().unwrap();
    let status = children[victim].0.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9));
    configs[victim].as_object_mut().unwrap().remove("stop_at");
    configs[victim]["duration_ms"] = json!(2000);
    write(&paths[victim], &configs[victim]);
    children[victim] = launch(&paths[victim]);
    for child in &mut children {
        assert!(child.0.wait().unwrap().success());
    }
    let receiver = read(dir.join("world-1.json"));
    let sender = read(dir.join("world-0.json"));
    assert_eq!(
        receiver["effects"].as_array().unwrap().len(),
        1,
        "{change}/{point}"
    );
    assert_eq!(receiver["effects"][0]["hex"], hex(&vec![7; 4100]));
    assert_eq!(
        sender["settlements"].as_array().unwrap().len(),
        1,
        "{change}/{point}"
    );
    assert_eq!(
        sender["settlements"][0]["outcome"]
            .as_str()
            .unwrap()
            .starts_with("Rejected"),
        reject
    );
    if close {
        for world in [&receiver, &sender] {
            let s: mesa_flow::ordered::State =
                serde_json::from_str(world["checkpoint"].as_str().unwrap()).unwrap();
            assert!(s.flows.is_empty());
            assert_eq!(s.closed.len(), 1);
        }
    }
}
#[test]
fn sigkill_at_enqueue_effect_and_settlement_boundaries_recovers_exactly_once() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/phase6-process-crash")
        .join(std::process::id().to_string());
    for change in ["enqueue", "accept", "settlement"] {
        for point in ["before_persist", "after_persist", "after_confirm"] {
            case(&root, change, point, false, false);
        }
    }
    case(&root, "accept", "after_persist", true, false);
    case(&root, "settlement", "after_persist", true, false);
    for change in ["close", "closed"] {
        case(&root, change, "after_persist", false, true);
    }
}
