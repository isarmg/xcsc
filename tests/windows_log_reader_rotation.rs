//! Native regression investigation: expected to FAIL on xcsc 400bc567.
//! Uses only the production sink, private reader, and shared query; no hooks or sleeps.
#![cfg(windows)]
use serde_json::Value;
use xcsc::{
    cli::{Args, Result, fail, query_rotating_logs, storage_error},
    fs_safety::{EntryName, Error, PrivateDirectory},
    log::{
        Level, LogFilter, LogRecord, LogRetention, MAX_RECORD_BYTES, QueryLimits, RotatingLogFile,
    },
};
fn decode(bytes: &[u8]) -> Result<Vec<Value>> {
    xcsc::log::query(
        std::io::Cursor::new(bytes),
        LogFilter::default(),
        QueryLimits {
            max_input_bytes: 1024 * 1024,
            max_records: 16384,
        },
    )
    .map_err(|_| fail(8, "log_integrity_or_filter_failed"))?
    .into_iter()
    .map(|r| serde_json::to_value(r).map_err(storage_error))
    .collect()
}
fn read(directory: &PrivateDirectory, name: &str) -> Result<Option<Vec<u8>>> {
    match directory.read_private_bounded(
        &EntryName::new(name).map_err(storage_error)?,
        8 * 1024 * 1024,
    ) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(fail(8, "unsafe_or_unreadable_runtime_log")),
    }
}
fn ids(value: &Value) -> Vec<&str> {
    value["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["instance_id"].as_str().unwrap())
        .collect()
}
fn record(id: &str) -> LogRecord {
    LogRecord::instance(
        "fixture",
        "worker",
        "fixture.worker.completed",
        "Completed.",
        Level::Info,
        id,
    )
    .unwrap()
    .with_attribute("padding", "x".repeat(9000))
    .unwrap()
}
#[test]
fn windows_rotating_query_must_not_omit_retained_record() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("logs");
    let mut sink = RotatingLogFile::create_private(
        &path,
        "fixture",
        LogRetention {
            file_bytes: MAX_RECORD_BYTES as u64,
            archives: 4,
        },
    )
    .unwrap();
    let directory = PrivateDirectory::open_existing(&path).unwrap();
    let a = record("record-a");
    let b = record("record-b");
    let c = record("record-c");
    for record in [&a, &b, &c] {
        let length = record.json_line().unwrap().len();
        assert!(length <= MAX_RECORD_BYTES && length * 2 > MAX_RECORD_BYTES);
    }
    let mut args =
        Args::parse(vec!["logs".into(), "--tail".into(), "10".into()], &[], &[]).unwrap();
    sink.write(&a).unwrap();
    let first = query_rotating_logs(&args, "fixture", |n| read(&directory, n), decode).unwrap();
    args.options.insert(
        "--log-cursor".into(),
        first["entries"][0]["cursor"].as_str().unwrap().into(),
    );
    sink.write(&b).unwrap(); // Native sink rotates a into .1; b is active.
    let mut fired = false;
    let during = query_rotating_logs(
        &args,
        "fixture",
        |name| {
            let bytes = read(&directory, name)?; // Its handle has closed before the hook.
            if name == "fixture.jsonl.1" {
                assert!(!fired);
                fired = true;
                sink.write(&c).unwrap(); // Native rotation, at an exact scan boundary.
            }
            Ok(bytes)
        },
        decode,
    )
    .unwrap();
    assert!(fired);
    args.options.insert(
        "--log-cursor".into(),
        during["entries"]
            .as_array()
            .unwrap()
            .last()
            .expect("scan must return a record for this fixture")["cursor"]
            .as_str()
            .unwrap()
            .into(),
    );
    let next = query_rotating_logs(&args, "fixture", |n| read(&directory, n), decode).unwrap();
    let all = Args::parse(vec!["logs".into()], &[], &[]).unwrap();
    let retained = query_rotating_logs(&all, "fixture", |n| read(&directory, n), decode).unwrap();
    assert_eq!(ids(&retained), ["record-a", "record-b", "record-c"]);
    sink.write(&record("record-d")).unwrap(); // Reader has not poisoned the writer.
    let mut observed = ids(&during);
    observed.extend(ids(&next));
    if observed == ["record-c"] {
        eprintln!(
            "WINDOWS_RETAINED_OMISSION_REPRO_READY: native rotation succeeded; private reads succeeded; B remains retained; C cursor advanced; next poll empty; writer remains healthy"
        );
    }
    assert_eq!(
        observed,
        ["record-b", "record-c"],
        "WINDOWS_RETAINED_RECORD_OMITTED: following A must deliver retained B and C exactly once across these two polls"
    );
}
