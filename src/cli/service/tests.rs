use super::*;

fn fixture_service() -> Service {
    Service {
        #[cfg(not(target_os = "macos"))]
        name: "fixture",
        label: "fixture",
        default_config: PathBuf::from("/unused"),
        binary: "fixture",
        log_path: "/unused",
    }
}

#[test]
fn native_service_calendar_clock_uses_utc_in_the_child() {
    let output = fixture_service()
        .capture(
            "/bin/sh",
            &["-c", "printf '%s' \"$TZ\""],
            Duration::from_secs(2),
        )
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"UTC0");
}

#[tokio::test]
async fn capture_bounds_inherited_pipes_inside_an_existing_runtime() {
    let service = fixture_service();
    let started = Instant::now();
    let failure = service
        .capture(
            "/bin/sh",
            &["-c", "sleep 2 & exit 0"],
            Duration::from_millis(150),
        )
        .unwrap_err();
    assert_eq!(failure.code, "service_timeout");
    assert!(started.elapsed() < Duration::from_secs(1));
    let output = service
        .capture(
            "/bin/sh",
            &["-c", "printf ready; exit 7"],
            Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"ready");
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn logs_since_reads_product_jsonl_from_the_service_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("service.log");
        let record =
            crate::log::LogRecord::common("example", crate::log::CommonEvent::RuntimeStarted)
                .unwrap();
        let mut record = serde_json::to_value(record).unwrap();
        let mut bytes = Vec::new();
        for timestamp in ["2026-10-11T23:59:59.999Z", "2026-10-12T00:00:00.000Z"] {
            record["timestamp"] = json!(timestamp);
            serde_json::to_writer(&mut bytes, &record).unwrap();
            bytes.push(b'\n');
        }
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut service = fixture_service();
        service.log_path = Box::leak(path.to_str().unwrap().to_owned().into_boxed_str());
        let args = Args::parse(
            vec![
                "logs".into(),
                "--since".into(),
                "2026-10-12T00:00:00Z".into(),
            ],
            &[],
            &[],
        )
        .unwrap();
        let result = service.logs(&args).unwrap();
        let entries = result["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0]["message"]
                .as_str()
                .unwrap()
                .contains("2026-10-12T00:00:00.000Z")
        );
    }

    struct Agent {
        directory: tempfile::TempDir,
        domain: String,
        target: String,
    }

    impl Agent {
        fn new() -> Self {
            let directory = tempfile::Builder::new()
                .prefix("xcsc-launchd-test-")
                .tempdir()
                .unwrap();
            let label = format!(
                "org.sarmg.xcsc-test.{}",
                directory.path().file_name().unwrap().to_str().unwrap()
            );
            let domain = format!("user/{}", rustix::process::getuid().as_raw());
            let target = format!("{domain}/{label}");
            let script = directory.path().join("agent.sh");
            std::fs::write(
                &script,
                "#!/bin/sh\ntrap '/bin/sleep 2; exit 0' TERM\nprintf ready > \"$0.ready\"\nwhile :; do /bin/sleep 0.1; done\n",
            )
            .unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o600)).unwrap();
            let escaped_script = script
                .to_str()
                .unwrap()
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            std::fs::write(
                directory.path().join("agent.plist"),
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>/bin/sh</string><string>{escaped_script}</string></array><key>LimitLoadToSessionType</key><string>Background</string><key>RunAtLoad</key><true/><key>ExitTimeOut</key><integer>6</integer></dict></plist>"
                ),
            )
            .unwrap();
            let agent = Self {
                directory,
                domain,
                target,
            };
            agent.bootstrap();
            agent
        }

        fn bootstrap(&self) {
            let ready = self.directory.path().join("agent.sh.ready");
            if ready.exists() {
                std::fs::remove_file(&ready).unwrap();
            }
            let plist = self.directory.path().join("agent.plist");
            let output = fixture_service()
                .capture(
                    "/bin/launchctl",
                    &["bootstrap", &self.domain, plist.to_str().unwrap()],
                    Duration::from_secs(5),
                )
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready.exists() {
                assert!(Instant::now() < deadline, "agent did not become ready");
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn print(&self) -> std::process::Output {
            fixture_service()
                .capture(
                    "/bin/launchctl",
                    &["print", &self.target],
                    Duration::from_secs(5),
                )
                .unwrap()
        }
    }

    impl Drop for Agent {
        fn drop(&mut self) {
            let service = fixture_service();
            let _ = service.capture(
                "/bin/launchctl",
                &["bootout", &self.target],
                Duration::from_secs(5),
            );
            let _ =
                service.wait_macos_unloaded(&self.target, Instant::now() + Duration::from_secs(8));
        }
    }

    #[test]
    fn bootout_waits_for_actual_removal_before_immediate_bootstrap() {
        let agent = Agent::new();
        assert!(agent.print().status.success());
        let output = fixture_service()
            .bootout_macos(&agent.target, Duration::from_secs(5))
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let after = agent.print();
        assert_eq!(
            after.status.code(),
            Some(113),
            "fixture state: {:?}",
            String::from_utf8_lossy(&after.stdout)
                .lines()
                .find(|line| line.trim_start().starts_with("state ="))
        );
        agent.bootstrap();
        let after_restart = agent.print();
        assert!(after_restart.status.success(), "{after_restart:?}");
        assert!(String::from_utf8_lossy(&after_restart.stdout).contains("state = running"));
        let removed = fixture_service()
            .bootout_macos(&agent.target, Duration::from_secs(5))
            .unwrap();
        assert!(removed.status.success(), "{removed:?}");
        assert_eq!(agent.print().status.code(), Some(113));
    }

    #[test]
    fn bootout_completion_remains_bounded_by_the_action_deadline() {
        let agent = Agent::new();
        let started = Instant::now();
        let failure = fixture_service()
            .bootout_macos(&agent.target, Duration::from_millis(150))
            .unwrap_err();
        assert_eq!(failure.exit, 9);
        assert_eq!(failure.code, "service_state_unconfirmed");
        assert!(started.elapsed() < Duration::from_secs(1));
        fixture_service()
            .wait_macos_unloaded(&agent.target, Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert_eq!(agent.print().status.code(), Some(113));
    }
}

#[test]
fn service_log_since_includes_structured_records_at_the_utc_boundary() {
    let record =
        crate::log::LogRecord::common("example", crate::log::CommonEvent::RuntimeStarted).unwrap();
    let mut value = serde_json::to_value(record).unwrap();
    value["timestamp"] = json!("2026-10-12T08:00:00.123Z");
    let line = serde_json::to_string(&value).unwrap();
    assert!(service_log_matches_since(&line, "2026-10-12T08:00:00Z"));
    assert!(service_log_matches_since(&line, "2026-10-12T08:00:00.123Z"));
    assert!(!service_log_matches_since(&line, "2026-10-12T08:00:01Z"));
    assert!(service_log_matches_since(&line, "2026-10-12"));
    assert!(service_log_matches_since(
        "2026-10-12T08:00:01Z service started",
        "2026-10-12T08:00:00Z",
    ));
    assert!(!service_log_matches_since("no timestamp", "2026-10-12"));
}

#[test]
fn service_log_since_uses_only_timestamp_and_compares_utc_days() {
    let before = r#"{"timestamp":"2026-10-11T23:59:59.999Z","message":"2026-10-13T00:00:00Z"}"#;
    let boundary = r#"{"timestamp":"2026-10-12T00:00:00.000Z"}"#;
    assert!(!service_log_matches_since(before, "2026-10-12"));
    assert!(service_log_matches_since(boundary, "2026-10-12"));
    assert!(service_log_matches_since(boundary, "2026-10-12T00:00:00Z"));
    assert!(service_log_matches_since(boundary, "2026-10-12 00:00:00"));
    assert!(!service_log_matches_since(
        r#"{"message":"2026-10-13T00:00:00Z"}"#,
        "2026-10-12",
    ));
    assert!(!service_log_matches_since(
        r#"{"timestamp":null,"message":"2026-10-13T00:00:00Z"}"#,
        "2026-10-12",
    ));
}
