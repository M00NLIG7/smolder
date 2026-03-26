use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smolder_tools::prelude::{
    DurableOpenOptions, NtlmCredentials, OpenOptions, ResilientHandle, ShareReconnectPlan,
};
use tokio::io::AsyncReadExt;

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[derive(Debug, Clone)]
struct WindowsConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    share: String,
    test_dir: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl WindowsConfig {
    fn from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_WINDOWS_HOST")?,
            port: required_env("SMOLDER_WINDOWS_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
            username: required_env("SMOLDER_WINDOWS_USERNAME")?,
            password: required_env("SMOLDER_WINDOWS_PASSWORD")?,
            share: required_env("SMOLDER_WINDOWS_SHARE").unwrap_or_else(|| "ADMIN$".to_string()),
            test_dir: required_env("SMOLDER_WINDOWS_TEST_DIR")
                .unwrap_or_else(|| "Temp".to_string()),
            domain: required_env("SMOLDER_WINDOWS_DOMAIN"),
            workstation: required_env("SMOLDER_WINDOWS_WORKSTATION"),
        })
    }
}

fn reconnect_plan() -> Option<(WindowsConfig, ShareReconnectPlan)> {
    let Some(config) = WindowsConfig::from_env() else {
        eprintln!(
            "skipping tools Windows reconnect test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, and SMOLDER_WINDOWS_PASSWORD must be set"
        );
        return None;
    };

    let mut credentials = NtlmCredentials::new(config.username.clone(), config.password.clone());
    if let Some(domain) = &config.domain {
        credentials = credentials.with_domain(domain.clone());
    }
    if let Some(workstation) = &config.workstation {
        credentials = credentials.with_workstation(workstation.clone());
    }

    Some((
        config.clone(),
        ShareReconnectPlan::new(config.host.clone(), config.share.clone(), credentials)
            .port(config.port),
    ))
}

fn unique_test_file_path(test_dir: &str) -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    format!(
        "{}\\smolder-tools-reconnect-{}-{}.txt",
        test_dir.trim_matches(['\\', '/']),
        std::process::id(),
        stamp
    )
}

#[tokio::test]
async fn reconnect_plan_reopens_durable_handle_on_windows_when_configured() {
    let Some((config, plan)) = reconnect_plan() else {
        return;
    };

    let timeout = 30_000;
    let path = unique_test_file_path(&config.test_dir);
    let payload = b"smolder tools durable reconnect".to_vec();

    let mut share = plan
        .connect()
        .await
        .expect("reconnect plan should build an authenticated Windows share");
    let mut file = share
        .open(
            &path,
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .durable(DurableOpenOptions::new().with_timeout(timeout))
                .resilient(timeout),
        )
        .await
        .expect("Windows should allow a durable high-level open");
    tokio::io::AsyncWriteExt::write_all(&mut file, &payload)
        .await
        .expect("Windows should write the durable payload");
    file.flush()
        .await
        .expect("Windows should flush the durable payload");

    let durable = file
        .durable_handle()
        .cloned()
        .expect("durable open should capture reconnect state");
    assert_eq!(durable.resilient_timeout(), Some(timeout));
    assert_eq!(
        file.resilient_handle(),
        Some(ResilientHandle {
            file_id: file.file_id(),
            timeout,
        })
    );

    drop(file);
    drop(share);

    let mut share = plan
        .connect()
        .await
        .expect("reconnect plan should rebuild the SMB session and tree");
    let mut reopened = share
        .reopen_durable(&durable)
        .await
        .expect("Windows should reopen the durable handle on the fresh share");
    let reopened_durable = reopened
        .durable_handle()
        .cloned()
        .expect("reopened file should keep durable reconnect state");
    let reopened_resilient = reopened
        .resilient_handle()
        .expect("reopened file should reapply resiliency");

    let mut round_trip = Vec::new();
    reopened
        .read_to_end(&mut round_trip)
        .await
        .expect("Windows should stream the reconnected payload");
    reopened
        .close()
        .await
        .expect("Windows should close the reconnected durable handle");

    assert_eq!(round_trip, payload);
    assert_eq!(reopened_durable.resilient_timeout(), Some(timeout));
    assert_eq!(
        reopened_resilient,
        ResilientHandle {
            file_id: reopened_durable.file_id(),
            timeout,
        }
    );

    share
        .remove(&path)
        .await
        .expect("Windows should remove the durable reconnect fixture");
}
