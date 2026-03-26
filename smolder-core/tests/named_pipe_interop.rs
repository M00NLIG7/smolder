use std::sync::OnceLock;

use smolder_core::prelude::{
    connect_tree, NamedPipe, NtlmCredentials, PipeAccess, SmbSessionConfig,
};
use smolder_proto::rpc::{BindAckPdu, BindPdu, Packet, PacketFlags, SyntaxId, Uuid};
use smolder_proto::smb::smb2::{SessionId, TreeId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

struct LiveEndpointConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    domain: Option<String>,
    workstation: Option<String>,
}

impl LiveEndpointConfig {
    fn windows_from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_WINDOWS_HOST")?,
            port: required_env("SMOLDER_WINDOWS_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
            username: required_env("SMOLDER_WINDOWS_USERNAME")?,
            password: required_env("SMOLDER_WINDOWS_PASSWORD")?,
            domain: required_env("SMOLDER_WINDOWS_DOMAIN"),
            workstation: required_env("SMOLDER_WINDOWS_WORKSTATION"),
        })
    }

    fn samba_from_env() -> Option<Self> {
        Some(Self {
            host: required_env("SMOLDER_SAMBA_HOST")?,
            port: required_env("SMOLDER_SAMBA_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(445),
            username: required_env("SMOLDER_SAMBA_USERNAME")?,
            password: required_env("SMOLDER_SAMBA_PASSWORD")?,
            domain: required_env("SMOLDER_SAMBA_DOMAIN"),
            workstation: required_env("SMOLDER_SAMBA_WORKSTATION"),
        })
    }

    fn session(&self) -> SmbSessionConfig {
        let mut credentials = NtlmCredentials::new(self.username.clone(), self.password.clone());
        if let Some(domain) = &self.domain {
            credentials = credentials.with_domain(domain.clone());
        }
        if let Some(workstation) = &self.workstation {
            credentials = credentials.with_workstation(workstation.clone());
        }
        SmbSessionConfig::new(self.host.clone(), credentials).with_port(self.port)
    }
}

fn windows_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn samba_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

const RPC_FRAGMENT_SIZE: u16 = 4_280;
const SRVSVC_SYNTAX: SyntaxId = SyntaxId::new(
    Uuid::new(
        0x4b32_4fc8,
        0x1670,
        0x01d3,
        [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88],
    ),
    3,
    0,
);

fn srvsvc_bind_request() -> Vec<u8> {
    Packet::Bind(BindPdu {
        call_id: 1,
        flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
        max_xmit_frag: RPC_FRAGMENT_SIZE,
        max_recv_frag: RPC_FRAGMENT_SIZE,
        assoc_group_id: 0,
        context_id: 0,
        abstract_syntax: SRVSVC_SYNTAX,
        transfer_syntax: SyntaxId::NDR32,
        auth_verifier: None,
    })
    .encode()
}

async fn read_rpc_pdu(pipe: &mut NamedPipe) -> Result<Vec<u8>, std::io::Error> {
    let mut header = [0_u8; 10];
    pipe.read_exact(&mut header).await?;
    let fragment_len = u16::from_le_bytes([header[8], header[9]]) as usize;
    let remaining = fragment_len.saturating_sub(header.len());
    let mut packet = Vec::with_capacity(fragment_len);
    packet.extend_from_slice(&header);
    if remaining > 0 {
        let mut rest = vec![0_u8; remaining];
        pipe.read_exact(&mut rest).await?;
        packet.extend_from_slice(&rest);
    }
    Ok(packet)
}

async fn bind_srvsvc_over_named_pipe(config: LiveEndpointConfig) {
    let connection = connect_tree(&config.session(), "IPC$")
        .await
        .expect("should connect to IPC$");
    assert_ne!(connection.session_id(), SessionId(0));
    assert_ne!(connection.tree_id(), TreeId(0));

    let mut pipe = NamedPipe::open(connection, "srvsvc", PipeAccess::ReadWrite)
        .await
        .expect("should open srvsvc named pipe");

    AsyncWriteExt::write_all(&mut pipe, &srvsvc_bind_request())
        .await
        .expect("should write bind request through named pipe AsyncWrite");
    AsyncWriteExt::flush(&mut pipe)
        .await
        .expect("should flush named pipe bind request");

    let response = read_rpc_pdu(&mut pipe)
        .await
        .expect("should read bind ack through named pipe AsyncRead");
    let packet = Packet::decode(&response).expect("bind response should decode as RPC packet");
    let Packet::BindAck(bind_ack) = packet else {
        panic!("expected bind ack packet from srvsvc");
    };
    assert_successful_bind_ack(bind_ack);

    let connection = pipe.close().await.expect("should close named pipe");
    let connection = connection
        .tree_disconnect()
        .await
        .expect("should disconnect IPC$ tree");
    connection.logoff().await.expect("should log off SMB session");
}

fn assert_successful_bind_ack(bind_ack: BindAckPdu) {
    assert_eq!(bind_ack.result.result, 0);
    assert_eq!(bind_ack.result.reason, 0);
}

#[tokio::test]
async fn exchanges_srvsvc_bind_over_windows_named_pipe_when_configured() {
    let _guard = windows_lock().lock().await;
    let Some(config) = LiveEndpointConfig::windows_from_env() else {
        eprintln!(
            "skipping live Windows named-pipe test: SMOLDER_WINDOWS_HOST, SMOLDER_WINDOWS_USERNAME, and SMOLDER_WINDOWS_PASSWORD must be set"
        );
        return;
    };

    bind_srvsvc_over_named_pipe(config).await;
}

#[tokio::test]
async fn exchanges_srvsvc_bind_over_samba_named_pipe_when_configured() {
    let _guard = samba_lock().lock().await;
    let Some(config) = LiveEndpointConfig::samba_from_env() else {
        eprintln!(
            "skipping live Samba named-pipe test: SMOLDER_SAMBA_HOST, SMOLDER_SAMBA_USERNAME, and SMOLDER_SAMBA_PASSWORD must be set"
        );
        return;
    };

    bind_srvsvc_over_named_pipe(config).await;
}
