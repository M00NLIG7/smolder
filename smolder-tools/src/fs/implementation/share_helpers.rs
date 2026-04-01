use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smolder_core::dfs::{DfsReferral, UncPath, referrals_from_response, resolve_unc_path};
use smolder_core::error::CoreError;
use smolder_core::transport::Transport;
use smolder_proto::smb::smb2::{
    Command, DfsReferralRequest, DirectoryInformationEntry, FileAttributes, FileBasicInformation,
    FileStandardInformation, IoctlRequest,
};
use smolder_proto::smb::status::NtStatus;

use super::{
    DEFAULT_DFS_REFERRAL_MAX_HOPS, DEFAULT_DFS_REFERRAL_MAX_RESPONSE, SEC_TO_UNIX_EPOCH, Share,
    SmbClient, SmbDirectoryEntry, SmbMetadata, WINDOWS_TICK,
};

pub(super) fn normalize_share_name(share: &str) -> Result<String, CoreError> {
    let share = share.trim_matches(['\\', '/']);
    if share.is_empty() {
        return Err(CoreError::PathInvalid("share name must not be empty"));
    }
    if share.contains(['\\', '/', '\0']) {
        return Err(CoreError::PathInvalid(
            "share name must not contain separators or NUL bytes",
        ));
    }
    Ok(share.to_string())
}

pub(super) fn normalize_share_path(path: &str) -> Result<String, CoreError> {
    normalize_share_path_with_options(path, false)
}

pub(super) fn normalize_share_path_with_options(
    path: &str,
    allow_empty: bool,
) -> Result<String, CoreError> {
    if path.contains('\0') {
        return Err(CoreError::PathInvalid("path must not contain NUL bytes"));
    }
    if matches!(path, "\\" | "/") {
        return Ok("\\".to_string());
    }

    let normalized = path
        .split(['\\', '/'])
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("\\");
    if normalized.is_empty() && !allow_empty {
        return Err(CoreError::PathInvalid("path must not be empty"));
    }
    Ok(normalized)
}

pub(super) fn metadata_from_info(
    basic: FileBasicInformation,
    standard: FileStandardInformation,
) -> SmbMetadata {
    let mut attributes = basic.file_attributes;
    if standard.directory {
        attributes |= FileAttributes::DIRECTORY;
    }

    SmbMetadata {
        size: standard.end_of_file,
        allocation_size: standard.allocation_size,
        attributes,
        created: system_time_from_windows_ticks(basic.creation_time),
        accessed: system_time_from_windows_ticks(basic.last_access_time),
        written: system_time_from_windows_ticks(basic.last_write_time),
        changed: system_time_from_windows_ticks(basic.change_time),
    }
}

pub(super) fn directory_entry_from_query(entry: DirectoryInformationEntry) -> SmbDirectoryEntry {
    SmbDirectoryEntry {
        name: entry.file_name,
        metadata: SmbMetadata {
            size: entry.end_of_file,
            allocation_size: entry.allocation_size,
            attributes: entry.file_attributes,
            created: system_time_from_windows_ticks(entry.creation_time),
            accessed: system_time_from_windows_ticks(entry.last_access_time),
            written: system_time_from_windows_ticks(entry.last_write_time),
            changed: system_time_from_windows_ticks(entry.change_time),
        },
    }
}

fn system_time_from_windows_ticks(value: u64) -> Option<SystemTime> {
    if value == 0 {
        return None;
    }

    let unix_ticks = value.checked_sub(SEC_TO_UNIX_EPOCH * WINDOWS_TICK)?;
    Some(UNIX_EPOCH + Duration::from_nanos(unix_ticks.saturating_mul(100)))
}

pub(super) fn parse_unc_share(unc: &str) -> Result<(String, String), CoreError> {
    let trimmed = unc
        .strip_prefix(r"\\")
        .ok_or(CoreError::PathInvalid("UNC path must start with \\\\"))?;
    let mut parts = trimmed.split('\\').filter(|segment| !segment.is_empty());
    let server = parts
        .next()
        .ok_or(CoreError::PathInvalid("UNC path must include a server"))?;
    let share = parts
        .next()
        .ok_or(CoreError::PathInvalid("UNC path must include a share"))?;
    if parts.next().is_some() {
        return Err(CoreError::PathInvalid(
            "UNC share paths must not include a file component",
        ));
    }

    Ok((server.to_string(), share.to_string()))
}

pub(super) fn resolve_share_path_with_referrals(
    connected_server: &str,
    unc: &str,
    referrals: &[DfsReferral],
) -> Result<(String, String), CoreError> {
    let original = UncPath::parse(unc)?;
    let resolved = resolve_unc_path(&original, referrals);
    if !resolved.server().eq_ignore_ascii_case(connected_server) {
        return Err(CoreError::PathInvalid(
            "resolved UNC host does not match the connected SMB session",
        ));
    }

    Ok((
        normalize_share_name(resolved.share())?,
        resolved.path().join("\\"),
    ))
}

pub(super) async fn connect_share_path_with_resolver<T, Connect, Fut>(
    unc: &str,
    mut connect_server: Connect,
) -> Result<(Share<T>, String), CoreError>
where
    T: Transport + Send,
    Connect: FnMut(String) -> Fut,
    Fut: Future<Output = Result<SmbClient<T>, CoreError>>,
{
    let mut current_path = UncPath::parse(unc)?;
    for _ in 0..DEFAULT_DFS_REFERRAL_MAX_HOPS {
        let client = connect_server(current_path.server().to_string()).await?;
        let mut ipc = client.share("IPC$").await?;
        let query_result = ipc
            .connection_mut()
            .ioctl(&IoctlRequest::get_dfs_referrals(
                DfsReferralRequest {
                    max_referral_level: 4,
                    request_file_name: current_path.as_unc(),
                },
                DEFAULT_DFS_REFERRAL_MAX_RESPONSE,
            ))
            .await;

        match query_result {
            Ok(response) => {
                let referral_result = response
                    .dfs_referral_response()?
                    .ok_or(CoreError::InvalidResponse(
                        "DFS referral IOCTL did not return a DFS referral response",
                    ))
                    .and_then(|response| referrals_from_response(&response));
                let client = ipc.disconnect().await?;
                match referral_result {
                    Ok(referrals) => {
                        let resolved = resolve_unc_path(&current_path, &referrals);
                        if resolved == current_path {
                            return connect_original_share_path(client, &current_path).await;
                        }
                        current_path = resolved;
                    }
                    Err(error) if should_fallback_direct_share_after_dfs_query(&error) => {
                        return connect_original_share_path(client, &current_path).await;
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => {
                let client = ipc.disconnect().await?;
                if should_fallback_direct_share_after_dfs_query(&error) {
                    return connect_original_share_path(client, &current_path).await;
                }
                return Err(error);
            }
        }
    }

    Err(CoreError::Unsupported(
        "too many DFS referral hops while resolving UNC path",
    ))
}

pub(super) async fn connect_original_share_path<T>(
    client: SmbClient<T>,
    original: &UncPath,
) -> Result<(Share<T>, String), CoreError>
where
    T: Transport + Send,
{
    let share = client.share(original.share()).await?;
    Ok((share, original.path().join("\\")))
}

pub(super) fn should_fallback_direct_share_after_dfs_query(error: &CoreError) -> bool {
    match error {
        CoreError::UnexpectedStatus { command, status }
            if *command == Command::Ioctl
                && (*status == NtStatus::PATH_NOT_COVERED.to_u32()
                    || *status == NtStatus::NOT_FOUND.to_u32()
                    || *status == NtStatus::FS_DRIVER_REQUIRED.to_u32()
                    || *status == NtStatus::OBJECT_PATH_NOT_FOUND.to_u32()
                    || *status == NtStatus::OBJECT_NAME_NOT_FOUND.to_u32()) =>
        {
            true
        }
        CoreError::InvalidResponse("DFS referral IOCTL did not return a DFS referral response") => {
            true
        }
        _ => false,
    }
}
