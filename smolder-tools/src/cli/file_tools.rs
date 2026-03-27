//! Standalone SMB file workflow binaries.

use std::path::PathBuf;

use super::common::{
    connect_share_move_paths, connect_share_path, ensure_same_share, parse_remote_location,
    parse_remote_location_with_options, print_metadata, AuthArgAccumulator, AuthOptions,
    RemoteLocation,
};

/// One standalone SMB file workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTool {
    /// Streams a remote file to stdout.
    Cat,
    /// Lists a share root or directory.
    Ls,
    /// Prints metadata for one remote path.
    Stat,
    /// Downloads one remote file to a local path.
    Get,
    /// Uploads one local file to a remote path.
    Put,
    /// Removes one remote file.
    Remove,
    /// Renames one remote path within a share.
    Move,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedFileArgs {
    SingleRemote {
        auth: AuthOptions,
        remote: RemoteLocation,
    },
    Get {
        auth: AuthOptions,
        remote: RemoteLocation,
        local: PathBuf,
    },
    Put {
        auth: AuthOptions,
        local: PathBuf,
        remote: RemoteLocation,
    },
    Move {
        auth: AuthOptions,
        source: RemoteLocation,
        destination: RemoteLocation,
    },
}

impl FileTool {
    fn usage(self, program: &str) -> String {
        match self {
            Self::Cat => format!(
                "Usage:\n  {program} smb://host[:port]/share/path [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]"
            ),
            Self::Ls => format!(
                "Usage:\n  {program} smb://host[:port]/share[/path] [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]"
            ),
            Self::Stat => format!(
                "Usage:\n  {program} smb://host[:port]/share/path [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]"
            ),
            Self::Get => format!(
                "Usage:\n  {program} smb://host[:port]/share/path LOCAL_PATH [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]"
            ),
            Self::Put => format!(
                "Usage:\n  {program} LOCAL_PATH smb://host[:port]/share/path [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]"
            ),
            Self::Remove => format!(
                "Usage:\n  {program} smb://host[:port]/share/path [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]"
            ),
            Self::Move => format!(
                "Usage:\n  {program} smb://host[:port]/share/path smb://host[:port]/share/new-path [--username USER] [--password PASS] [--domain DOMAIN] [--workstation NAME]"
            ),
        }
    }

    fn expected_program(self) -> &'static str {
        match self {
            Self::Cat => "smolder-cat",
            Self::Ls => "smolder-ls",
            Self::Stat => "smolder-stat",
            Self::Get => "smolder-get",
            Self::Put => "smolder-put",
            Self::Remove => "smolder-rm",
            Self::Move => "smolder-mv",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Cat => "cat",
            Self::Ls => "ls",
            Self::Stat => "stat",
            Self::Get => "get",
            Self::Put => "put",
            Self::Remove => "rm",
            Self::Move => "mv",
        }
    }
}

/// Runs one standalone SMB file tool.
pub async fn run_file_tool(tool: FileTool, args: Vec<String>) -> Result<i32, String> {
    match parse_args(tool, args)? {
        ParsedFileArgs::SingleRemote { auth, remote } => match tool {
            FileTool::Cat => {
                let (mut share, path) = connect_share_path(&auth, &remote).await?;
                let mut stdout = tokio::io::stdout();
                share
                    .cat_into(&path, &mut stdout)
                    .await
                    .map_err(|error| error.to_string())?;
            }
            FileTool::Ls => {
                let (mut share, path) = connect_share_path(&auth, &remote).await?;
                let mut entries = share.list(&path).await.map_err(|error| error.to_string())?;
                entries.sort_by(|left, right| left.name.cmp(&right.name));
                for entry in entries {
                    if entry.metadata.is_directory() {
                        println!("{}/", entry.name);
                    } else {
                        println!("{}", entry.name);
                    }
                }
            }
            FileTool::Stat => {
                let (mut share, path) = connect_share_path(&auth, &remote).await?;
                let metadata = share.stat(&path).await.map_err(|error| error.to_string())?;
                print_metadata(&path, &metadata);
            }
            FileTool::Remove => {
                let (mut share, path) = connect_share_path(&auth, &remote).await?;
                share.remove(&path).await.map_err(|error| error.to_string())?;
            }
            FileTool::Get | FileTool::Put | FileTool::Move => {
                unreachable!("single-remote parser variant does not apply to this tool");
            }
        },
        ParsedFileArgs::Get { auth, remote, local } => {
            let (mut share, path) = connect_share_path(&auth, &remote).await?;
            share
                .get(&path, local)
                .await
                .map_err(|error| error.to_string())?;
        }
        ParsedFileArgs::Put { auth, local, remote } => {
            let (mut share, path) = connect_share_path(&auth, &remote).await?;
            share
                .put(local, &path)
                .await
                .map_err(|error| error.to_string())?;
        }
        ParsedFileArgs::Move {
            auth,
            source,
            destination,
        } => {
            ensure_same_share(&source, &destination)?;
            let (mut share, source_path, destination_path) =
                connect_share_move_paths(&auth, &source, &destination).await?;
            share
                .rename(&source_path, &destination_path)
                .await
                .map_err(|error| error.to_string())?;
        }
    }

    Ok(0)
}

fn parse_args(tool: FileTool, args: Vec<String>) -> Result<ParsedFileArgs, String> {
    let program = args
        .first()
        .cloned()
        .unwrap_or_else(|| tool.expected_program().to_string());
    let usage = tool.usage(&program);

    if args.len() < 2 {
        return Err(usage);
    }

    let mut auth = AuthArgAccumulator::default();
    let mut positionals = Vec::new();
    let mut index = 1;
    while index < args.len() {
        let token = &args[index];
        if token == "-h" || token == "--help" {
            return Err(tool.usage(&program));
        }
        if auth.parse_flag(&args, &mut index, token)? {
            index += 1;
            continue;
        }
        if token.starts_with("--") {
            return Err(format!("unknown option: {token}\n\n{}", tool.usage(&program)));
        }

        positionals.push(token.as_str());
        index += 1;
    }

    let auth = auth.resolve(&usage)?;
    match tool {
        FileTool::Cat => {
            if positionals.len() != 1 {
                return Err(format!(
                    "`{}` expects exactly 1 remote SMB URL\n\n{}",
                    tool.label(),
                    tool.usage(&program)
                ));
            }
            Ok(ParsedFileArgs::SingleRemote {
                auth,
                remote: parse_remote_location(positionals[0])?,
            })
        }
        FileTool::Ls => {
            if positionals.len() != 1 {
                return Err(format!(
                    "`{}` expects exactly 1 remote SMB URL\n\n{}",
                    tool.label(),
                    tool.usage(&program)
                ));
            }
            Ok(ParsedFileArgs::SingleRemote {
                auth,
                remote: parse_remote_location_with_options(positionals[0], true)?,
            })
        }
        FileTool::Stat => {
            if positionals.len() != 1 {
                return Err(format!(
                    "`{}` expects exactly 1 remote SMB URL\n\n{}",
                    tool.label(),
                    tool.usage(&program)
                ));
            }
            Ok(ParsedFileArgs::SingleRemote {
                auth,
                remote: parse_remote_location(positionals[0])?,
            })
        }
        FileTool::Get => {
            if positionals.len() != 2 {
                return Err(format!(
                    "`{}` expects a remote SMB URL and a local path\n\n{}",
                    tool.label(),
                    tool.usage(&program)
                ));
            }
            Ok(ParsedFileArgs::Get {
                auth,
                remote: parse_remote_location(positionals[0])?,
                local: PathBuf::from(positionals[1]),
            })
        }
        FileTool::Put => {
            if positionals.len() != 2 {
                return Err(format!(
                    "`{}` expects a local path and a remote SMB URL\n\n{}",
                    tool.label(),
                    tool.usage(&program)
                ));
            }
            Ok(ParsedFileArgs::Put {
                auth,
                local: PathBuf::from(positionals[0]),
                remote: parse_remote_location(positionals[1])?,
            })
        }
        FileTool::Remove => {
            if positionals.len() != 1 {
                return Err(format!(
                    "`{}` expects exactly 1 remote SMB URL\n\n{}",
                    tool.label(),
                    tool.usage(&program)
                ));
            }
            Ok(ParsedFileArgs::SingleRemote {
                auth,
                remote: parse_remote_location(positionals[0])?,
            })
        }
        FileTool::Move => {
            if positionals.len() != 2 {
                return Err(format!(
                    "`{}` expects a source SMB URL and a destination SMB URL\n\n{}",
                    tool.label(),
                    tool.usage(&program)
                ));
            }
            Ok(ParsedFileArgs::Move {
                auth,
                source: parse_remote_location(positionals[0])?,
                destination: parse_remote_location(positionals[1])?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{parse_args, FileTool, ParsedFileArgs};
    use crate::cli::common::{AuthOptions, RemoteLocation};

    #[test]
    fn parse_cat_command_with_inline_credentials() {
        let options = parse_args(
            FileTool::Cat,
            vec![
                "smolder-cat".to_string(),
                "smb://127.0.0.1:1445/share/docs/file.txt".to_string(),
                "--username=smolder".to_string(),
                "--password=smolderpass".to_string(),
                "--domain=WORKGROUP".to_string(),
            ],
        )
        .expect("parser should accept cat arguments");

        assert_eq!(
            options,
            ParsedFileArgs::SingleRemote {
                auth: AuthOptions {
                    username: "smolder".to_string(),
                    password: "smolderpass".to_string(),
                    domain: Some("WORKGROUP".to_string()),
                    workstation: None,
                },
                remote: RemoteLocation {
                    host: "127.0.0.1".to_string(),
                    port: 1445,
                    share: "share".to_string(),
                    path: "docs/file.txt".to_string(),
                },
            }
        );
    }

    #[test]
    fn parse_put_command_with_split_flags() {
        let options = parse_args(
            FileTool::Put,
            vec![
                "smolder-put".to_string(),
                "local.txt".to_string(),
                "smb://server/share/remote.txt".to_string(),
                "--username".to_string(),
                "user".to_string(),
                "--password".to_string(),
                "pass".to_string(),
                "--workstation".to_string(),
                "ws1".to_string(),
            ],
        )
        .expect("parser should accept put arguments");

        match options {
            ParsedFileArgs::Put {
                auth,
                local,
                remote,
            } => {
                assert_eq!(auth.username, "user");
                assert_eq!(auth.password, "pass");
                assert_eq!(auth.workstation.as_deref(), Some("ws1"));
                assert_eq!(local, PathBuf::from("local.txt"));
                assert_eq!(
                    remote,
                    RemoteLocation {
                        host: "server".to_string(),
                        port: 445,
                        share: "share".to_string(),
                        path: "remote.txt".to_string(),
                    }
                );
            }
            other => panic!("unexpected parser output: {other:?}"),
        }
    }

    #[test]
    fn parse_ls_command_allows_share_root() {
        let options = parse_args(
            FileTool::Ls,
            vec![
                "smolder-ls".to_string(),
                "smb://server/share".to_string(),
                "--username=user".to_string(),
                "--password=pass".to_string(),
            ],
        )
        .expect("parser should accept ls arguments");

        match options {
            ParsedFileArgs::SingleRemote { auth, remote } => {
                assert_eq!(auth.username, "user");
                assert_eq!(auth.password, "pass");
                assert_eq!(
                    remote,
                    RemoteLocation {
                        host: "server".to_string(),
                        port: 445,
                        share: "share".to_string(),
                        path: String::new(),
                    }
                );
            }
            other => panic!("unexpected parser output: {other:?}"),
        }
    }

    #[test]
    fn parse_mv_command_accepts_two_remote_urls() {
        let options = parse_args(
            FileTool::Move,
            vec![
                "smolder-mv".to_string(),
                "smb://server/share/old.txt".to_string(),
                "smb://server/share/new.txt".to_string(),
                "--username=user".to_string(),
                "--password=pass".to_string(),
            ],
        )
        .expect("parser should accept mv arguments");

        match options {
            ParsedFileArgs::Move {
                auth,
                source,
                destination,
            } => {
                assert_eq!(auth.username, "user");
                assert_eq!(auth.password, "pass");
                assert_eq!(
                    source,
                    RemoteLocation {
                        host: "server".to_string(),
                        port: 445,
                        share: "share".to_string(),
                        path: "old.txt".to_string(),
                    }
                );
                assert_eq!(
                    destination,
                    RemoteLocation {
                        host: "server".to_string(),
                        port: 445,
                        share: "share".to_string(),
                        path: "new.txt".to_string(),
                    }
                );
            }
            other => panic!("unexpected parser output: {other:?}"),
        }
    }
}
