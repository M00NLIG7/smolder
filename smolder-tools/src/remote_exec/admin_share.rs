use smolder_core::client::{Connection, TreeConnected};
use smolder_core::error::CoreError;
use smolder_core::pipe::{SmbSessionConfig, connect_tree};
use smolder_core::transport::TokioTcpTransport;
use smolder_proto::smb::smb2::{
    CloseRequest, CreateDisposition, CreateOptions, CreateRequest, DispositionInformation,
    FileAttributes, FileId, FileInfoClass, FlushRequest, ReadRequest, SetInfoRequest, ShareAccess,
    WriteRequest,
};

use super::{
    DELETE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    READ_CONTROL, SYNCHRONIZE, is_end_of_file, is_not_found, normalize_share_path,
};

pub(super) struct AdminShare {
    connection: Connection<TokioTcpTransport, TreeConnected>,
    max_read_size: u32,
    max_write_size: u32,
}

impl AdminShare {
    pub(super) async fn connect(config: &SmbSessionConfig, share: &str) -> Result<Self, CoreError> {
        let connection = connect_tree(config, share).await?;
        let max_read_size = connection
            .state()
            .negotiated
            .max_read_size
            .min(u32::from(u16::MAX))
            .max(1);
        let max_write_size = connection
            .state()
            .negotiated
            .max_write_size
            .min(u32::from(u16::MAX))
            .max(1);
        Ok(Self {
            connection,
            max_read_size,
            max_write_size,
        })
    }

    pub(super) async fn read_if_exists(
        &mut self,
        path: &str,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let file_id = match self
            .open_file(path, FILE_READ_DATA | FILE_READ_ATTRIBUTES)
            .await
        {
            Ok(file_id) => file_id,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };

        let mut offset = 0_u64;
        let mut output = Vec::new();
        let read_result = async {
            loop {
                let response = match self
                    .connection
                    .read(&ReadRequest::for_file(file_id, offset, self.max_read_size))
                    .await
                {
                    Ok(response) => response,
                    Err(error) if is_end_of_file(&error) => break,
                    Err(error) => return Err(error),
                };
                if response.data.is_empty() {
                    break;
                }
                offset += response.data.len() as u64;
                let reached_end = response.data.len() < self.max_read_size as usize;
                output.extend_from_slice(&response.data);
                if reached_end {
                    break;
                }
            }
            Ok::<(), CoreError>(())
        }
        .await;
        let close_result = self.close(file_id).await;
        match read_result {
            Ok(()) => {
                close_result?;
                Ok(Some(output))
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    pub(super) async fn write_all(&mut self, path: &str, data: &[u8]) -> Result<(), CoreError> {
        let file_id = self
            .create_file(path, FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES)
            .await?;
        let mut offset = 0_u64;
        let write_result = async {
            while (offset as usize) < data.len() {
                let chunk_end = ((offset as usize) + self.max_write_size as usize).min(data.len());
                let request = WriteRequest::for_file(
                    file_id,
                    offset,
                    data[offset as usize..chunk_end].to_vec(),
                );
                let response = self.connection.write(&request).await?;
                if response.count == 0 {
                    return Err(CoreError::InvalidResponse(
                        "admin share write returned zero bytes",
                    ));
                }
                offset += response.count as u64;
            }
            let _ = self
                .connection
                .flush(&FlushRequest::for_file(file_id))
                .await;
            Ok::<(), CoreError>(())
        }
        .await;
        let close_result = self.close(file_id).await;
        match write_result {
            Ok(()) => {
                close_result?;
                Ok(())
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    pub(super) async fn try_remove(&mut self, path: &str) -> Result<(), CoreError> {
        let file_id = match self
            .open_file(path, DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
            .await
        {
            Ok(file_id) => file_id,
            Err(error) if is_not_found(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        let delete_result = self
            .connection
            .set_info(&SetInfoRequest::for_file_info(
                file_id,
                FileInfoClass::DispositionInformation,
                DispositionInformation {
                    delete_pending: true,
                }
                .encode(),
            ))
            .await;
        let close_result = self.close(file_id).await;
        match delete_result {
            Ok(_) => {
                close_result?;
                Ok(())
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    async fn open_file(&mut self, path: &str, desired_access: u32) -> Result<FileId, CoreError> {
        let normalized = normalize_share_path(path)?;
        let mut request = CreateRequest::from_path(&normalized);
        request.desired_access = desired_access | READ_CONTROL | SYNCHRONIZE;
        request.create_disposition = CreateDisposition::Open;
        request.share_access = ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE;
        request.file_attributes = FileAttributes::NORMAL;
        request.create_options = CreateOptions::NON_DIRECTORY_FILE;
        self.connection
            .create(&request)
            .await
            .map(|response| response.file_id)
    }

    async fn create_file(&mut self, path: &str, desired_access: u32) -> Result<FileId, CoreError> {
        let normalized = normalize_share_path(path)?;
        let mut request = CreateRequest::from_path(&normalized);
        request.desired_access = desired_access | READ_CONTROL | SYNCHRONIZE;
        request.create_disposition = CreateDisposition::OverwriteIf;
        request.share_access = ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE;
        request.file_attributes = FileAttributes::NORMAL;
        request.create_options = CreateOptions::NON_DIRECTORY_FILE;
        self.connection
            .create(&request)
            .await
            .map(|response| response.file_id)
    }

    async fn close(&mut self, file_id: FileId) -> Result<(), CoreError> {
        let _ = self
            .connection
            .close(&CloseRequest { flags: 0, file_id })
            .await?;
        Ok(())
    }
}
