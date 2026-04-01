use rand::random;

use smolder_core::client::DurableOpenOptions;
use smolder_core::error::CoreError;
use smolder_proto::smb::smb2::{
    CreateContext, CreateDisposition, CreateOptions, CreateRequest, Dialect, FileAttributes,
    LeaseFlags, LeaseState, LeaseV2, RequestedOplockLevel, ShareAccess,
};

use super::{
    FILE_APPEND_DATA, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA, FILE_WRITE_EA, READ_CONTROL, SYNCHRONIZE, normalize_share_path,
};

/// High-level lease request attached to an open operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseRequest {
    key: [u8; 16],
    state: LeaseState,
    parent_key: Option<[u8; 16]>,
}

impl LeaseRequest {
    /// Builds a lease request with an explicit lease key and desired state.
    #[must_use]
    pub fn new(key: [u8; 16], state: LeaseState) -> Self {
        Self {
            key,
            state,
            parent_key: None,
        }
    }

    /// Builds a lease request with a random lease key.
    #[must_use]
    pub fn random(state: LeaseState) -> Self {
        Self::new(random(), state)
    }

    /// Associates a parent-directory lease key with the request.
    #[must_use]
    pub fn with_parent_key(mut self, parent_key: [u8; 16]) -> Self {
        self.parent_key = Some(parent_key);
        self
    }

    pub(crate) fn into_proto(self) -> LeaseV2 {
        LeaseV2::new(self.key, self.state).with_parent_lease_key(self.parent_key)
    }
}

/// Lease metadata granted by the server for an open handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    /// Lease owner key.
    pub key: [u8; 16],
    /// Granted lease state.
    pub state: LeaseState,
    /// Server-provided lease flags.
    pub flags: LeaseFlags,
    /// Parent lease key when present.
    pub parent_key: Option<[u8; 16]>,
    /// Lease epoch.
    pub epoch: u16,
}

impl From<LeaseV2> for Lease {
    fn from(value: LeaseV2) -> Self {
        Self {
            key: value.lease_key,
            state: value.lease_state,
            flags: value.flags,
            parent_key: value.parent_lease_key,
            epoch: value.epoch,
        }
    }
}

/// Rust-style options for opening a remote file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    create: bool,
    truncate: bool,
    create_new: bool,
    lease: Option<LeaseRequest>,
    durable: Option<DurableOpenOptions>,
    resilient_timeout: Option<u32>,
}

impl OpenOptions {
    /// Creates a new set of open options with all flags disabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables or disables read access.
    #[must_use]
    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    /// Enables or disables write access.
    #[must_use]
    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    /// Enables or disables create-if-missing behavior.
    #[must_use]
    pub fn create(mut self, create: bool) -> Self {
        self.create = create;
        self
    }

    /// Enables or disables truncation of an existing file.
    #[must_use]
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.truncate = truncate;
        self
    }

    /// Enables or disables create-new semantics.
    #[must_use]
    pub fn create_new(mut self, create_new: bool) -> Self {
        self.create_new = create_new;
        self
    }

    /// Requests an SMB lease for the opened handle.
    #[must_use]
    pub fn lease(mut self, lease: LeaseRequest) -> Self {
        self.lease = Some(lease);
        self
    }

    /// Requests a durable handle for the opened file.
    #[must_use]
    pub fn durable(mut self, durable: DurableOpenOptions) -> Self {
        self.durable = Some(durable);
        self
    }

    /// Requests handle resiliency for the opened file.
    #[must_use]
    pub fn resilient(mut self, timeout: u32) -> Self {
        self.resilient_timeout = Some(timeout);
        self
    }

    pub(super) fn requests_lease(&self) -> bool {
        self.lease.is_some()
    }

    pub(super) fn resilient_timeout(&self) -> Option<u32> {
        self.resilient_timeout
    }

    pub(super) fn to_create_request(&self, path: &str) -> Result<CreateRequest, CoreError> {
        if !self.read && !self.write {
            return Err(CoreError::InvalidInput(
                "open options must request read and/or write access",
            ));
        }
        if (self.truncate || self.create || self.create_new) && !self.write {
            return Err(CoreError::InvalidInput(
                "create and truncate operations require write access",
            ));
        }

        let mut request = CreateRequest::from_path(&normalize_share_path(path)?);
        request.desired_access = desired_access_mask(self);
        request.share_access = ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE;
        request.file_attributes = FileAttributes::NORMAL;
        request.create_options = CreateOptions::NON_DIRECTORY_FILE;
        request.create_disposition = create_disposition(self);
        if let Some(lease) = self.lease {
            request.requested_oplock_level = RequestedOplockLevel::Lease;
            request.create_contexts = vec![CreateContext::lease_v2(lease.into_proto())];
        }
        Ok(request)
    }

    pub(super) fn durable_options(&self, dialect: Dialect) -> Option<DurableOpenOptions> {
        self.durable.clone().map(|durable| {
            if dialect_supports_durable_v2(dialect) && durable.create_guid.is_none() {
                durable.with_create_guid(random())
            } else {
                durable
            }
        })
    }
}

fn desired_access_mask(options: &OpenOptions) -> u32 {
    let mut desired_access = READ_CONTROL | SYNCHRONIZE;
    if options.read {
        desired_access |= FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES;
    }
    if options.write {
        desired_access |=
            FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
    }
    desired_access
}

fn create_disposition(options: &OpenOptions) -> CreateDisposition {
    if options.create_new {
        CreateDisposition::Create
    } else if options.create && options.truncate {
        CreateDisposition::OverwriteIf
    } else if options.create {
        CreateDisposition::OpenIf
    } else if options.truncate {
        CreateDisposition::Overwrite
    } else {
        CreateDisposition::Open
    }
}

fn dialect_supports_durable_v2(dialect: Dialect) -> bool {
    matches!(dialect, Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311)
}
