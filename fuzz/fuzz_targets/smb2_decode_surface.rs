#![no_main]

use libfuzzer_sys::fuzz_target;
use smolder_proto::smb::smb2::{
    ChangeNotifyRequest, CreateRequest, Header, IoctlRequest, LockRequest, NegotiateRequest,
    ReadRequest, SessionSetupRequest, TreeConnectRequest, WriteRequest,
};
use smolder_proto::smb::transform::TransformHeader;

fuzz_target!(|data: &[u8]| {
    let _ = Header::decode(data);
    let _ = TransformHeader::decode(data);
    let _ = NegotiateRequest::decode(data);
    let _ = SessionSetupRequest::decode(data);
    let _ = TreeConnectRequest::decode(data);
    let _ = CreateRequest::decode(data);
    let _ = ReadRequest::decode(data);
    let _ = WriteRequest::decode(data);
    let _ = IoctlRequest::decode(data);
    let _ = ChangeNotifyRequest::decode(data);
    let _ = LockRequest::decode(data);
});
