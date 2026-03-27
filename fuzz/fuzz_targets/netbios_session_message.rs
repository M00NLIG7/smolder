#![no_main]

use libfuzzer_sys::fuzz_target;
use smolder_proto::smb::netbios::SessionMessage;

fuzz_target!(|data: &[u8]| {
    let _ = SessionMessage::decode(data);
});
