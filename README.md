# Smolder 🔥

A blazing fast, pure Rust implementation of the SMB protocol for security testing and assessment, inspired by projects like Impacket. This project aims to provide similar capabilities in a modern, memory-safe Rust environment.

## Overview

Smolder is a comprehensive SMB protocol toolkit written in Rust, designed specifically for security testing. It provides low-level control over SMB operations while maintaining high performance and memory safety.

## Features

- 🛡️ Pure Rust implementation of SMB protocol
- 🚀 Async/await support for high performance
- 🔧 Low-level protocol control for security testing
- 🔒 NTLM and Kerberos authentication support
- 🛠️ Example tools inspired by various security testing utilities
- 📦 Zero external dependencies for core protocol implementation

## Quick Start

```rust
use smolder::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    let conn = SMBConnection::new()
        .with_credentials(Credentials::ntlm("username", "password"))
        .connect("192.168.1.1", 445)
        .await?;
    
    // Your SMB operations here
}
```

## Security Notice

This tool is designed for security research and penetration testing. Always ensure you have proper authorization before testing any systems or networks.

## License

MIT License - Copyright (c) 2025 M00NLIG7

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
