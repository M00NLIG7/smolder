#![allow(dead_code)]

use std::error::Error;

use smolder_core::auth::NtlmCredentials;

pub type ExampleResult<T> = Result<T, Box<dyn Error>>;

pub fn required_env(name: &str) -> ExampleResult<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing required environment variable {name}").into())
}

pub fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

pub fn optional_u16_env(name: &str, default: u16) -> ExampleResult<u16> {
    match optional_env(name) {
        Some(value) => value
            .parse::<u16>()
            .map_err(|_| format!("invalid u16 in {name}: {value}").into()),
        None => Ok(default),
    }
}

pub fn required_prefixed_env(prefix: &str, suffix: &str) -> ExampleResult<String> {
    required_env(&prefixed_key(prefix, suffix))
}

pub fn optional_prefixed_env(prefix: &str, suffix: &str) -> Option<String> {
    optional_env(&prefixed_key(prefix, suffix))
}

pub fn optional_prefixed_u16_env(prefix: &str, suffix: &str, default: u16) -> ExampleResult<u16> {
    optional_u16_env(&prefixed_key(prefix, suffix), default)
}

pub fn ntlm_credentials_from_env_prefix(prefix: &str) -> ExampleResult<NtlmCredentials> {
    let mut credentials = NtlmCredentials::new(
        required_prefixed_env(prefix, "USERNAME")?,
        required_prefixed_env(prefix, "PASSWORD")?,
    );
    if let Some(domain) = optional_prefixed_env(prefix, "DOMAIN") {
        credentials = credentials.with_domain(domain);
    }
    if let Some(workstation) = optional_prefixed_env(prefix, "WORKSTATION") {
        credentials = credentials.with_workstation(workstation);
    }
    Ok(credentials)
}

fn prefixed_key(prefix: &str, suffix: &str) -> String {
    format!("{prefix}_{suffix}")
}
