//! DFS-aware UNC parsing and referral resolution helpers.

use crate::error::CoreError;

/// A normalized UNC path split into its server, share, and path components.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UncPath {
    server: String,
    share: String,
    path: Vec<String>,
}

impl UncPath {
    /// Parses and normalizes a UNC path.
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        let trimmed = value
            .strip_prefix(r"\\")
            .ok_or(CoreError::PathInvalid("UNC path must start with \\\\"))?;
        let mut parts = trimmed
            .split(['\\', '/'])
            .filter(|segment| !segment.is_empty());
        let server = normalize_component(
            parts
                .next()
                .ok_or(CoreError::PathInvalid("UNC path must include a server"))?,
            "UNC path server must not be empty",
        )?;
        let share = normalize_component(
            parts
                .next()
                .ok_or(CoreError::PathInvalid("UNC path must include a share"))?,
            "UNC path share must not be empty",
        )?;
        let mut path = Vec::new();
        for segment in parts {
            path.push(normalize_path_segment(segment)?);
        }

        Ok(Self {
            server,
            share,
            path,
        })
    }

    /// Returns the server component.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Returns the share component.
    #[must_use]
    pub fn share(&self) -> &str {
        &self.share
    }

    /// Returns the normalized path segments after the share.
    #[must_use]
    pub fn path(&self) -> &[String] {
        &self.path
    }

    /// Returns the `\\server\share` prefix for this UNC path.
    #[must_use]
    pub fn share_unc(&self) -> String {
        format!(r"\\{}\{}", self.server, self.share)
    }

    /// Returns the fully normalized UNC string.
    #[must_use]
    pub fn as_unc(&self) -> String {
        if self.path.is_empty() {
            return self.share_unc();
        }

        format!(r"{}\{}", self.share_unc(), self.path.join(r"\"))
    }

    /// Returns true when `self` starts with the namespace prefix `other`.
    #[must_use]
    pub fn starts_with(&self, other: &Self) -> bool {
        component_eq(&self.server, &other.server)
            && component_eq(&self.share, &other.share)
            && self.path.len() >= other.path.len()
            && self
                .path
                .iter()
                .zip(other.path.iter())
                .all(|(left, right)| component_eq(left, right))
    }

    fn with_appended_suffix(&self, suffix: &[String]) -> Self {
        let mut path = self.path.clone();
        path.extend(suffix.iter().cloned());
        Self {
            server: self.server.clone(),
            share: self.share.clone(),
            path,
        }
    }
}

/// A DFS referral mapping a namespace path to a concrete target UNC path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DfsReferral {
    /// The DFS namespace path that should be replaced.
    pub namespace_path: UncPath,
    /// The concrete target UNC path for the namespace prefix.
    pub target_path: UncPath,
}

impl DfsReferral {
    /// Creates a referral mapping from a namespace prefix to a concrete target.
    #[must_use]
    pub fn new(namespace_path: UncPath, target_path: UncPath) -> Self {
        Self {
            namespace_path,
            target_path,
        }
    }
}

/// Resolves a UNC path through the provided DFS referrals.
///
/// The longest matching namespace prefix wins. When no referral matches, the
/// original path is returned unchanged.
#[must_use]
pub fn resolve_unc_path(path: &UncPath, referrals: &[DfsReferral]) -> UncPath {
    let Some(referral) = referrals
        .iter()
        .filter(|referral| path.starts_with(&referral.namespace_path))
        .max_by_key(|referral| referral.namespace_path.path.len())
    else {
        return path.clone();
    };

    let suffix = &path.path[referral.namespace_path.path.len()..];
    referral.target_path.with_appended_suffix(suffix)
}

fn normalize_component(value: &str, empty_message: &'static str) -> Result<String, CoreError> {
    if value.is_empty() {
        return Err(CoreError::PathInvalid(empty_message));
    }
    Ok(value.to_string())
}

fn normalize_path_segment(segment: &str) -> Result<String, CoreError> {
    if segment == "." || segment == ".." {
        return Err(CoreError::PathInvalid(
            "UNC paths must not contain relative path segments",
        ));
    }
    normalize_component(segment, "UNC path segments must not be empty")
}

fn component_eq(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

#[cfg(test)]
mod tests {
    use super::{resolve_unc_path, DfsReferral, UncPath};

    #[test]
    fn parses_normalized_unc_paths() {
        let path = UncPath::parse(r"\\server/share\docs\report.txt")
            .expect("UNC path should parse");

        assert_eq!(path.server(), "server");
        assert_eq!(path.share(), "share");
        assert_eq!(path.path(), ["docs", "report.txt"]);
        assert_eq!(path.share_unc(), r"\\server\share");
        assert_eq!(path.as_unc(), r"\\server\share\docs\report.txt");
    }

    #[test]
    fn rejects_relative_unc_segments() {
        let error = UncPath::parse(r"\\server\share\..\secret.txt")
            .expect_err("relative segments should fail");

        assert_eq!(
            error.to_string(),
            "invalid path: UNC paths must not contain relative path segments"
        );
    }

    #[test]
    fn resolves_longest_matching_referral_prefix() {
        let original = UncPath::parse(r"\\domain\dfs\team\docs\report.txt")
            .expect("original path should parse");
        let namespace_root = DfsReferral::new(
            UncPath::parse(r"\\domain\dfs").expect("root namespace should parse"),
            UncPath::parse(r"\\server-a\root").expect("root target should parse"),
        );
        let namespace_branch = DfsReferral::new(
            UncPath::parse(r"\\domain\dfs\team").expect("branch namespace should parse"),
            UncPath::parse(r"\\server-b\teamshare\docs").expect("branch target should parse"),
        );

        let resolved = resolve_unc_path(&original, &[namespace_root, namespace_branch]);

        assert_eq!(resolved.as_unc(), r"\\server-b\teamshare\docs\docs\report.txt");
    }

    #[test]
    fn leaves_non_matching_paths_unchanged() {
        let original = UncPath::parse(r"\\domain\dfs\team\docs\report.txt")
            .expect("original path should parse");
        let referral = DfsReferral::new(
            UncPath::parse(r"\\other\dfs").expect("namespace should parse"),
            UncPath::parse(r"\\server\share").expect("target should parse"),
        );

        let resolved = resolve_unc_path(&original, &[referral]);

        assert_eq!(resolved, original);
    }
}
