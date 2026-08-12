mod archive;
mod executable_swap;
mod installation;

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use ureq::Agent;

use self::archive::extract_binary;
use self::executable_swap::swap_executable;
use self::installation::{detect_install_method, manager_command};
use super::check::is_newer_version;
use super::source::{release_api_url, release_asset_name, release_asset_url};

pub use self::installation::InstallMethod;

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    ManagerCompleted(InstallMethod),
    Updated {
        method: InstallMethod,
        previous_version: String,
        new_version: String,
    },
    UpToDate {
        method: InstallMethod,
        version: String,
    },
}

impl fmt::Display for UpdateOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManagerCompleted(method) => write!(f, "Update completed through {method}."),
            Self::Updated {
                method,
                previous_version,
                new_version,
            } => write!(
                f,
                "Updated tuicr from {previous_version} to {new_version} ({method})."
            ),
            Self::UpToDate { method, version } => {
                write!(f, "tuicr {version} is already up to date ({method}).")
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("could not locate the running tuicr executable: {0}")]
    CurrentExecutable(#[source] std::io::Error),
    #[error("failed to fetch update metadata: {0}")]
    Network(String),
    #[error("invalid GitHub release metadata: {0}")]
    ReleaseMetadata(String),
    #[error("tuicr does not publish pre-built binaries for {arch}-{os}")]
    UnsupportedPlatform { os: String, arch: String },
    #[error("release asset '{0}' was not found")]
    MissingAsset(String),
    #[error("release asset '{0}' has no SHA-256 digest; refusing an unverified update")]
    MissingDigest(String),
    #[error("SHA-256 verification failed for '{0}'")]
    Integrity(String),
    #[error("failed to extract '{asset}': {detail}")]
    Archive { asset: String, detail: String },
    #[error("{0} cannot install a specific tuicr version; use that manager's pinning workflow")]
    VersionPinUnsupported(InstallMethod),
    #[error("{method} could not update tuicr: {detail}")]
    Manager {
        method: InstallMethod,
        detail: String,
    },
    #[error("could not replace '{path}': {detail}")]
    Replace { path: PathBuf, detail: String },
}

pub fn update_installed() -> Result<UpdateOutcome, UpdateError> {
    update_with_runtime(&SystemRuntime, UpdateContext::current()?)
}

pub fn update_to_version(version: &Version) -> Result<UpdateOutcome, UpdateError> {
    update_version_with_runtime(&SystemRuntime, UpdateContext::current()?, version)
}

#[derive(Debug)]
struct UpdateContext {
    executable: PathBuf,
    method: InstallMethod,
    current_version: String,
    os: String,
    arch: String,
}

impl UpdateContext {
    fn current() -> Result<Self, UpdateError> {
        let executable = std::env::current_exe().map_err(UpdateError::CurrentExecutable)?;
        let executable = canonical_executable(&executable)?;
        let home = directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf());
        let cargo_home = std::env::var_os("CARGO_HOME").map(PathBuf::from);
        let method = detect_install_method(&executable, home.as_deref(), cargo_home.as_deref());

        Ok(Self {
            executable,
            method,
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
        })
    }
}

fn canonical_executable(executable: &Path) -> Result<PathBuf, UpdateError> {
    std::fs::canonicalize(executable).map_err(UpdateError::CurrentExecutable)
}

trait UpdateRuntime {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, UpdateError>;
    fn run_command(
        &self,
        method: InstallMethod,
        program: &str,
        args: &[&str],
    ) -> Result<(), UpdateError>;
    fn replace_executable(&self, path: &Path, contents: &[u8]) -> Result<(), UpdateError>;
}

struct SystemRuntime;

impl UpdateRuntime for SystemRuntime {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, UpdateError> {
        let config = Agent::config_builder()
            .timeout_global(Some(DOWNLOAD_TIMEOUT))
            .build();
        let agent: Agent = config.into();
        agent
            .get(url)
            .header("User-Agent", concat!("tuicr/", env!("CARGO_PKG_VERSION")))
            .header("Accept", "application/vnd.github+json")
            .call()
            .map_err(|error| UpdateError::Network(error.to_string()))?
            .into_body()
            .read_to_vec()
            .map_err(|error| UpdateError::Network(error.to_string()))
    }

    fn run_command(
        &self,
        method: InstallMethod,
        program: &str,
        args: &[&str],
    ) -> Result<(), UpdateError> {
        let rendered = display_command(program, args);
        let status =
            Command::new(program)
                .args(args)
                .status()
                .map_err(|error| UpdateError::Manager {
                    method,
                    detail: format!("failed to run `{rendered}`: {error}"),
                })?;
        status.success().then_some(()).ok_or(UpdateError::Manager {
            method,
            detail: format!("`{rendered}` exited with {status}"),
        })
    }

    fn replace_executable(&self, path: &Path, contents: &[u8]) -> Result<(), UpdateError> {
        swap_executable(path, contents)
    }
}

fn update_with_runtime(
    runtime: &impl UpdateRuntime,
    context: UpdateContext,
) -> Result<UpdateOutcome, UpdateError> {
    update_with_optional_version(runtime, context, None)
}

fn update_version_with_runtime(
    runtime: &impl UpdateRuntime,
    context: UpdateContext,
    version: &Version,
) -> Result<UpdateOutcome, UpdateError> {
    update_with_optional_version(runtime, context, Some(version))
}

fn update_with_optional_version(
    runtime: &impl UpdateRuntime,
    context: UpdateContext,
    requested_version: Option<&Version>,
) -> Result<UpdateOutcome, UpdateError> {
    let method = context.method;
    if requested_version.is_some()
        && !matches!(method, InstallMethod::Cargo | InstallMethod::Direct)
    {
        return Err(UpdateError::VersionPinUnsupported(method));
    }

    let (release, release_version) = fetch_release(runtime, requested_version)?;
    if !should_install(
        &context.current_version,
        &release_version,
        requested_version,
    ) {
        return Ok(UpdateOutcome::UpToDate {
            method,
            version: context.current_version,
        });
    }

    if matches!(method, InstallMethod::Cargo | InstallMethod::Direct) {
        let binary_update = install_release_binary(runtime, &context, &release, &release_version);
        if method == InstallMethod::Cargo
            && matches!(
                binary_update,
                Err(UpdateError::UnsupportedPlatform { .. } | UpdateError::MissingAsset(_))
            )
        {
            return run_cargo_install(runtime, requested_version);
        }
        return binary_update;
    }

    let command =
        manager_command(method).expect("managed install method must have an update command");
    runtime.run_command(method, command.program, command.args)?;
    Ok(UpdateOutcome::ManagerCompleted(method))
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    // GitHub computes SHA-256 digests when release assets are uploaded:
    // https://github.blog/changelog/2025-06-03-releases-now-expose-digests-for-release-assets/
    // Keep this optional so missing data fails closed instead of breaking deserialization.
    digest: Option<String>,
}

fn fetch_release(
    runtime: &impl UpdateRuntime,
    requested_version: Option<&Version>,
) -> Result<(GitHubRelease, Version), UpdateError> {
    let metadata = runtime.fetch(&release_api_url(requested_version))?;
    let release: GitHubRelease = serde_json::from_slice(&metadata)
        .map_err(|error| UpdateError::ReleaseMetadata(error.to_string()))?;
    let release_version = Version::parse(release.tag_name.trim_start_matches('v'))
        .map_err(|error| UpdateError::ReleaseMetadata(error.to_string()))?;
    if let Some(requested) = requested_version.filter(|requested| *requested != &release_version) {
        return Err(UpdateError::ReleaseMetadata(format!(
            "requested {requested}, but GitHub returned {release_version}"
        )));
    }
    Ok((release, release_version))
}

fn should_install(
    current_version: &str,
    release_version: &Version,
    requested_version: Option<&Version>,
) -> bool {
    requested_version.map_or_else(
        || is_newer_version(current_version, &release_version.to_string()),
        |requested| Version::parse(current_version).map_or(true, |current| current != *requested),
    )
}

fn install_release_binary(
    runtime: &impl UpdateRuntime,
    context: &UpdateContext,
    release: &GitHubRelease,
    release_version: &Version,
) -> Result<UpdateOutcome, UpdateError> {
    let release_version = release_version.to_string();
    let asset_name = release_asset_name(&release_version, &context.os, &context.arch)?;
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == asset_name)
        .ok_or_else(|| UpdateError::MissingAsset(asset_name.clone()))?;
    let expected_digest = asset
        .digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .ok_or_else(|| UpdateError::MissingDigest(asset.name.clone()))?;
    let archive = runtime.fetch(&release_asset_url(&release_version, &asset.name))?;
    if !format!("{:x}", Sha256::digest(&archive)).eq_ignore_ascii_case(expected_digest) {
        return Err(UpdateError::Integrity(asset.name.clone()));
    }

    let binary = extract_binary(&asset.name, &archive)?;
    runtime.replace_executable(&context.executable, &binary)?;
    Ok(UpdateOutcome::Updated {
        method: context.method,
        previous_version: context.current_version.clone(),
        new_version: release_version,
    })
}

fn run_cargo_install(
    runtime: &impl UpdateRuntime,
    requested_version: Option<&Version>,
) -> Result<UpdateOutcome, UpdateError> {
    let version = requested_version.map(ToString::to_string);
    let mut args = vec!["install", "tuicr"];
    if let Some(version) = version.as_deref() {
        args.extend(["--version", version]);
    }
    args.push("--force");
    runtime.run_command(InstallMethod::Cargo, "cargo", &args)?;
    Ok(UpdateOutcome::ManagerCompleted(InstallMethod::Cargo))
}

fn display_command(program: &str, args: &[&str]) -> String {
    std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests;
