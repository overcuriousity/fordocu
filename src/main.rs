use anyhow::{bail, Context, Result};
use chrono::{DateTime, Local, Utc};
use clap::Parser;
use dialoguer::{Confirm, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;
use sysinfo::System;
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(name = "fordocu")]
#[command(about = "Collect and document directory contents with hashes and metadata")]
#[command(version)]
struct Args {
    #[arg(long, help = "Do not compute MD5 hashes")]
    no_md5: bool,
    #[arg(long, help = "Do not compute SHA-256 hashes")]
    no_sha256: bool,
    #[arg(long, help = "Do not compute SHA-512 hashes")]
    no_sha512: bool,
}

#[derive(Debug, Clone)]
struct HashConfig {
    md5: bool,
    sha256: bool,
    sha512: bool,
}

impl HashConfig {
    fn from_args(args: &Args) -> Result<Self> {
        let cfg = Self {
            md5: !args.no_md5,
            sha256: !args.no_sha256,
            sha512: !args.no_sha512,
        };
        if !cfg.md5 && !cfg.sha256 && !cfg.sha512 {
            bail!("At least one hash algorithm must be enabled.");
        }
        Ok(cfg)
    }
}

#[derive(Debug, Clone)]
struct CaseInfo {
    reference: String,
    source: String,
    reason: String,
    operator: String,
    notes: String,
}

#[derive(Debug, Clone)]
struct HostInfo {
    hostname: String,
    username: String,
    realname: String,
    os: String,
    kernel: String,
    cwd: PathBuf,
}

#[derive(Debug, Clone)]
struct Hashes {
    md5: Option<String>,
    sha256: Option<String>,
    sha512: Option<String>,
}

#[derive(Debug, Clone)]
enum EntryType {
    File,
    Dir,
    Symlink(String),
    Other,
}

#[derive(Debug, Clone)]
struct FileEntry {
    rel_path: String,
    entry_type: EntryType,
    size: u64,
    modified: Option<String>,
    hashes: Option<Hashes>,
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChecksumAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl ChecksumAlgorithm {
    fn as_str(&self) -> &'static str {
        match self {
            ChecksumAlgorithm::Md5 => "MD5",
            ChecksumAlgorithm::Sha1 => "SHA-1",
            ChecksumAlgorithm::Sha256 => "SHA-256",
            ChecksumAlgorithm::Sha512 => "SHA-512",
        }
    }
}

#[derive(Debug, Clone)]
enum ArtifactKind {
    ChecksumFile(ChecksumAlgorithm),
    DetachedSignature,
}

#[derive(Debug, Clone)]
struct ExistingArtifact {
    rel_path: String,
    kind: ArtifactKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationStatus {
    Ok,
    Failed,
    Missing,
    Error,
}

impl VerificationStatus {
    fn as_str(&self) -> &'static str {
        match self {
            VerificationStatus::Ok => "OK",
            VerificationStatus::Failed => "FAILED",
            VerificationStatus::Missing => "MISSING",
            VerificationStatus::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone)]
struct VerificationResult {
    artifact_path: String,
    kind: String,
    status: VerificationStatus,
    summary: String,
    details: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let hash_cfg = HashConfig::from_args(&args)?;

    println!("for-docu v{} - data collection documentation", env!("CARGO_PKG_VERSION"));
    println!();

    let case_info = prompt_case_info()?;
    let host_info = collect_host_info()?;
    let report_name = generate_report_name(&host_info.cwd);
    let sig_name = format!("{}.asc", report_name);

    println!();
    println!("Scanning directory: {}", host_info.cwd.display());
    let (entries, artifacts) = scan_directory(&host_info.cwd, &report_name, &sig_name)?;
    if !artifacts.is_empty() {
        println!("Detected {} existing integrity artifact(s)", artifacts.len());
    }

    println!("Hashing {} file(s)...", entries.iter().filter(|e| matches!(e.entry_type, EntryType::File)).count());
    let entries = hash_entries(entries, &hash_cfg)?;

    let gpg = find_gpg();
    let verification_results = verify_artifacts(&host_info.cwd, &artifacts, gpg.as_deref())?;
    for result in &verification_results {
        match result.status {
            VerificationStatus::Ok => println!("  OK   {}: {}", result.artifact_path, result.summary),
            _ => eprintln!("  {} {}: {}", result.status.as_str(), result.artifact_path, result.summary),
        }
    }

    let report_path = host_info.cwd.join(&report_name);
    write_report(&report_path, &case_info, &host_info, &entries, &hash_cfg, &verification_results)?;

    let report_sha256 = sha256_file(&report_path)?;

    let sig_info = if let Some(gpg) = find_gpg() {
        if Confirm::new()
            .with_prompt("Sign the report with GPG?")
            .default(false)
            .interact()?
        {
            match sign_with_gpg(&gpg, &report_path, &host_info.cwd) {
                Ok(key_id) => {
                    println!("Detached signature written: {}", sig_name);
                    Some(key_id)
                }
                Err(e) => {
                    eprintln!("Warning: GPG signing failed: {}", e);
                    None
                }
            }
        } else {
            None
        }
    } else {
        println!("GPG not found; skipping signature step.");
        None
    };

    println!();
    println!("Report written: {}", report_name);
    println!("Report SHA-256: {}", report_sha256);
    if let Some(key_id) = sig_info {
        println!("GPG signature:  {} (key: {})", sig_name, key_id);
    }

    Ok(())
}

fn prompt_case_info() -> Result<CaseInfo> {
    let reference: String = Input::new()
        .with_prompt("Case reference")
        .interact_text()
        .context("Failed to read case reference")?;

    let source: String = Input::new()
        .with_prompt("Data collection source")
        .interact_text()
        .context("Failed to read data source")?;

    println!("Reason for data collection (empty line to finish):");
    let reason = read_multiline(true, "  reason")?;

    let operator: String = Input::new()
        .with_prompt("Operator / collector name (optional)")
        .allow_empty(true)
        .interact_text()
        .context("Failed to read operator")?;

    println!("Notes (empty line to finish):");
    let notes = read_multiline(false, "  notes")?;

    Ok(CaseInfo {
        reference,
        source,
        reason,
        operator,
        notes,
    })
}

fn read_multiline(required: bool, prompt: &str) -> Result<String> {
    let mut lines = Vec::new();
    loop {
        let line: String = Input::new()
            .with_prompt(prompt)
            .allow_empty(true)
            .interact_text()
            .context("Failed to read multi-line input")?;
        if line.is_empty() {
            break;
        }
        lines.push(line);
    }
    if required && lines.is_empty() {
        bail!("Input is required");
    }
    Ok(lines.join("\n"))
}

fn collect_host_info() -> Result<HostInfo> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let hostname = hostname::get()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let username = whoami::username();
    let realname = whoami::realname();
    let os = System::name().unwrap_or_else(|| "unknown".to_string());
    let kernel = System::kernel_version().unwrap_or_else(|| "unknown".to_string());
    let cwd = std::env::current_dir().context("Failed to get current working directory")?;

    Ok(HostInfo {
        hostname,
        username,
        realname,
        os,
        kernel,
        cwd,
    })
}

fn generate_report_name(cwd: &Path) -> String {
    let now = Local::now();
    let ts = now.format("%Y%m%d_%H%M%S").to_string();
    let mut name = format!("collection_report_{}.txt", ts);
    let mut n = 1;
    while cwd.join(&name).exists() {
        name = format!("collection_report_{}-{}.txt", ts, n);
        n += 1;
    }
    name
}

fn scan_directory(cwd: &Path, report_name: &str, sig_name: &str) -> Result<(Vec<FileEntry>, Vec<ExistingArtifact>)> {
    let walker = WalkDir::new(cwd)
        .follow_links(false)
        .contents_first(false);

    let entries: Vec<_> = walker.into_iter().filter_map(|e| e.ok()).collect();
    let pb = ProgressBar::new(entries.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message("scanning");

    let mut file_entries = Vec::new();
    let mut artifacts = Vec::new();
    for entry in entries {
        let path = entry.path();
        let rel_path = path
            .strip_prefix(cwd)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        let rel_path = if rel_path.is_empty() {
            ".".to_string()
        } else {
            rel_path
        };

        if rel_path == report_name || rel_path == sig_name {
            pb.inc(1);
            continue;
        }

        if let Some(artifact) = detect_artifact(&rel_path) {
            artifacts.push(artifact);
            pb.inc(1);
            continue;
        }

        let metadata = entry.metadata();
        let entry_type = match entry.file_type() {
            t if t.is_file() => EntryType::File,
            t if t.is_dir() => EntryType::Dir,
            t if t.is_symlink() => {
                let target = fs::read_link(path)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "?".to_string());
                EntryType::Symlink(target)
            }
            _ => EntryType::Other,
        };

        let (size, modified) = match metadata {
            Ok(ref m) => (m.len(), format_time(m.modified().ok())),
            Err(_) => (0, None),
        };

        file_entries.push(FileEntry {
            rel_path,
            entry_type,
            size,
            modified,
            hashes: None,
            error: metadata.err().map(|e| e.to_string()),
        });
        pb.inc(1);
    }
    pb.finish_with_message("scan complete");
    Ok((file_entries, artifacts))
}

fn detect_artifact(rel_path: &str) -> Option<ExistingArtifact> {
    let file_name = Path::new(rel_path).file_name()?.to_str()?;
    let lower = file_name.to_lowercase();

    if let Some(alg) = checksum_algorithm_from_name(file_name) {
        return Some(ExistingArtifact {
            rel_path: rel_path.to_string(),
            kind: ArtifactKind::ChecksumFile(alg),
        });
    }

    if lower.ends_with(".asc") || lower.ends_with(".sig") || lower.ends_with(".sign") {
        return Some(ExistingArtifact {
            rel_path: rel_path.to_string(),
            kind: ArtifactKind::DetachedSignature,
        });
    }

    None
}

fn checksum_algorithm_from_name(file_name: &str) -> Option<ChecksumAlgorithm> {
    let upper = file_name.to_uppercase();
    if upper == "MD5SUMS" || upper == "MD5SUMS.TXT" || upper.ends_with(".MD5") {
        return Some(ChecksumAlgorithm::Md5);
    }
    if upper == "SHA1SUMS" || upper == "SHA1SUMS.TXT" || upper.ends_with(".SHA1") {
        return Some(ChecksumAlgorithm::Sha1);
    }
    if upper == "SHA256SUMS" || upper == "SHA256SUMS.TXT" || upper.ends_with(".SHA256") {
        return Some(ChecksumAlgorithm::Sha256);
    }
    if upper == "SHA512SUMS" || upper == "SHA512SUMS.TXT" || upper.ends_with(".SHA512") {
        return Some(ChecksumAlgorithm::Sha512);
    }
    None
}

fn format_time(time: Option<SystemTime>) -> Option<String> {
    time.map(|t| {
        let dt: DateTime<Local> = t.into();
        dt.format("%Y-%m-%d %H:%M:%S %:z").to_string()
    })
}

fn hash_entries(entries: Vec<FileEntry>, cfg: &HashConfig) -> Result<Vec<FileEntry>> {
    let file_indices: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.entry_type, EntryType::File) && e.error.is_none())
        .map(|(i, _)| i)
        .collect();

    let pb = ProgressBar::new(file_indices.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message("hashing");

    let cwd = std::env::current_dir()?;
    let mut entries = entries;
    for i in file_indices {
        let path = cwd.join(&entries[i].rel_path);
        pb.set_message(entries[i].rel_path.clone());
        match hash_file(&path, cfg) {
            Ok(hashes) => entries[i].hashes = Some(hashes),
            Err(e) => entries[i].error = Some(e.to_string()),
        }
        pb.inc(1);
    }
    pb.finish_with_message("hashing complete");
    Ok(entries)
}

fn hash_file(path: &Path, cfg: &HashConfig) -> Result<Hashes> {
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut buf = [0u8; 8192];

    let mut md5_context = cfg.md5.then(md5::Context::new);
    let mut sha256_hasher = cfg.sha256.then(Sha256::new);
    let mut sha512_hasher = cfg.sha512.then(Sha512::new);

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        if let Some(ref mut h) = md5_context {
            h.consume(chunk);
        }
        if let Some(ref mut h) = sha256_hasher {
            h.update(chunk);
        }
        if let Some(ref mut h) = sha512_hasher {
            h.update(chunk);
        }
    }

    Ok(Hashes {
        md5: md5_context.map(|h| format!("{:x}", h.compute())),
        sha256: sha256_hasher.map(|h| format!("{:x}", h.finalize())),
        sha512: sha512_hasher.map(|h| format!("{:x}", h.finalize())),
    })
}

fn hash_file_with_algorithm(path: &Path, alg: ChecksumAlgorithm) -> Result<String> {
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut buf = [0u8; 8192];

    match alg {
        ChecksumAlgorithm::Md5 => {
            let mut hasher = md5::Context::new();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.consume(&buf[..n]);
            }
            Ok(format!("{:x}", hasher.compute()))
        }
        ChecksumAlgorithm::Sha1 => {
            let mut hasher = Sha1::new();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        ChecksumAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        ChecksumAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
    }
}

fn verify_artifacts(
    cwd: &Path,
    artifacts: &[ExistingArtifact],
    gpg: Option<&str>,
) -> Result<Vec<VerificationResult>> {
    let mut results = Vec::new();
    for artifact in artifacts {
        let result = match &artifact.kind {
            ArtifactKind::ChecksumFile(alg) => verify_checksum_file(cwd, &artifact.rel_path, *alg),
            ArtifactKind::DetachedSignature => {
                if let Some(gpg) = gpg {
                    verify_detached_signature(cwd, &artifact.rel_path, gpg)
                } else {
                    Ok(VerificationResult {
                        artifact_path: artifact.rel_path.clone(),
                        kind: "GPG signature".to_string(),
                        status: VerificationStatus::Error,
                        summary: "GPG not available".to_string(),
                        details: vec![],
                    })
                }
            }
        };
        results.push(result.unwrap_or_else(|e| VerificationResult {
            artifact_path: artifact.rel_path.clone(),
            kind: match &artifact.kind {
                ArtifactKind::ChecksumFile(alg) => format!("{} checksum file", alg.as_str()),
                ArtifactKind::DetachedSignature => "GPG signature".to_string(),
            },
            status: VerificationStatus::Error,
            summary: format!("Verification error: {}", e),
            details: vec![],
        }));
    }
    Ok(results)
}

fn verify_checksum_file(
    cwd: &Path,
    rel_path: &str,
    alg: ChecksumAlgorithm,
) -> Result<VerificationResult> {
    let path = cwd.join(rel_path);
    let content = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read checksum file {}", path.display()))?;

    let mut matched = 0usize;
    let mut failed = 0usize;
    let mut missing = 0usize;
    let mut errors = 0usize;
    let mut details = Vec::new();
    let mut parsed_any = false;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some((expected, file_name)) = parse_checksum_line(line) {
            parsed_any = true;
            let file_path = cwd.join(&file_name);
            if !file_path.exists() {
                missing += 1;
                details.push(format!("{}: referenced file not found", file_name));
                continue;
            }
            match hash_file_with_algorithm(&file_path, alg) {
                Ok(actual) => {
                    if actual.eq_ignore_ascii_case(&expected) {
                        matched += 1;
                    } else {
                        failed += 1;
                        details.push(format!(
                            "{}: expected {}, got {}",
                            file_name, expected, actual
                        ));
                    }
                }
                Err(_) => {
                    errors += 1;
                    details.push(format!("{}: could not verify", file_name));
                }
            }
        }
    }

    if !parsed_any {
        return Ok(VerificationResult {
            artifact_path: rel_path.to_string(),
            kind: format!("{} checksum file", alg.as_str()),
            status: VerificationStatus::Error,
            summary: "No valid checksum entries found".to_string(),
            details: vec![],
        });
    }

    let total = matched + failed + missing + errors;
    let status = if failed > 0 || errors > 0 {
        VerificationStatus::Failed
    } else if missing > 0 {
        VerificationStatus::Missing
    } else {
        VerificationStatus::Ok
    };

    let summary = format!(
        "{} matched, {} failed, {} missing, {} errors out of {} entries",
        matched, failed, missing, errors, total
    );

    Ok(VerificationResult {
        artifact_path: rel_path.to_string(),
        kind: format!("{} checksum file", alg.as_str()),
        status,
        summary,
        details,
    })
}

fn parse_checksum_line(line: &str) -> Option<(String, String)> {
    let hash_end = line.find(' ')?;
    let hash = line[..hash_end].to_lowercase();
    let rest = line[hash_end..].trim_start();

    let file_name = if rest.starts_with('*') {
        unescape_filename(&rest[1..])
    } else {
        unescape_filename(rest)
    };

    if hash.is_empty() || file_name.is_empty() {
        return None;
    }

    Some((hash, file_name))
}

fn unescape_filename(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some(other) => result.push(other),
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}

fn verify_detached_signature(
    cwd: &Path,
    rel_path: &str,
    gpg: &str,
) -> Result<VerificationResult> {
    let sig_path = cwd.join(rel_path);
    let signed_rel_path = guess_signed_file(rel_path);
    let signed_path = cwd.join(&signed_rel_path);

    if !signed_path.exists() {
        return Ok(VerificationResult {
            artifact_path: rel_path.to_string(),
            kind: "GPG signature".to_string(),
            status: VerificationStatus::Missing,
            summary: format!("Signed file '{}' not found", signed_rel_path.display()),
            details: vec![],
        });
    }

    let output = Command::new(gpg)
        .arg("--verify")
        .arg(&sig_path)
        .arg(&signed_path)
        .output()
        .context("Failed to run gpg --verify")?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stderr, stdout);

    let (status, summary) = if output.status.success() {
        let signer = extract_gpg_signer(&combined);
        (
            VerificationStatus::Ok,
            signer.unwrap_or_else(|| "Good signature".to_string()),
        )
    } else if combined.contains("BAD signature") {
        (VerificationStatus::Failed, "BAD signature".to_string())
    } else if combined.contains("No public key") || combined.contains("No such file or directory") {
        (VerificationStatus::Error, "Public key not found".to_string())
    } else {
        (
            VerificationStatus::Error,
            format!("GPG verification failed: {}", combined.trim()),
        )
    };

    Ok(VerificationResult {
        artifact_path: rel_path.to_string(),
        kind: "GPG signature".to_string(),
        status,
        summary,
        details: combined.lines().map(|s| s.to_string()).collect(),
    })
}

fn guess_signed_file(rel_path: &str) -> PathBuf {
    let name = Path::new(rel_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let lower = name.to_lowercase();
    let stripped = if lower.ends_with(".asc") {
        &name[..name.len() - 4]
    } else if lower.ends_with(".sig") {
        &name[..name.len() - 4]
    } else if lower.ends_with(".sign") {
        &name[..name.len() - 5]
    } else {
        &name[..]
    };
    PathBuf::from(stripped)
}

fn extract_gpg_signer(output: &str) -> Option<String> {
    for line in output.lines() {
        if let Some(start) = line.find("Good signature from \"") {
            let rest = &line[start + 21..];
            if let Some(end) = rest.find('"') {
                return Some(format!("Good signature from {}", &rest[..end]));
            }
        }
        if let Some(start) = line.find("Good signature from ") {
            return Some(line[start..].to_string());
        }
    }
    None
}

fn write_report(
    path: &Path,
    case: &CaseInfo,
    host: &HostInfo,
    entries: &[FileEntry],
    cfg: &HashConfig,
    verification_results: &[VerificationResult],
) -> Result<()> {
    let mut f = File::create(path).with_context(|| format!("Failed to create {}", path.display()))?;
    let now = Local::now();

    writeln!(f, "================================================================================")?;
    writeln!(f, " DATA COLLECTION REPORT")?;
    writeln!(f, "================================================================================")?;
    writeln!(f)?;
    writeln!(f, "Generated (local): {}", now.format("%Y-%m-%d %H:%M:%S %:z"))?;
    writeln!(f, "Generated (UTC):   {}", Utc::now().format("%Y-%m-%d %H:%M:%S %:z"))?;
    writeln!(f, "Tool:              {} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))?;
    writeln!(f, "Working directory: {}", host.cwd.display())?;
    writeln!(f)?;

    writeln!(f, "CASE INFORMATION")?;
    writeln!(f, "--------------------------------------------------------------------------------")?;
    writeln!(f, "Case reference:             {}", case.reference)?;
    writeln!(f, "Data collection source:     {}", case.source)?;
    writeln!(f, "Reason for data collection: {}", case.reason)?;
    if !case.operator.is_empty() {
        writeln!(f, "Operator / collector:       {}", case.operator)?;
    }
    if !case.notes.is_empty() {
        writeln!(f, "Notes:")?;
        for line in case.notes.lines() {
            writeln!(f, "  {}", line)?;
        }
    }
    writeln!(f)?;

    writeln!(f, "HOST INFORMATION")?;
    writeln!(f, "--------------------------------------------------------------------------------")?;
    writeln!(f, "Hostname: {}", host.hostname)?;
    writeln!(f, "Username: {}", host.username)?;
    if !host.realname.is_empty() && host.realname != host.username {
        writeln!(f, "Realname: {}", host.realname)?;
    }
    writeln!(f, "OS:       {}", host.os)?;
    writeln!(f, "Kernel:   {}", host.kernel)?;
    writeln!(f)?;

    if !verification_results.is_empty() {
        writeln!(f, "EXISTING INTEGRITY ARTIFACTS")?;
        writeln!(f, "--------------------------------------------------------------------------------")?;
        for result in verification_results {
            writeln!(
                f,
                "[{}] {} ({}): {}",
                result.status.as_str(),
                result.artifact_path,
                result.kind,
                result.summary
            )?;
            for detail in &result.details {
                writeln!(f, "         {}", detail)?;
            }
        }
        writeln!(f)?;
    }

    writeln!(f, "DIRECTORY LISTING")?;
    writeln!(f, "--------------------------------------------------------------------------------")?;
    writeln!(f, "Total entries: {}", entries.len())?;
    let file_count = entries.iter().filter(|e| matches!(e.entry_type, EntryType::File)).count();
    writeln!(f, "Files listed:  {}", file_count)?;
    writeln!(f)?;

    // Header line for table
    write!(f, "Type     Size          Modified              Path")?;
    if cfg.md5 {
        write!(f, "  MD5")?;
    }
    if cfg.sha256 {
        write!(f, "  SHA-256")?;
    }
    if cfg.sha512 {
        write!(f, "  SHA-512")?;
    }
    writeln!(f)?;
    writeln!(f, "--------------------------------------------------------------------------------")?;

    for entry in entries {
        let type_str = match &entry.entry_type {
            EntryType::File => "file",
            EntryType::Dir => "dir ",
            EntryType::Symlink(_) => "link",
            EntryType::Other => "other",
        };
        let size_str = if matches!(entry.entry_type, EntryType::Dir | EntryType::Symlink(_)) {
            "-".to_string()
        } else {
            format!("{}", entry.size)
        };
        let modified_str = entry.modified.clone().unwrap_or_else(|| "-".to_string());
        writeln!(
            f,
            "{:<8} {:<13} {:<23} {}",
            type_str,
            size_str,
            modified_str,
            entry.rel_path
        )?;

        if let EntryType::Symlink(target) = &entry.entry_type {
            writeln!(f, "         -> {}", target)?;
        }

        if let Some(err) = &entry.error {
            writeln!(f, "         ERROR: {}", err)?;
        } else if let Some(hashes) = &entry.hashes {
            if cfg.md5 && let Some(h) = &hashes.md5 {
                writeln!(f, "         MD5:    {}", h)?;
            }
            if cfg.sha256 && let Some(h) = &hashes.sha256 {
                writeln!(f, "         SHA-256: {}", h)?;
            }
            if cfg.sha512 && let Some(h) = &hashes.sha512 {
                writeln!(f, "         SHA-512: {}", h)?;
            }
        }
    }

    let errors: Vec<_> = entries.iter().filter(|e| e.error.is_some()).collect();
    if !errors.is_empty() {
        writeln!(f)?;
        writeln!(f, "ERRORS")?;
        writeln!(f, "--------------------------------------------------------------------------------")?;
        for entry in errors {
            writeln!(f, "  {}: {}", entry.rel_path, entry.error.as_ref().unwrap())?;
        }
    }

    writeln!(f)?;
    writeln!(f, "================================================================================")?;
    writeln!(
        f,
        "Documented via fordocu v{} — https://github.com/overcuriousity/fordocu",
        env!("CARGO_PKG_VERSION")
    )?;
    writeln!(f, "================================================================================")?;

    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn find_gpg() -> Option<String> {
    for cmd in &["gpg", "gpg2"] {
        if Command::new(cmd).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok() {
            return Some(cmd.to_string());
        }
    }
    None
}

fn sign_with_gpg(gpg: &str, report_path: &Path, _cwd: &Path) -> Result<String> {
    let keys = list_secret_keys(gpg)?;
    if keys.is_empty() {
        bail!("No GPG secret keys found");
    }

    let key_id = if keys.len() == 1 {
        println!("Using the only available GPG secret key: {} - {}", keys[0].0, keys[0].1);
        keys[0].0.clone()
    } else {
        let items: Vec<String> = keys
            .iter()
            .map(|(key_id, uid)| format!("{} - {}", key_id, uid))
            .collect();
        let selection = Select::new()
            .with_prompt("Select GPG signing key")
            .items(&items)
            .interact()
            .context("Failed to select GPG key")?;
        keys[selection].0.clone()
    };

    let sig_path = PathBuf::from(format!("{}.asc", report_path.display()));

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message("Signing report with GPG...");

    let status = Command::new(gpg)
        .arg("--detach-sign")
        .arg("--armor")
        .arg("--local-user")
        .arg(&key_id)
        .arg("--output")
        .arg(&sig_path)
        .arg(report_path)
        .status()
        .context("Failed to run gpg")?;

    pb.finish_with_message("GPG signing complete");

    if !status.success() {
        bail!("gpg returned non-zero exit status");
    }
    if !sig_path.exists() {
        bail!("Signature file was not created");
    }

    Ok(key_id)
}

fn list_secret_keys(gpg: &str) -> Result<Vec<(String, String)>> {
    let output = Command::new(gpg)
        .args(["--list-secret-keys", "--with-colons"])
        .output()
        .context("Failed to list GPG secret keys")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut keys = Vec::new();
    let mut current_key: Option<String> = None;

    for line in stdout.lines() {
        if line.starts_with("sec:") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 4 && !parts[4].is_empty() {
                current_key = Some(parts[4].to_string());
            }
        } else if line.starts_with("uid:") && let Some(ref key_id) = current_key {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 9 {
                let uid = parts[9].to_string();
                keys.push((key_id.clone(), uid));
                current_key = None;
            }
        }
    }

    Ok(keys)
}
