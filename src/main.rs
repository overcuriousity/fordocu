use anyhow::{bail, Context, Result};
use chrono::{DateTime, Local, Utc};
use clap::Parser;
use dialoguer::{Confirm, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
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
    let entries = scan_directory(&host_info.cwd, &report_name, &sig_name)?;

    println!("Hashing {} file(s)...", entries.iter().filter(|e| matches!(e.entry_type, EntryType::File)).count());
    let entries = hash_entries(entries, &hash_cfg)?;

    let report_path = host_info.cwd.join(&report_name);
    write_report(&report_path, &case_info, &host_info, &entries, &hash_cfg)?;

    let report_sha256 = sha256_file(&report_path)?;

    let sig_info = if let Some(gpg) = find_gpg() {
        if Confirm::new()
            .with_prompt("Sign the report with GPG?")
            .default(false)
            .interact()?
        {
            // Append the integrity footer before signing so the signature covers it.
            append_integrity_footer(&report_path, &report_name, &report_sha256, true)?;
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
            append_integrity_footer(&report_path, &report_name, &report_sha256, false)?;
            None
        }
    } else {
        println!("GPG not found; skipping signature step.");
        append_integrity_footer(&report_path, &report_name, &report_sha256, false)?;
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

fn scan_directory(cwd: &Path, report_name: &str, sig_name: &str) -> Result<Vec<FileEntry>> {
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

    let mut result = Vec::new();
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

        result.push(FileEntry {
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
    Ok(result)
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

fn write_report(
    path: &Path,
    case: &CaseInfo,
    host: &HostInfo,
    entries: &[FileEntry],
    cfg: &HashConfig,
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

fn append_integrity_footer(
    path: &Path,
    report_name: &str,
    report_sha256: &str,
    signed: bool,
) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(path)
        .with_context(|| format!("Failed to open {} for appending", path.display()))?;

    writeln!(f)?;
    writeln!(f, "REPORT INTEGRITY")?;
    writeln!(f, "--------------------------------------------------------------------------------")?;
    writeln!(f, "Report file:    {}", report_name)?;
    writeln!(f, "Report SHA-256: {}", report_sha256)?;
    if signed {
        writeln!(f, "GPG signature:  {}.asc", report_name)?;
    } else {
        writeln!(f, "GPG signature:  none")?;
    }
    writeln!(f, "================================================================================")?;
    Ok(())
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
