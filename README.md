# fordocu

Interactive directory documentation for data collection.

`fordocu` runs without arguments, asks a few questions about the case/source/reason, then writes a timestamped plain-text report of the current working directory. The report contains a recursive listing, file sizes, modification times, and MD5/SHA-256/SHA-512 hashes. An optional detached GPG signature can be created alongside the report.

## Installation

### Quick install (Linux / macOS / WSL)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/overcuriousity/fordocu/master/install.sh | bash
```

The installer downloads the latest release for your platform and places the binary in `~/.local/bin` (preferred) or `/usr/local/bin`.

You can override the install location:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/overcuriousity/fordocu/master/install.sh | PREFIX=/opt/bin bash
```

### Manual install

1. Download the archive for your platform from the [latest release](https://github.com/overcuriousity/fordocu/releases/latest).
2. Extract the binary.
3. Move it to a directory on your `PATH`, for example:

```bash
mkdir -p ~/.local/bin
tar -xzf fordocu-x86_64-unknown-linux-gnu.tar.gz -C ~/.local/bin
```

### From source

```bash
git clone https://github.com/overcuriousity/fordocu.git
cd fordocu
cargo build --release
# binary is at target/release/fordocu
cp target/release/fordocu ~/.local/bin/
```

## Usage

Run without arguments inside the directory you want to document:

```bash
fordocu
```

The tool interactively asks for:

- Case reference
- Data collection source
- Reason for data collection
- Operator / collector name (optional)
- Notes (optional)

It then scans the directory recursively, computes hashes, writes `collection_report_<timestamp>.txt`, and optionally signs it with GPG.

### Existing integrity artifacts

If the directory already contains integrity artifacts, `fordocu` detects and verifies them before creating the new report:

- Checksum files: `SHA256SUMS`, `SHA256SUMS.txt`, `MD5SUMS`, `MD5SUMS.txt`, `SHA1SUMS`, `SHA1SUMS.txt`, `SHA512SUMS`, `SHA512SUMS.txt`, or files ending in `.md5`, `.sha1`, `.sha256`, `.sha512`.
- Detached signatures: files ending in `.asc`, `.sig`, or `.sign`.

For checksum files, each entry is re-computed and compared to the expected value. For detached signatures, `fordocu` tries to find the corresponding signed file and verifies it with GPG. The verification result is printed to the console and recorded in the report under **EXISTING INTEGRITY ARTIFACTS**.

These artifacts are excluded from the directory listing so they are not treated as part of the acquired data.

## CLI options

```
Collect and document directory contents with hashes and metadata

Usage: fordocu [OPTIONS]

Options:
      --no-md5     Do not compute MD5 hashes
      --no-sha256  Do not compute SHA-256 hashes
      --no-sha512  Do not compute SHA-512 hashes
  -h, --help       Print help
```

## Output

- `collection_report_<timestamp>.txt` — the plain-text report.
- `collection_report_<timestamp>.txt.asc` — detached GPG signature (only if signing was selected).

The report itself and any generated signature file are excluded from the directory listing.

## License

MIT OR Apache-2.0
