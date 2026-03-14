# lfi_repo_dumper

![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Purpose](https://img.shields.io/badge/purpose-security%20research-red)
![Category](https://img.shields.io/badge/category-bug%20bounty%20%7C%20pentesting-orange)

---

## Description

**lfi_repo_dumper** is a command-line security research tool designed to automatically extract exposed Git repositories from web servers through **Local File Inclusion (LFI)** vulnerabilities.

When a web application is vulnerable to LFI and a `.git/` directory is accessible from the web root, an attacker (or authorized penetration tester) can reconstruct the entire source code repository without needing direct directory listing access. This tool automates that entire workflow — from detecting the exposed repository, to parsing the Git index, to downloading and reconstructing every tracked file.

It is built for **security researchers**, **penetration testers**, and **bug bounty hunters** who need to demonstrate the real-world impact of an LFI vulnerability during authorized engagements.

---

## Features

- **LFI marker injection** — Flexible URL templating with multiple injection markers to support diverse LFI sink types
- **Automatic prefix discovery** — Iteratively tests path traversal depths (`../`) to locate the `.git` directory automatically
- **Git repository detection** — Validates that a real `.git/HEAD` file is accessible before proceeding
- **Git index parsing** — Downloads and parses the binary `.git/index` file to enumerate every file tracked in the repository
- **Multi-threaded file downloading** — Uses a configurable thread pool to download repository files concurrently via the LFI vector
- **Base64 encoding support** — Supports both raw and Base64-encoded path injection for bypassing input filters
- **Repository reconstruction** — Saves all downloaded files to a local output directory, preserving the original folder structure

---

## Supported Injection Markers

Place one of the following markers inside the `--url` argument where the file path should be injected.

| Marker | Description |
|---|---|
| `$lfi$` | Injects the raw file path directly (e.g., `.git/HEAD`) |
| `$prefixlfi$` | Injects the traversal prefix concatenated with the file path (e.g., `../../.git/HEAD`) |
| `$b64lfi$` | Injects the Base64-encoded file path only (e.g., `base64(.git/HEAD)`) |
| `$b64prefixlfi$` | Injects the Base64-encoded string of the prefix + file path (e.g., `base64(../../.git/HEAD)`) |

**Examples:**

```
# Raw path injection
https://target.com/view.php?file=$lfi$

# Prefix included in the injection
https://target.com/view.php?file=$prefixlfi$

# Base64-encoded path (no prefix)
https://target.com/download.php?resource=$b64lfi$

# Base64-encoded path with traversal prefix
https://target.com/download.php?resource=$b64prefixlfi$
```

---

## Installation

```bash
git clone https://github.com/youruser/lfi_repo_dumper.git
cd lfi_repo_dumper
pip install -r requirements.txt
```

**Requirements (`requirements.txt`):**

```
requests
urllib3
```

---

## Basic Usage

```bash
python3 lfiGitDumper.py --url "https://target.com/view.php?file=$b64prefixlfi$" --prefix "../../" --output dump
```

**Run with automatic prefix discovery:**

```bash
python3 lfiGitDumper.py --url "https://target.com/view.php?file=$b64prefixlfi$" --auto --output dump
```

**Use raw path injection with a custom thread count:**

```bash
python3 lfiGitDumper.py --url "https://target.com/page.php?path=$lfi$" --prefix "../../../" --output results --jobs 20
```

---

## Execution Workflow

The tool executes the following steps automatically:

1. **Validate LFI Injection** — The target URL is tested using the configured marker and prefix by attempting to fetch `.git/HEAD`.
2. **Detect Exposed `.git`** — The response is inspected for a valid Git `HEAD` reference (`ref:` or a 40-character SHA hash). If detection fails, automatic prefix scanning is triggered.
3. **Auto Prefix Scan (if needed)** — The tool iterates traversal depths from `../` up to `../../../../../../../../../..` until `.git/HEAD` is found.
4. **Download `.git/index`** — The binary Git index file is fetched, which contains the list of all tracked files with their SHA hashes.
5. **Parse Repository Paths** — The binary index is parsed to extract every file path and its corresponding blob SHA.
6. **Dump Files via LFI** — All extracted paths are queued and downloaded concurrently using a thread pool, with each request injected through the LFI vector.
7. **Reconstruct Output** — Downloaded files are saved locally, preserving the original directory structure of the repository.

---

## Example Output

```
[*] Target : https://target.com/view.php?file=$b64prefixlfi$
[*] Prefix : ../../
[*] Output : dump

[*] Running prefix scan
[+] Found prefix: ../../
[*] Downloading .git/index
[+] 42 paths extracted
[*] Starting file dump
[+]  src/config.php
[+]  src/database.php
[+]  src/auth/login.php
[+]  src/auth/register.php
[+]  includes/functions.php
[+]  includes/db.php
[+]  .env
[+]  README.md
[+]  composer.json
...

[✓] Repository dump finished
```

---

## Command Line Arguments

| Argument | Required | Default | Description |
|---|---|---|---|
| `--url` | ✅ Yes | — | Full URL template containing one of the supported injection markers |
| `--prefix` | No | `../../` | Directory traversal prefix prepended to each file path |
| `--output` | No | `dump` | Local directory where dumped files will be saved |
| `--jobs` | No | `10` | Number of concurrent download threads |
| `--auto` | No | `False` | Skip manual prefix and force automatic prefix discovery scan |

---

## Output Structure

After a successful dump, the output directory mirrors the original repository structure:

```
dump/
├── _index_paths.txt          # Full list of parsed paths and SHA hashes
├── .env                      # Sensitive environment file (if present)
├── README.md
├── composer.json
├── src/
│   ├── config.php
│   ├── database.php
│   └── auth/
│       ├── login.php
│       └── register.php
└── includes/
    ├── functions.php
    └── db.php
```

> `_index_paths.txt` — A flat text file listing every `<SHA> <path>` pair parsed from the Git index. Useful for inventory and offline analysis.

---

## Use Cases

This tool is designed for the following authorized security testing scenarios:

- **Bug Bounty Hunting** — Demonstrating the full impact of an LFI vulnerability by showing that source code, credentials (`.env`, `config.php`), and application logic can be extracted
- **Web Application Penetration Testing** — Assessing whether a misconfigured or accidentally deployed `.git` directory exposes the application codebase
- **Security Code Review** — Recovering application source code for manual review after gaining LFI access during an engagement
- **CTF Challenges** — Solving capture-the-flag challenges that involve LFI and exposed Git repositories

---

## Legal Disclaimer

> ⚠️ **This tool is intended exclusively for educational purposes and authorized security testing.**
>
> Use of **lfi_repo_dumper** against systems you do not own or do not have explicit written permission to test is **illegal** and may violate computer fraud laws in your jurisdiction, including but not limited to the Computer Fraud and Abuse Act (CFAA) and equivalent legislation.
>
> The author assumes **no liability** for any misuse, damage, or legal consequences arising from the use of this tool. Always obtain proper authorization before conducting any security assessment.

---

## License

This project is licensed under the **MIT License**.

```
