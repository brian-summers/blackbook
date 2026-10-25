//! `bbk key` and `bbk crypto` — the crypto toolkit on the command line.
//!
//! `bbk key` manages server-held keys (create / ls / show / rotate / rm).
//! `bbk crypto` runs operations, choosing the key with one of:
//!
//!   -k, --key NAME     a managed key on the server (domain from -D); its
//!                      secret material never leaves the server
//!   --cmk              this profile's client master key (local, never sent)
//!   --key-file PATH    a local unmanaged key: a `crypto keygen` file, an
//!                      Ed25519 PEM, or 32 raw / hex / base64 bytes
//!   -p, --passphrase   a passphrase (encrypt / decrypt), read from
//!                      $BLACKBOOK_CRYPTO_PASSPHRASE or prompted for
//!   --public-key KEY   an Ed25519 public key (verify only)
//!
//! Byte formats are defined once in [`crate::crypto_ops`].

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use clap::{Args, Subcommand};
use serde_json::{json, Map, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::crypto_ops::{self, EnvelopeKind, HashAlg, KeyType, TokenSigner, TokenVerifier};
use crate::{build_client, client, credstore, read_stdin_line, AppError, Result};

// ---------------------------------------------------------------------------
// clap definitions
// ---------------------------------------------------------------------------

#[derive(Subcommand)]
pub enum KeyCmd {
    /// Create a managed key in the current domain (-D). Its secret material is
    /// generated on (or imported to) the server and never leaves it; you use it
    /// through `bbk crypto … -k NAME`.
    Create {
        name: String,
        /// aes256-gcm (encrypt/decrypt) | ed25519 (sign/verify/tokens) |
        /// hmac (keyed hashes/tokens). Default: aes256-gcm, or the type of
        /// the --import file.
        #[arg(short = 't', long = "type")]
        key_type: Option<String>,
        /// Require a TOTP code (-m) for every use of the key's secret material.
        #[arg(short = 'M', long)]
        mfa_required: bool,
        /// Bring your own key: import material from a local key file instead
        /// of generating it (a keygen file, an Ed25519 PEM, or 32 raw / hex /
        /// base64 bytes).
        #[arg(long, value_name = "PATH")]
        import: Option<PathBuf>,
    },
    /// List the managed keys you can read in the current domain.
    Ls {
        #[arg(long)] json: bool,
    },
    /// Show a key's type, versions, and (Ed25519) public key.
    Show {
        name: String,
        #[arg(long)] json: bool,
    },
    /// Print an Ed25519 key's public keys as a JWK Set (RFC 7517), so any JWT
    /// library can verify its tokens.
    Jwks { name: String },
    /// Rotate: add a new version that is used for all new output. Older
    /// versions keep decrypting and verifying, so nothing already made breaks.
    Rotate { name: String },
    /// Delete a key and ALL of its versions. Anything it encrypted becomes
    /// permanently unrecoverable.
    Rm {
        name: String,
        #[arg(short = 'y', long)] yes: bool,
    },
}

/// Where an operation's input comes from.
#[derive(Args)]
pub struct Input {
    /// Input file (`-` or omitted = stdin).
    input: Option<PathBuf>,
    /// Use this text as the input. Visible in the process list and shell
    /// history, so avoid it for secrets.
    #[arg(long, conflicts_with = "input")]
    text: Option<String>,
}

#[derive(Subcommand)]
pub enum CryptoCmd {
    /// Encrypt data into a text envelope. Pick one key source:
    /// -k NAME (managed key: a one-time data key is wrapped by it and your data
    /// is encrypted locally, never sent), --cmk, --key-file (your own AES-256
    /// key; output is standard AES-256-GCM), or -p (passphrase, Argon2id).
    Encrypt {
        #[command(flatten)] input: Input,
        /// Managed key on the server (in the -D domain).
        #[arg(short = 'k', long = "key", value_name = "NAME")] key: Option<String>,
        /// This profile's client master key.
        #[arg(long)] cmk: bool,
        /// Local 32-byte AES-256 key file.
        #[arg(long, value_name = "PATH")] key_file: Option<PathBuf>,
        /// Passphrase ($BLACKBOOK_CRYPTO_PASSPHRASE, else prompted).
        #[arg(short = 'p', long)] passphrase: bool,
        /// Associated data: authenticated but not encrypted. The same value
        /// must be given to decrypt, binding the ciphertext to a context.
        #[arg(long)] aad: Option<String>,
        /// Write the envelope here instead of stdout.
        #[arg(short = 'o', long)] out: Option<PathBuf>,
    },
    /// Decrypt an envelope from `crypto encrypt`, or `bbk:v<N>:` ciphertext
    /// from the keys API. The method is read from the envelope; give -k NAME
    /// for managed-key data and --key-file for raw-key data.
    Decrypt {
        #[command(flatten)] input: Input,
        #[arg(short = 'k', long = "key", value_name = "NAME")] key: Option<String>,
        #[arg(long, value_name = "PATH")] key_file: Option<PathBuf>,
        /// Associated data given at encryption time.
        #[arg(long)] aad: Option<String>,
        /// Write the plaintext here instead of stdout.
        #[arg(short = 'o', long)] out: Option<PathBuf>,
    },
    /// Sign data with an Ed25519 key (managed -k, or a local --key-file).
    Sign {
        #[command(flatten)] input: Input,
        #[arg(short = 'k', long = "key", value_name = "NAME")] key: Option<String>,
        #[arg(long, value_name = "PATH")] key_file: Option<PathBuf>,
    },
    /// Verify an Ed25519 signature or an HMAC. Exit status: 0 valid, 1 invalid.
    Verify {
        #[command(flatten)] input: Input,
        /// The signature / MAC (`bbk:v<N>:…`, base64, or hex).
        #[arg(short = 's', long)] signature: String,
        #[arg(short = 'k', long = "key", value_name = "NAME")] key: Option<String>,
        #[arg(long, value_name = "PATH")] key_file: Option<PathBuf>,
        /// Ed25519 public key: base64/hex, or a file holding PEM, JWK, or a
        /// keygen key.
        #[arg(long, value_name = "KEY")] public_key: Option<String>,
        /// HMAC algorithm the MAC was made with.
        #[arg(short = 'a', long, default_value = "sha3-256")] algorithm: String,
    },
    /// Hash data (sha3-256, sha3-512, sha256, sha512). With a key (-k, --cmk,
    /// --key-file) it computes an HMAC — a keyed hash only key holders can
    /// reproduce or check.
    Hash {
        #[command(flatten)] input: Input,
        #[arg(short = 'a', long, default_value = "sha3-256")] algorithm: String,
        #[arg(short = 'k', long = "key", value_name = "NAME")] key: Option<String>,
        #[arg(long)] cmk: bool,
        #[arg(long, value_name = "PATH")] key_file: Option<PathBuf>,
        /// hex | base64 | base64url (local hashes; managed HMACs print `bbk:v<N>:`).
        #[arg(short = 'e', long, default_value = "hex")] encoding: String,
    },
    /// Issue and verify signed tokens (JWT, EdDSA or HS256).
    #[command(subcommand)]
    Token(TokenCmd),
    /// Generate a local (unmanaged) key file. Nothing is sent anywhere; keep
    /// the file secret.
    Keygen {
        /// ed25519 | aes256-gcm | hmac.
        #[arg(short = 't', long = "type", default_value = "ed25519")] key_type: String,
        /// Output path (`-` = stdout).
        #[arg(short = 'o', long)] out: PathBuf,
        /// json (keygen format) | pem (Ed25519 PKCS#8) | raw (32 bytes; AES/HMAC).
        #[arg(short = 'f', long, default_value = "json")] format: String,
        /// Overwrite an existing file.
        #[arg(long)] force: bool,
    },
    /// Get a fresh 256-bit data key from a managed AES key, for your own
    /// envelope encryption: use `plaintext` locally, store `ciphertext`, and
    /// recover it later with `crypto decrypt -k NAME`.
    Datakey {
        #[arg(short = 'k', long = "key", value_name = "NAME")] key: String,
        #[arg(long)] json: bool,
    },
    /// Cryptographically secure random bytes.
    Random {
        #[arg(short = 'n', long, default_value_t = 32)] bytes: usize,
        /// hex | base64 | base64url | token.
        #[arg(short = 'e', long, default_value = "base64url")] encoding: String,
    },
    /// Derive a 256-bit key from a passphrase ($BLACKBOOK_CRYPTO_PASSPHRASE or
    /// prompt) with Argon2id, scrypt, or PBKDF2-HMAC-SHA3-512.
    DeriveKey {
        #[arg(short = 'a', long, default_value = "argon2id")] algorithm: String,
        /// Base64 salt to reproduce a key (default: a fresh random 16 bytes).
        #[arg(long)] salt: Option<String>,
    },
    /// Hash a password for storage: Argon2id in the standard PHC string
    /// format. The password comes from $BLACKBOOK_CRYPTO_PASSPHRASE or a prompt.
    PasswordHash,
    /// Check a password against a PHC hash. Exit status: 0 match, 1 no match.
    PasswordVerify { hash: String },
    /// Human-verifiable fingerprint of data: randomart, braille, SHA3-256.
    Fingerprint {
        #[command(flatten)] input: Input,
    },
}

#[derive(Subcommand)]
pub enum TokenCmd {
    /// Issue a signed token (JWT). Ed25519 keys sign EdDSA tokens; HMAC keys
    /// sign HS256 tokens. Prints the token.
    Issue {
        #[arg(short = 'k', long = "key", value_name = "NAME")] key: Option<String>,
        #[arg(long, value_name = "PATH")] key_file: Option<PathBuf>,
        /// Subject (`sub`).
        #[arg(long)] sub: Option<String>,
        /// Audience (`aud`).
        #[arg(long)] aud: Option<String>,
        /// Issuer (`iss`).
        #[arg(long)] iss: Option<String>,
        /// Lifetime: seconds, or 90s / 15m / 1h / 7d / 2w.
        #[arg(long, default_value = "1h")] ttl: String,
        /// Not valid until this long from now (same units as --ttl).
        #[arg(long)] nbf: Option<String>,
        /// Extra claim, repeatable: `-c role=reader`. Values that parse as
        /// JSON (numbers, true/false, arrays) keep their type.
        #[arg(short = 'c', long = "claim", value_name = "KEY=VALUE")] claims: Vec<String>,
        /// Extra claims as a JSON object (applied before -c).
        #[arg(long, value_name = "JSON")] claims_json: Option<String>,
        /// Print token, kid, expiry and claims as JSON.
        #[arg(long)] json: bool,
    },
    /// Verify a token's signature, algorithm, expiry, not-before and (with
    /// --aud) audience, then print its claims. Exit status: 0 valid, 1 invalid.
    Verify {
        /// The token (`-` = stdin).
        token: String,
        #[arg(short = 'k', long = "key", value_name = "NAME")] key: Option<String>,
        #[arg(long, value_name = "PATH")] key_file: Option<PathBuf>,
        /// Ed25519 public key (base64/hex, or a PEM / JWK / keygen file).
        #[arg(long, value_name = "KEY")] public_key: Option<String>,
        /// Require this audience.
        #[arg(long)] aud: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cfg(msg: impl std::fmt::Display) -> AppError { AppError::Config(msg.to_string()) }

fn read_stdin() -> Result<Zeroizing<Vec<u8>>> {
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() {
        eprintln!("(reading from stdin — finish with Ctrl-D, or Ctrl-Z then Enter on Windows)");
    }
    let mut buf = Zeroizing::new(Vec::new());
    std::io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

fn read_input(input: &Input) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(t) = &input.text { return Ok(Zeroizing::new(t.as_bytes().to_vec())); }
    match input.input.as_deref() {
        Some(p) if p != Path::new("-") => Ok(Zeroizing::new(std::fs::read(p)?)),
        _ => read_stdin(),
    }
}

fn read_input_text(input: &Input) -> Result<String> {
    let bytes = read_input(input)?;
    std::str::from_utf8(&bytes).map(|s| s.trim().to_string())
        .map_err(|_| cfg("input is not a text envelope (expected UTF-8)"))
}

fn write_output(out: Option<&Path>, bytes: &[u8]) -> Result<()> {
    match out {
        Some(p) if p != Path::new("-") => std::fs::write(p, bytes)?,
        _ => {
            let mut so = std::io::stdout().lock();
            so.write_all(bytes)?;
            so.flush()?;
        }
    }
    Ok(())
}

/// Exactly one (or at most one, when `required` is false) of the named key
/// sources may be set; returns the chosen flag name.
fn one_source(sources: &[(&'static str, bool)], required: bool) -> Result<Option<&'static str>> {
    let set: Vec<&str> = sources.iter().filter(|(_, on)| *on).map(|(n, _)| *n).collect();
    match set.as_slice() {
        [] if required => Err(cfg(format!(
            "choose a key: {}", sources.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")))),
        [] => Ok(None),
        [one] => Ok(Some(one)),
        many => Err(cfg(format!("pick one key source, not {}", many.join(" + ")))),
    }
}

/// A secret typed by the user: env var, else a no-echo prompt.
fn crypto_secret(prompt: &str, confirm: bool) -> Result<Zeroizing<String>> {
    for var in ["BLACKBOOK_CRYPTO_PASSPHRASE", "BLACKBOOK_EXTERNAL_PASSPHRASE"] {
        if let Ok(p) = std::env::var(var) {
            if !p.is_empty() { return Ok(Zeroizing::new(p)); }
        }
    }
    let missing = || cfg("a passphrase is required — set $BLACKBOOK_CRYPTO_PASSPHRASE or run interactively");
    if credstore::prompts_suppressed() { return Err(missing()); }
    let p1 = Zeroizing::new(rpassword::prompt_password(prompt).map_err(|_| missing())?);
    if p1.is_empty() { return Err(cfg("empty passphrase")); }
    if confirm {
        let p2 = Zeroizing::new(rpassword::prompt_password("Confirm: ").map_err(|_| missing())?);
        if *p1 != *p2 { return Err(cfg("entries did not match")); }
    }
    Ok(p1)
}

fn managed_client(domain: Option<String>, mfa: Option<String>) -> Result<client::BlackbookClient> {
    let session = client::Session::load()?;
    build_client(&session, domain, mfa)
}

fn profile_cmk() -> Result<Zeroizing<[u8; 32]>> {
    let session = client::Session::load()?;
    session.cmk_bytes().map(Zeroizing::new).ok_or_else(|| cfg(
        "this profile has no client master key (CMK) — re-run `bbk login` to mint one"))
}

fn load_key_file(path: &Path, hint: Option<KeyType>) -> Result<crypto_ops::LocalKey> {
    let bytes = Zeroizing::new(std::fs::read(path)
        .map_err(|e| cfg(format!("{}: {e}", path.display())))?);
    crypto_ops::parse_local_key(&bytes, hint).map_err(|e| cfg(format!("{}: {e}", path.display())))
}

/// `--public-key` value: a file path, or the key text itself.
fn public_key_arg(arg: &str) -> Result<[u8; 32]> {
    let text = if Path::new(arg).is_file() { std::fs::read_to_string(arg)? } else { arg.to_string() };
    crypto_ops::parse_public_key(&text).map_err(cfg)
}

fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key).and_then(Value::as_str)
        .ok_or_else(|| AppError::Client(format!("server response is missing '{key}'")))
}

fn b64_field(v: &Value, key: &str) -> Result<Zeroizing<Vec<u8>>> {
    B64.decode(field(v, key)?).map(Zeroizing::new)
        .map_err(|_| AppError::Client(format!("server response '{key}' is not base64")))
}

fn aad_json(aad: &[u8]) -> Value {
    if aad.is_empty() { Value::Null } else { json!(B64.encode(aad)) }
}

/// Seconds from `30`, `90s`, `15m`, `1h`, `7d`, `2w`.
fn parse_duration(s: &str) -> Result<i64> {
    let s = s.trim();
    let bad = || cfg(format!("'{s}' isn't a duration (use seconds, or 90s / 15m / 1h / 7d / 2w)"));
    let (num, mult) = match s.chars().last().ok_or_else(bad)? {
        's' => (&s[..s.len() - 1], 1),
        'm' => (&s[..s.len() - 1], 60),
        'h' => (&s[..s.len() - 1], 3600),
        'd' => (&s[..s.len() - 1], 86_400),
        'w' => (&s[..s.len() - 1], 604_800),
        c if c.is_ascii_digit() => (s, 1),
        _ => return Err(bad()),
    };
    num.parse::<i64>().ok().and_then(|n| n.checked_mul(mult)).ok_or_else(bad)
}

fn build_claims(claims_json: Option<&str>, pairs: &[String]) -> Result<Map<String, Value>> {
    let mut claims = match claims_json {
        Some(j) => match serde_json::from_str::<Value>(j) {
            Ok(Value::Object(m)) => m,
            _ => return Err(cfg("--claims-json must be a JSON object")),
        },
        None => Map::new(),
    };
    for p in pairs {
        let (k, v) = p.split_once('=').ok_or_else(|| cfg(format!("claim '{p}' isn't KEY=VALUE")))?;
        let v = serde_json::from_str::<Value>(v).unwrap_or_else(|_| json!(v));
        claims.insert(k.to_string(), v);
    }
    Ok(claims)
}

/// Print the outcome of a check and set the exit status (0 ok, 1 not ok).
fn finish_check(ok: bool, yes: &str, no: &str) -> Result<()> {
    if ok {
        println!("✓ {yes}");
        Ok(())
    } else {
        eprintln!("✗ {no}");
        std::process::exit(1);
    }
}

fn print_public_key(pk: &[u8; 32]) {
    println!("public key:  {}", B64.encode(pk));
    print!("{}", crypto_ops::ed25519_public_pem(pk));
}

// ---------------------------------------------------------------------------
// bbk key
// ---------------------------------------------------------------------------

pub async fn cmd_key(cmd: KeyCmd, domain: Option<String>, mfa: Option<String>) -> Result<()> {
    let bb = managed_client(domain, mfa)?;
    match cmd {
        KeyCmd::Create { name, key_type, mfa_required, import } => {
            let requested = key_type.as_deref().map(KeyType::parse).transpose().map_err(cfg)?;
            let (key_type, material) = match import {
                Some(path) => {
                    let k = load_key_file(&path, requested)?;
                    if let Some(want) = requested.filter(|w| *w != k.key_type) {
                        return Err(cfg(format!("{} holds an {} key, not {}",
                            path.display(), k.key_type.as_str(), want.as_str())));
                    }
                    (k.key_type, Some(Zeroizing::new(B64.encode(k.secret.as_slice()))))
                }
                None => (requested.unwrap_or(KeyType::Aes256Gcm), None),
            };
            let k = bb.key_create(&name, key_type.as_str(), mfa_required, material.as_deref().map(|s| s.as_str())).await?;
            println!("{} {} key '{}' (v{}) in domain '{}'{}",
                     if material.is_some() { "imported" } else { "created" },
                     k.key_type, k.name, k.latest_version, bb.domain(),
                     if k.mfa_required { " — MFA required to use it" } else { "" });
            if let Some(pk) = k.public_key.as_deref() {
                println!("public key:  {pk}");
                if let Some(pem) = &k.public_key_pem { print!("{pem}"); }
            }
        }
        KeyCmd::Ls { json } => {
            let list = bb.key_list().await?;
            if json {
                println!("{}", serde_json::to_string(&list)?);
                return Ok(());
            }
            if list.count == 0 { println!("(no keys)"); return Ok(()); }
            println!("{:<28}  {:<11}  {:<7}  {:<4}  {}", "NAME", "TYPE", "VERSION", "MFA", "UPDATED");
            println!("{}", "-".repeat(84));
            for k in list.keys {
                println!("{:<28}  {:<11}  {:<7}  {:<4}  {}", k.name, k.key_type,
                         format!("v{}", k.latest_version), if k.mfa_required { "yes" } else { "no" }, k.updated_at);
            }
        }
        KeyCmd::Show { name, json } => {
            let k = bb.key_show(&name).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&k)?);
                return Ok(());
            }
            println!("name:        {}", k.name);
            println!("type:        {} ({})", k.key_type,
                     KeyType::parse(&k.key_type).map(|t| t.operations()).unwrap_or("?"));
            println!("version:     v{} (latest)", k.latest_version);
            println!("mfa:         {}", if k.mfa_required { "required" } else { "not required" });
            println!("created:     {}", k.created_at);
            println!("updated:     {}", k.updated_at);
            for v in &k.versions {
                println!("  v{:<4} created {}{}", v.version, v.created_at,
                         v.public_key.as_deref().map(|p| format!("  public {p}")).unwrap_or_default());
            }
            if let Some(pem) = &k.public_key_pem { print!("{pem}"); }
        }
        KeyCmd::Jwks { name } => {
            println!("{}", serde_json::to_string_pretty(&bb.key_jwks(&name).await?)?);
        }
        KeyCmd::Rotate { name } => {
            let k = bb.key_rotate(&name).await?;
            println!("rotated '{}' — new output uses v{}; earlier versions still decrypt and verify",
                     k.name, k.latest_version);
            if let Some(pk) = k.public_key.as_deref() { println!("new public key:  {pk}"); }
        }
        KeyCmd::Rm { name, yes } => {
            if !yes {
                eprint!("Delete key '{name}' and ALL its versions? Anything it encrypted becomes \
                         unrecoverable. Type the key name to confirm: ");
                if read_stdin_line() != name { println!("aborted"); return Ok(()); }
            }
            let r = bb.key_delete(&name).await?;
            println!("deleted key '{name}' ({} version(s))", r.get("versions").and_then(Value::as_i64).unwrap_or(0));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// bbk crypto
// ---------------------------------------------------------------------------

pub async fn cmd_crypto(cmd: CryptoCmd, domain: Option<String>, mfa: Option<String>) -> Result<()> {
    match cmd {
        CryptoCmd::Encrypt { input, key, cmk, key_file, passphrase, aad, out } => {
            let src = one_source(&[("-k/--key", key.is_some()), ("--cmk", cmk),
                                   ("--key-file", key_file.is_some()), ("-p/--passphrase", passphrase)], true)?;
            let aad = aad.unwrap_or_default().into_bytes();
            let data = read_input(&input)?;
            let envelope = match src {
                Some("-k/--key") => {
                    let bb = managed_client(domain, mfa)?;
                    let r = bb.key_op(key.as_deref().unwrap_or_default(), "datakey", &json!({})).await?;
                    let dek = b64_field(&r, "plaintext")?;
                    crypto_ops::datakey_seal(&data, &dek, field(&r, "ciphertext")?, &aad)
                }
                Some("--cmk") => crypto_ops::cmk_seal(&data, profile_cmk()?.as_slice(), &aad),
                Some("--key-file") => {
                    let k = load_key_file(key_file.as_deref().unwrap_or(Path::new("")), Some(KeyType::Aes256Gcm))?;
                    if k.key_type != KeyType::Aes256Gcm {
                        return Err(cfg(format!("that is an {} key; encryption needs an aes256-gcm key \
                                                (`bbk crypto keygen -t aes256-gcm`)", k.key_type.as_str())));
                    }
                    crypto_ops::rawkey_seal(&data, &k.secret, &aad)
                }
                _ => crypto_ops::passphrase_seal(&data, &crypto_secret("Passphrase: ", true)?, &aad),
            }.map_err(AppError::Crypto)?;
            write_output(out.as_deref(), format!("{envelope}\n").as_bytes())?;
        }

        CryptoCmd::Decrypt { input, key, key_file, aad, out } => {
            let text = read_input_text(&input)?;
            let aad = aad.unwrap_or_default().into_bytes();
            let need_key = || cfg("this was encrypted with a managed key — pass -k NAME \
                                   (and -D DOMAIN if the key isn't in your default domain)");
            let plaintext: Zeroizing<Vec<u8>> = match crypto_ops::detect(&text) {
                Some(EnvelopeKind::Managed) => {
                    let bb = managed_client(domain, mfa)?;
                    let r = bb.key_op(key.as_deref().ok_or_else(need_key)?, "decrypt",
                                      &json!({ "ciphertext": text, "aad": aad_json(&aad) })).await?;
                    b64_field(&r, "plaintext")?
                }
                Some(EnvelopeKind::DataKey) => {
                    let (wrapped, sealed) = crypto_ops::datakey_parse(&text).map_err(AppError::Crypto)?;
                    let bb = managed_client(domain, mfa)?;
                    let r = bb.key_op(key.as_deref().ok_or_else(need_key)?, "decrypt",
                                      &json!({ "ciphertext": wrapped })).await?;
                    let dek = b64_field(&r, "plaintext")?;
                    Zeroizing::new(crypto_ops::datakey_open(&sealed, &dek, &aad).map_err(AppError::Crypto)?)
                }
                Some(EnvelopeKind::Passphrase) => Zeroizing::new(crypto_ops::passphrase_open(
                    &text, &crypto_secret("Passphrase: ", false)?, &aad).map_err(AppError::Crypto)?),
                Some(EnvelopeKind::Cmk) => Zeroizing::new(crypto_ops::cmk_open(
                    &text, profile_cmk()?.as_slice(), &aad).map_err(AppError::Crypto)?),
                Some(EnvelopeKind::RawKey) => {
                    let path = key_file.ok_or_else(|| cfg("this was encrypted with a raw key — pass --key-file PATH"))?;
                    let k = load_key_file(&path, Some(KeyType::Aes256Gcm))?;
                    Zeroizing::new(crypto_ops::rawkey_open(&text, &k.secret, &aad).map_err(AppError::Crypto)?)
                }
                None => return Err(cfg("not a Blackbook envelope (expected bbk:v<N>:, bbkd1:, bbkx1:, \
                                        bbkc1: or bbkk1:)")),
            };
            write_output(out.as_deref(), &plaintext)?;
        }

        CryptoCmd::Sign { input, key, key_file } => {
            let src = one_source(&[("-k/--key", key.is_some()), ("--key-file", key_file.is_some())], true)?;
            let data = read_input(&input)?;
            if src == Some("-k/--key") {
                let bb = managed_client(domain, mfa)?;
                let r = bb.key_op(key.as_deref().unwrap_or_default(), "sign",
                                  &json!({ "input": B64.encode(data.as_slice()) })).await?;
                println!("{}", field(&r, "signature")?);
            } else {
                let k = load_key_file(key_file.as_deref().unwrap_or(Path::new("")), Some(KeyType::Ed25519))?;
                if k.key_type != KeyType::Ed25519 {
                    return Err(cfg(format!("signing needs an ed25519 key; for an {} key use `crypto hash \
                                            --key-file` (an HMAC)", k.key_type.as_str())));
                }
                println!("{}", B64.encode(crypto_ops::ed25519_sign(&k.secret, &data).map_err(AppError::Crypto)?));
            }
        }

        CryptoCmd::Verify { input, signature, key, key_file, public_key, algorithm } => {
            let src = one_source(&[("-k/--key", key.is_some()), ("--key-file", key_file.is_some()),
                                   ("--public-key", public_key.is_some())], true)?;
            let alg = HashAlg::parse(&algorithm).map_err(cfg)?;
            let data = read_input(&input)?;
            let valid = match src {
                Some("-k/--key") => {
                    let bb = managed_client(domain, mfa)?;
                    let r = bb.key_op(key.as_deref().unwrap_or_default(), "verify", &json!({
                        "input": B64.encode(data.as_slice()), "signature": signature.trim(),
                        "algorithm": alg.as_str(),
                    })).await?;
                    r.get("valid").and_then(Value::as_bool).unwrap_or(false)
                }
                Some("--public-key") => {
                    let pk = public_key_arg(public_key.as_deref().unwrap_or_default())?;
                    let tag = crypto_ops::parse_tag(&signature).map_err(cfg)?;
                    crypto_ops::ed25519_verify(&pk, &data, &tag)
                }
                _ => {
                    let k = load_key_file(key_file.as_deref().unwrap_or(Path::new("")), Some(KeyType::Hmac))?;
                    let tag = crypto_ops::parse_tag(&signature).map_err(cfg)?;
                    match k.key_type {
                        KeyType::Ed25519 => crypto_ops::ed25519_verify(
                            &crypto_ops::ed25519_public(&k.secret).map_err(AppError::Crypto)?, &data, &tag),
                        _ => crypto_ops::hmac_verify(alg, &k.secret, &data, &tag),
                    }
                }
            };
            finish_check(valid, "valid", "INVALID — the data, signature, or key doesn't match")?;
        }

        CryptoCmd::Hash { input, algorithm, key, cmk, key_file, encoding } => {
            let alg = HashAlg::parse(&algorithm).map_err(cfg)?;
            let src = one_source(&[("-k/--key", key.is_some()), ("--cmk", cmk),
                                   ("--key-file", key_file.is_some())], false)?;
            let data = read_input(&input)?;
            let out = match src {
                None => crypto_ops::encode(&crypto_ops::digest(alg, &data), &encoding).map_err(cfg)?,
                Some("-k/--key") => {
                    let bb = managed_client(domain, mfa)?;
                    let r = bb.key_op(key.as_deref().unwrap_or_default(), "hmac", &json!({
                        "input": B64.encode(data.as_slice()), "algorithm": alg.as_str(),
                    })).await?;
                    field(&r, "hmac")?.to_string()
                }
                Some("--cmk") => {
                    let k = crypto_ops::cmk_subkey(profile_cmk()?.as_slice(), "hmac");
                    crypto_ops::encode(&crypto_ops::hmac(alg, k.as_slice(), &data), &encoding).map_err(cfg)?
                }
                _ => {
                    let k = load_key_file(key_file.as_deref().unwrap_or(Path::new("")), Some(KeyType::Hmac))?;
                    if k.key_type != KeyType::Hmac {
                        return Err(cfg(format!("keyed hashing needs an hmac key, not {} \
                                                (`bbk crypto keygen -t hmac`)", k.key_type.as_str())));
                    }
                    crypto_ops::encode(&crypto_ops::hmac(alg, &k.secret, &data), &encoding).map_err(cfg)?
                }
            };
            println!("{out}");
        }

        CryptoCmd::Token(cmd) => cmd_token(cmd, domain, mfa).await?,

        CryptoCmd::Keygen { key_type, out, format, force } => {
            let key_type = KeyType::parse(&key_type).map_err(cfg)?;
            let secret = KeyType::generate();
            let bytes: Zeroizing<Vec<u8>> = match (format.as_str(), key_type) {
                ("json", _) => Zeroizing::new(crypto_ops::local_key_json(key_type, &secret).as_bytes().to_vec()),
                ("pem", KeyType::Ed25519) => Zeroizing::new(crypto_ops::ed25519_private_pem(&secret).into_bytes()),
                ("pem", _) => return Err(cfg("PEM output is for ed25519 keys; use json or raw")),
                ("raw", KeyType::Ed25519) => return Err(cfg("raw output is for aes256-gcm / hmac keys; use json or pem")),
                ("raw", _) => secret.clone(),
                (other, _) => return Err(cfg(format!("unknown format '{other}' (use json, pem or raw)"))),
            };
            if out == Path::new("-") {
                write_output(None, &bytes)?;
            } else {
                write_secret_file(&out, &bytes, force)?;
                eprintln!("wrote {} key to {} — keep this file secret", key_type.as_str(), out.display());
            }
            if let Some(pk) = key_type.public_key(&secret) {
                if out != Path::new("-") { print_public_key(&pk); }
            }
        }

        CryptoCmd::Datakey { key, json } => {
            let bb = managed_client(domain, mfa)?;
            let r = bb.key_op(&key, "datakey", &json!({})).await?;
            if json {
                println!("{}", serde_json::to_string(&r)?);
            } else {
                println!("plaintext:   {}", field(&r, "plaintext")?);
                println!("ciphertext:  {}", field(&r, "ciphertext")?);
                eprintln!("(use the plaintext key locally and discard it; keep only the ciphertext)");
            }
        }

        CryptoCmd::Random { bytes, encoding } => {
            if bytes == 0 || bytes > 65_536 { return Err(cfg("--bytes must be between 1 and 65536")); }
            println!("{}", crypto_ops::encode(&crypto_ops::random_bytes(bytes), &encoding).map_err(cfg)?);
        }

        CryptoCmd::DeriveKey { algorithm, salt } => {
            let alg = crypto_ops::KdfAlg::parse(&algorithm).map_err(cfg)?;
            let salt = match salt {
                Some(s) => B64.decode(s.trim()).map_err(|_| cfg("--salt is not valid base64"))?,
                None => crypto_ops::random_bytes(16).to_vec(),
            };
            let pass = crypto_secret("Passphrase: ", false)?;
            let key = crypto_ops::derive_key(alg, &pass, &salt).map_err(AppError::Crypto)?;
            println!("algorithm:  {}", alg.as_str());
            println!("key_base64: {}", B64.encode(key.as_slice()));
            println!("key_hex:    {}", hex::encode(key.as_slice()));
            println!("salt:       {}", B64.encode(&salt));
        }

        CryptoCmd::PasswordHash => {
            let pw = crypto_secret("Password: ", true)?;
            println!("{}", crypto_ops::password_hash(&pw).map_err(AppError::Crypto)?);
        }

        CryptoCmd::PasswordVerify { hash } => {
            let pw = crypto_secret("Password: ", false)?;
            let ok = crypto_ops::password_verify(&pw, &hash).map_err(cfg)?;
            finish_check(ok, "password matches", "password does NOT match")?;
        }

        CryptoCmd::Fingerprint { input } => {
            let data = read_input(&input)?;
            let fp = crypto_ops::digest(HashAlg::Sha3_256, &data);
            println!("{}", crate::presentation::randomart(&fp, "bbk"));
            println!("braille:  {}", crate::presentation::braille(&fp));
            println!("sha3-256: {}", hex::encode(fp));
        }
    }
    Ok(())
}

/// Create `path` with owner-only permissions; refuse to clobber unless `force`.
fn write_secret_file(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if force { opts.create(true).truncate(true); } else { opts.create_new(true); }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => cfg(format!("{} already exists (pass --force to overwrite)", path.display())),
        _ => cfg(format!("{}: {e}", path.display())),
    })?;
    f.write_all(bytes)?;
    Ok(())
}

async fn cmd_token(cmd: TokenCmd, domain: Option<String>, mfa: Option<String>) -> Result<()> {
    match cmd {
        TokenCmd::Issue { key, key_file, sub, aud, iss, ttl, nbf, claims, claims_json, json } => {
            let src = one_source(&[("-k/--key", key.is_some()), ("--key-file", key_file.is_some())], true)?;
            let extra = build_claims(claims_json.as_deref(), &claims)?;
            let ttl_secs = parse_duration(&ttl)?;
            let nbf_secs = nbf.as_deref().map(parse_duration).transpose()?;
            let resp = if src == Some("-k/--key") {
                let bb = managed_client(domain, mfa)?;
                bb.key_op(key.as_deref().unwrap_or_default(), "token", &json!({
                    "claims": extra, "subject": sub, "audience": aud, "issuer": iss,
                    "ttl_secs": ttl_secs, "not_before_secs": nbf_secs,
                })).await?
            } else {
                // A raw 32-byte file is taken as an HMAC key (HS256).
                let k = load_key_file(key_file.as_deref().unwrap_or(Path::new("")), Some(KeyType::Hmac))?;
                let (signer, kid) = match k.key_type {
                    KeyType::Ed25519 => {
                        let pk = crypto_ops::ed25519_public(&k.secret).map_err(AppError::Crypto)?;
                        (TokenSigner::Ed25519(&k.secret), Some(crypto_ops::key_fingerprint(&pk)))
                    }
                    KeyType::Hmac => (TokenSigner::Hmac(&k.secret), None),
                    KeyType::Aes256Gcm => return Err(cfg(
                        "tokens need an ed25519 or hmac key, not aes256-gcm")),
                };
                let claims = crypto_ops::token_claims(crypto_ops::TokenRequest {
                    claims: extra, subject: sub, audience: aud, issuer: iss,
                    ttl_secs, not_before_secs: nbf_secs,
                }, crypto_ops::now_unix()).map_err(cfg)?;
                let token = crypto_ops::token_issue(&signer, kid.as_deref(), &claims).map_err(AppError::Crypto)?;
                let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or_default();
                json!({ "token": token, "kid": kid, "expires_at": crypto_ops::fmt_unix(exp), "claims": claims })
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                println!("{}", field(&resp, "token")?);
                if let Some(exp) = resp.get("expires_at").and_then(Value::as_str) {
                    eprintln!("(expires {exp})");
                }
            }
        }
        TokenCmd::Verify { token, key, key_file, public_key, aud } => {
            let token = if token == "-" {
                String::from_utf8_lossy(&read_stdin()?).trim().to_string()
            } else {
                token
            };
            let src = one_source(&[("-k/--key", key.is_some()), ("--key-file", key_file.is_some()),
                                   ("--public-key", public_key.is_some())], true)?;
            let now = crypto_ops::now_unix();
            let outcome: std::result::Result<Map<String, Value>, String> = match src {
                Some("-k/--key") => {
                    let bb = managed_client(domain, mfa)?;
                    let r = bb.key_op(key.as_deref().unwrap_or_default(), "token/verify",
                                      &json!({ "token": token, "audience": aud })).await?;
                    if r.get("valid").and_then(Value::as_bool) == Some(true) {
                        Ok(r.get("claims").and_then(Value::as_object).cloned().unwrap_or_default())
                    } else {
                        Err(r.get("reason").and_then(Value::as_str).unwrap_or("invalid").to_string())
                    }
                }
                Some("--public-key") => {
                    let pk = public_key_arg(public_key.as_deref().unwrap_or_default())?;
                    crypto_ops::token_verify(&token, &TokenVerifier::Ed25519(pk), now, aud.as_deref())
                }
                _ => {
                    let k = load_key_file(key_file.as_deref().unwrap_or(Path::new("")), Some(KeyType::Hmac))?;
                    match k.key_type {
                        KeyType::Ed25519 => {
                            let pk = crypto_ops::ed25519_public(&k.secret).map_err(AppError::Crypto)?;
                            crypto_ops::token_verify(&token, &TokenVerifier::Ed25519(pk), now, aud.as_deref())
                        }
                        _ => crypto_ops::token_verify(&token, &TokenVerifier::Hmac(&k.secret), now, aud.as_deref()),
                    }
                }
            };
            match outcome {
                Ok(claims) => {
                    println!("✓ valid token");
                    if let Some(exp) = claims.get("exp").and_then(Value::as_i64) {
                        println!("expires: {}", crypto_ops::fmt_unix(exp));
                    }
                    println!("{}", serde_json::to_string_pretty(&claims)?);
                }
                Err(reason) => {
                    eprintln!("✗ invalid token: {reason}");
                    std::process::exit(1);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse_with_units() {
        assert_eq!(parse_duration("30").unwrap(), 30);
        assert_eq!(parse_duration("90s").unwrap(), 90);
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert_eq!(parse_duration("1h").unwrap(), 3600);
        assert_eq!(parse_duration("7d").unwrap(), 604_800);
        assert!(parse_duration("1y").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn claims_merge_json_then_pairs_and_keep_types() {
        let c = build_claims(Some(r#"{"role":"x","n":1}"#), &["role=reader".into(), "admin=true".into(),
                             "scopes=[\"a\",\"b\"]".into()]).unwrap();
        assert_eq!(c["role"], json!("reader"));
        assert_eq!(c["n"], json!(1));
        assert_eq!(c["admin"], json!(true));
        assert_eq!(c["scopes"], json!(["a", "b"]));
        assert!(build_claims(Some("[1]"), &[]).is_err());
        assert!(build_claims(None, &["noequals".into()]).is_err());
    }

    #[test]
    fn exactly_one_key_source() {
        assert_eq!(one_source(&[("a", false), ("b", true)], true).unwrap(), Some("b"));
        assert!(one_source(&[("a", false), ("b", false)], true).is_err());
        assert_eq!(one_source(&[("a", false)], false).unwrap(), None);
        assert!(one_source(&[("a", true), ("b", true)], false).is_err());
    }
}
