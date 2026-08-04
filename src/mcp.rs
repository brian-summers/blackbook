//! MCP (Model Context Protocol) server — exposes Blackbook's data-security
//! features to AI agents over stdio JSON-RPC 2.0.
//!
//! Two tiers of tools:
//!   * **Offline** (always available, no server, no secrets leave the machine):
//!     hashing, passphrase encryption/decryption, key derivation, CSPRNG,
//!     visual fingerprints. These call the exact same primitives the rest of
//!     Blackbook uses ([`crate::blackbook_core`], [`crate::credstore`]).
//!   * **Online** (only when a logged-in profile is available): status, and
//!     reading/listing/writing secrets on a Blackbook server. These go through
//!     the normal client ([`crate::client`]), so the server still enforces
//!     mTLS + token, ACLs, K-of-N, and MFA — the agent is just another
//!     authorized client, bounded by the profile's permissions.
//!
//! Security posture (secure by default, like the rest of Blackbook):
//!   * `--offline` lists ONLY the offline crypto tools (no network, ever).
//!   * writes (`secret_put`/`secret_delete`) are hidden and refused unless
//!     `--allow-write` is passed.
//!   * `BLACKBOOK_NO_PROMPT=1` is forced so profile-unlock never blocks on an
//!     interactive prompt (stdin is the protocol channel); online tools instead
//!     return a clear "run `bbk unlock`" error when the profile is locked.
//!   * stdout carries ONLY protocol messages; all logging goes to stderr.

use crate::{client, credstore};
use base64::Engine as _;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::Digest as _;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Protocol versions we understand. We echo the client's if it's one of these,
/// otherwise we answer with our latest ([`PROTO_LATEST`]).
const PROTO_LATEST: &str = "2025-06-18";
const PROTO_SUPPORTED: &[&str] = &["2024-11-05", "2025-03-26", "2025-06-18"];

const ENVELOPE_PREFIX: &str = "bbkx1:";
const ENVELOPE_MAGIC: &[u8] = b"BBKX1";

/// How the server was launched — decides which tools exist and what they can do.
pub struct McpConfig {
    /// Profile to act as for online tools. `None` = offline-only (crypto tools
    /// only; the server never touches the network).
    pub profile: Option<String>,
    /// Hard offline switch: even if a profile exists, expose no network tools.
    pub offline: bool,
    /// Enable the mutating online tools (`secret_put`, `secret_delete`).
    pub allow_write: bool,
    /// Default domain for online tools (overridable per-call).
    pub domain: Option<String>,
}

impl McpConfig {
    /// Online tools are available when we're not forced offline AND a profile
    /// is configured. (Whether it's *unlocked* is discovered lazily per call.)
    fn online(&self) -> bool {
        !self.offline && self.profile.is_some()
    }
}

/// Run the stdio MCP server until stdin closes. Never returns an error to the
/// caller for per-request problems — those are reported in-band as JSON-RPC.
pub async fn run(cfg: McpConfig) -> std::io::Result<()> {
    // Profile-unlock must never block on a console prompt: stdin is the wire.
    std::env::set_var("BLACKBOOK_NO_PROMPT", "1");

    log::info!(
        "blackbook MCP server ready — online: {}, writes: {}",
        if cfg.online() {
            format!("profile '{}'", cfg.profile.as_deref().unwrap_or("?"))
        } else {
            "disabled (offline)".to_string()
        },
        if cfg.allow_write { "enabled" } else { "read-only" },
    );

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                send(&mut stdout, error(Value::Null, -32700, &format!("parse error: {e}"))).await?;
                continue;
            }
        };

        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");

        // Notifications (no `id`) get no response.
        let is_notification = id.is_none();

        match method {
            "initialize" => {
                send(&mut stdout, result(id, initialize_result())).await?;
            }
            "ping" => {
                send(&mut stdout, result(id, json!({}))).await?;
            }
            "tools/list" => {
                send(&mut stdout, result(id, json!({ "tools": tools_list(&cfg) }))).await?;
            }
            "tools/call" => {
                let r = call_tool(&cfg, msg.get("params")).await;
                send(&mut stdout, result(id, r)).await?;
            }
            m if m.starts_with("notifications/") => { /* initialized, cancelled, … — ignore */ }
            _ => {
                if !is_notification {
                    send(&mut stdout, error(id.unwrap_or(Value::Null), -32601,
                        &format!("method not found: {method}"))).await?;
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON-RPC framing (newline-delimited JSON on stdio)
// ---------------------------------------------------------------------------

async fn send(out: &mut tokio::io::Stdout, msg: Value) -> std::io::Result<()> {
    let mut s = serde_json::to_string(&msg).unwrap_or_else(|_| "{}".into());
    s.push('\n');
    out.write_all(s.as_bytes()).await?;
    out.flush().await
}

fn result(id: Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "result": result })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTO_LATEST,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "blackbook", "version": env!("CARGO_PKG_VERSION") },
        "instructions":
            "Blackbook data-security tools. Offline tools (bbk_hash, bbk_random, \
             bbk_encrypt, bbk_decrypt, bbk_derive_key, bbk_fingerprint) run locally \
             and never send data anywhere. Online tools talk to a Blackbook server \
             as an authenticated client; the server enforces its own ACLs/MFA, so \
             you can only reach what this profile is allowed to. Never paste real \
             secrets into a shared transcript."
    })
}

/// A tool result envelope: `{ content: [{type:text,text}], isError }`.
fn tool_ok(text: impl Into<String>) -> Value {
    json!({ "content": [ { "type": "text", "text": text.into() } ], "isError": false })
}
fn tool_err(text: impl Into<String>) -> Value {
    json!({ "content": [ { "type": "text", "text": text.into() } ], "isError": true })
}

// ---------------------------------------------------------------------------
// Tool catalogue
// ---------------------------------------------------------------------------

fn tools_list(cfg: &McpConfig) -> Vec<Value> {
    let mut t = vec![
        tool("bbk_hash",
            "Hash data with a chosen algorithm. Offline; nothing leaves the machine.",
            json!({"type":"object","properties":{
                "data":{"type":"string","description":"Input data."},
                "algorithm":{"type":"string","enum":["sha3-256","sha3-512","sha256","sha512"],"default":"sha3-256"},
                "data_base64":{"type":"boolean","default":false,"description":"Treat `data` as base64 rather than UTF-8 text."}
            },"required":["data"]})),
        tool("bbk_random",
            "Generate cryptographically secure random bytes (keys, tokens, passwords). Offline.",
            json!({"type":"object","properties":{
                "bytes":{"type":"integer","minimum":1,"maximum":4096,"default":32},
                "encoding":{"type":"string","enum":["hex","base64","base64url","token"],"default":"base64url","description":"`token` = URL-safe, unpadded."}
            }})),
        tool("bbk_encrypt",
            "Encrypt text under a passphrase (Argon2id -> AES-256-GCM). Returns a portable 'bbkx1:' envelope. Offline.",
            json!({"type":"object","properties":{
                "plaintext":{"type":"string"},
                "passphrase":{"type":"string","description":"Never stored; used only to derive the key."}
            },"required":["plaintext","passphrase"]})),
        tool("bbk_decrypt",
            "Decrypt a 'bbkx1:' envelope produced by bbk_encrypt, using its passphrase. Offline.",
            json!({"type":"object","properties":{
                "envelope":{"type":"string"},
                "passphrase":{"type":"string"}
            },"required":["envelope","passphrase"]})),
        tool("bbk_derive_key",
            "Derive a 256-bit key from a passphrase with Argon2id (default) or scrypt. Returns key + salt so it's reproducible. Offline.",
            json!({"type":"object","properties":{
                "passphrase":{"type":"string"},
                "algorithm":{"type":"string","enum":["argon2id","scrypt"],"default":"argon2id"},
                "salt_base64":{"type":"string","description":"Reuse a salt (base64). Omit to generate a fresh random 16-byte salt."}
            },"required":["passphrase"]})),
        tool("bbk_fingerprint",
            "Human-verifiable fingerprint of data: OpenSSH-style randomart + braille + SHA3-256 hex. Offline.",
            json!({"type":"object","properties":{
                "data":{"type":"string"},
                "data_base64":{"type":"boolean","default":false}
            },"required":["data"]})),
    ];

    if cfg.online() {
        t.push(tool("bbk_status",
            "Show the connected identity, server, and health of the Blackbook server this profile targets.",
            json!({"type":"object","properties":{}})));
        t.push(tool("bbk_secret_list",
            "List secret names and metadata (kind, read count, policy flags, K-of-N) in a domain. No values are returned.",
            json!({"type":"object","properties":{
                "domain":{"type":"string","description":"Override the default domain."}
            }})));
        t.push(tool("bbk_secret_get",
            "Read a secret's value from the Blackbook server (subject to the server's ACL/MFA/K-of-N). Returns plaintext for server-side secrets.",
            json!({"type":"object","properties":{
                "name":{"type":"string"},
                "domain":{"type":"string"},
                "mfa":{"type":"string","description":"Current 6-digit TOTP code, if the secret requires MFA."},
                "request_id":{"type":"string","description":"Approved K-of-N request id, if the secret is threshold-gated."}
            },"required":["name"]})));
        t.push(tool("bbk_file_list",
            "List files stored on the Blackbook server (metadata only).",
            json!({"type":"object","properties":{
                "domain":{"type":"string"}
            }})));

        if cfg.allow_write {
            t.push(tool("bbk_secret_put",
                "Store (or overwrite) a secret on the Blackbook server. Requires --allow-write.",
                json!({"type":"object","properties":{
                    "name":{"type":"string"},
                    "value":{"type":"string"},
                    "domain":{"type":"string"},
                    "overwrite":{"type":"boolean","default":false},
                    "mfa_required":{"type":"boolean","default":false},
                    "delete_on_read":{"type":"boolean","default":false},
                    "max_reads":{"type":"integer","minimum":1}
                },"required":["name","value"]})));
            t.push(tool("bbk_secret_delete",
                "Delete a secret on the Blackbook server. Requires --allow-write.",
                json!({"type":"object","properties":{
                    "name":{"type":"string"},
                    "domain":{"type":"string"}
                },"required":["name"]})));
        }
    }
    t
}

fn tool(name: &str, description: &str, schema: Value) -> Value {
    json!({ "name": name, "description": description, "inputSchema": schema })
}

// ---------------------------------------------------------------------------
// Tool dispatch
// ---------------------------------------------------------------------------

async fn call_tool(cfg: &McpConfig, params: Option<&Value>) -> Value {
    let params = match params {
        Some(p) => p,
        None => return tool_err("missing params"),
    };
    let name = match params.get("name").and_then(Value::as_str) {
        Some(n) => n,
        None => return tool_err("missing tool name"),
    };
    let empty = json!({});
    let args = params.get("arguments").unwrap_or(&empty);

    let outcome: Result<String, String> = match name {
        // --- offline -------------------------------------------------------
        "bbk_hash" => tool_hash(args),
        "bbk_random" => tool_random(args),
        "bbk_encrypt" => tool_encrypt(args),
        "bbk_decrypt" => tool_decrypt(args),
        "bbk_derive_key" => tool_derive_key(args),
        "bbk_fingerprint" => tool_fingerprint(args),
        // --- online --------------------------------------------------------
        "bbk_status" | "bbk_secret_list" | "bbk_secret_get" | "bbk_file_list"
        | "bbk_secret_put" | "bbk_secret_delete" => {
            if !cfg.online() {
                Err("online tools are disabled — this MCP server was started offline or with no profile".into())
            } else if matches!(name, "bbk_secret_put" | "bbk_secret_delete") && !cfg.allow_write {
                Err("writes are disabled — restart the MCP server with `--allow-write` to enable this tool".into())
            } else {
                call_online(cfg, name, args).await
            }
        }
        other => Err(format!("unknown tool: {other}")),
    };

    match outcome {
        Ok(text) => tool_ok(text),
        Err(msg) => tool_err(msg),
    }
}

// ---------------------------------------------------------------------------
// Offline tools
// ---------------------------------------------------------------------------

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key).and_then(Value::as_str).ok_or_else(|| format!("missing required string argument '{key}'"))
}
fn arg_str_opt<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}
fn arg_bool(args: &Value, key: &str, default: bool) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(default)
}

/// Decode a data argument: UTF-8 text, or base64 when `data_base64` is set.
fn arg_data(args: &Value) -> Result<Vec<u8>, String> {
    let s = arg_str(args, "data")?;
    if arg_bool(args, "data_base64", false) {
        base64::engine::general_purpose::STANDARD.decode(s.trim())
            .map_err(|e| format!("data_base64 is set but the data isn't valid base64: {e}"))
    } else {
        Ok(s.as_bytes().to_vec())
    }
}

fn tool_hash(args: &Value) -> Result<String, String> {
    let data = arg_data(args)?;
    let algo = arg_str_opt(args, "algorithm").unwrap_or("sha3-256");
    let digest = match algo {
        "sha3-256" => sha3::Sha3_256::digest(&data).to_vec(),
        "sha3-512" => sha3::Sha3_512::digest(&data).to_vec(),
        "sha256" => sha2::Sha256::digest(&data).to_vec(),
        "sha512" => sha2::Sha512::digest(&data).to_vec(),
        other => return Err(format!("unknown algorithm '{other}' (use sha3-256, sha3-512, sha256, sha512)")),
    };
    Ok(format!("{algo}: {}", hex::encode(digest)))
}

fn tool_random(args: &Value) -> Result<String, String> {
    let n = args.get("bytes").and_then(Value::as_u64).unwrap_or(32);
    if n == 0 || n > 4096 {
        return Err("bytes must be between 1 and 4096".into());
    }
    let mut buf = vec![0u8; n as usize];
    rand::thread_rng().fill_bytes(&mut buf);
    let enc = arg_str_opt(args, "encoding").unwrap_or("base64url");
    let out = match enc {
        "hex" => hex::encode(&buf),
        "base64" => base64::engine::general_purpose::STANDARD.encode(&buf),
        "base64url" | "token" => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf),
        other => return Err(format!("unknown encoding '{other}' (use hex, base64, base64url, token)")),
    };
    Ok(out)
}

fn tool_encrypt(args: &Value) -> Result<String, String> {
    let plaintext = arg_str(args, "plaintext")?;
    let passphrase = arg_str(args, "passphrase")?;
    seal_envelope(plaintext.as_bytes(), passphrase)
}

fn tool_decrypt(args: &Value) -> Result<String, String> {
    let envelope = arg_str(args, "envelope")?;
    let passphrase = arg_str(args, "passphrase")?;
    let pt = open_envelope(envelope, passphrase)?;
    String::from_utf8(pt).map_err(|_| "decrypted bytes are not valid UTF-8 text".into())
}

fn tool_derive_key(args: &Value) -> Result<String, String> {
    let passphrase = arg_str(args, "passphrase")?;
    let algo = arg_str_opt(args, "algorithm").unwrap_or("argon2id");
    let salt = match arg_str_opt(args, "salt_base64") {
        Some(s) => base64::engine::general_purpose::STANDARD.decode(s.trim())
            .map_err(|e| format!("salt_base64 is not valid base64: {e}"))?,
        None => {
            let mut s = vec![0u8; 16];
            rand::thread_rng().fill_bytes(&mut s);
            s
        }
    };
    let key = match algo {
        "argon2id" => {
            let (k, _, _, _) = credstore::argon2_key(passphrase, &salt).map_err(|e| e.to_string())?;
            k.to_vec()
        }
        "scrypt" => crate::blackbook_core::scrypt_dek(passphrase.as_bytes(), &salt)
            .map_err(|e| e.to_string())?
            .to_vec(),
        other => return Err(format!("unknown algorithm '{other}' (use argon2id or scrypt)")),
    };
    use base64::engine::general_purpose::STANDARD as B64;
    Ok(format!(
        "algorithm: {algo}\nkey_base64: {}\nkey_hex: {}\nsalt_base64: {}",
        B64.encode(&key), hex::encode(&key), B64.encode(&salt)
    ))
}

fn tool_fingerprint(args: &Value) -> Result<String, String> {
    let data = arg_data(args)?;
    let fp = sha3::Sha3_256::digest(&data);
    Ok(format!(
        "{}\nbraille: {}\nsha3-256: {}",
        crate::presentation::randomart(&fp, "bbk"),
        crate::presentation::braille(&fp),
        hex::encode(fp),
    ))
}

/// `bbkx1:` + base64( MAGIC | salt(16) | AES-256-GCM(Argon2id(passphrase,salt), plaintext) ).
fn seal_envelope(plaintext: &[u8], passphrase: &str) -> Result<String, String> {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let (key, _, _, _) = credstore::argon2_key(passphrase, &salt).map_err(|e| e.to_string())?;
    let sealed = crate::blackbook_core::aead_seal(plaintext, key.as_slice()).map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(ENVELOPE_MAGIC.len() + 16 + sealed.len());
    buf.extend_from_slice(ENVELOPE_MAGIC);
    buf.extend_from_slice(&salt);
    buf.extend_from_slice(&sealed);
    Ok(format!("{ENVELOPE_PREFIX}{}", base64::engine::general_purpose::STANDARD.encode(buf)))
}

fn open_envelope(envelope: &str, passphrase: &str) -> Result<Vec<u8>, String> {
    let b64 = envelope.trim().strip_prefix(ENVELOPE_PREFIX)
        .ok_or_else(|| format!("not a Blackbook envelope (expected a '{ENVELOPE_PREFIX}' prefix)"))?;
    let buf = base64::engine::general_purpose::STANDARD.decode(b64)
        .map_err(|e| format!("envelope is not valid base64: {e}"))?;
    let min = ENVELOPE_MAGIC.len() + 16;
    if buf.len() <= min || &buf[..ENVELOPE_MAGIC.len()] != ENVELOPE_MAGIC {
        return Err("corrupted or truncated envelope".into());
    }
    let salt = &buf[ENVELOPE_MAGIC.len()..ENVELOPE_MAGIC.len() + 16];
    let sealed = &buf[ENVELOPE_MAGIC.len() + 16..];
    let (key, _, _, _) = credstore::argon2_key(passphrase, salt).map_err(|e| e.to_string())?;
    crate::blackbook_core::aead_open(sealed, key.as_slice())
        .map_err(|_| "decryption failed — wrong passphrase or a corrupted envelope".to_string())
}

// ---------------------------------------------------------------------------
// Online tools (go through the normal authenticated client)
// ---------------------------------------------------------------------------

/// Build an authenticated client for the configured profile in the effective
/// domain (per-call `domain` overrides the launch default).
fn online_client(cfg: &McpConfig, args: &Value) -> Result<client::BlackbookClient, String> {
    let profile = cfg.profile.as_deref().ok_or("no Blackbook profile is configured")?;
    let session = client::Session::load_named(profile).map_err(|e| format!(
        "could not open profile '{profile}': {e}. Unlock it first: `bbk -P {profile} unlock`, \
         or set $BLACKBOOK_PASSPHRASE in the MCP server's environment."
    ))?;
    let mut bb = client::BlackbookClient::from_session(&session).map_err(|e| e.to_string())?;
    if let Some(d) = arg_str_opt(args, "domain").map(String::from).or_else(|| cfg.domain.clone()) {
        bb = bb.with_domain(d);
    }
    Ok(bb)
}

async fn call_online(cfg: &McpConfig, name: &str, args: &Value) -> Result<String, String> {
    let bb = online_client(cfg, args)?;
    match name {
        "bbk_status" => {
            let who = bb.whoami().await.map_err(|e| e.to_string())?;
            let health = bb.health().await.ok();
            let mut s = format!(
                "identity: {} ({}) — id {}\nauth: {}\nserver: {}",
                who.name, who.role, who.id, who.auth_method, bb.server_url()
            );
            if let Some(ud) = who.user_domain.as_deref() {
                s.push_str(&format!("\nuser domain: {ud}"));
            }
            if let Some(h) = health {
                s.push_str(&format!("\nhealth: {} (db {}), version {}", h.status, h.database, h.version));
            }
            Ok(s)
        }
        "bbk_secret_list" => {
            let list = bb.list().await.map_err(|e| e.to_string())?;
            if list.resources.is_empty() {
                return Ok("(no secrets in this domain)".into());
            }
            let mut lines = vec![format!("{} secret(s):", list.count)];
            for r in &list.resources {
                let kind = if r.external { "external" } else { "server" };
                let status = if r.exhausted_at.is_some() { " [exhausted]" } else { "" };
                let quorum = match (r.threshold_k, r.signatory_count) {
                    (Some(k), Some(n)) => format!(" quorum {k}-of-{n}"),
                    _ => String::new(),
                };
                lines.push(format!("  {} [{kind}]{status}{quorum} (reads: {})", r.resource_name, r.read_count));
            }
            Ok(lines.join("\n"))
        }
        "bbk_secret_get" => {
            let mut bb = bb;
            if let Some(code) = arg_str_opt(args, "mfa") {
                bb = bb.with_mfa(code.to_string());
            }
            let n = arg_str(args, "name")?;
            let r = bb.retrieve_with_request(n, arg_str_opt(args, "request_id")).await
                .map_err(|e| e.to_string())?;
            if r.external {
                Ok(format!(
                    "secret '{}' is client-side encrypted (external): the server only holds an \
                     opaque envelope. Decrypt it with the bbk CLI (which holds the client key).",
                    r.resource_name
                ))
            } else {
                Ok(r.data)
            }
        }
        "bbk_file_list" => {
            let list = bb.file_list().await.map_err(|e| e.to_string())?;
            if list.files.is_empty() {
                return Ok("(no files in this domain)".into());
            }
            let mut lines = vec![format!("{} file(s):", list.count)];
            for f in &list.files {
                lines.push(format!("  {} ({} bytes, {})",
                    f.name, f.size, f.mime_type.as_deref().unwrap_or("application/octet-stream")));
            }
            Ok(lines.join("\n"))
        }
        "bbk_secret_put" => {
            let n = arg_str(args, "name")?;
            let v = arg_str(args, "value")?;
            let flags = client::ResourceFlagsRequest {
                mfa_required: arg_bool(args, "mfa_required", false),
                delete_on_read: arg_bool(args, "delete_on_read", false),
                max_reads: args.get("max_reads").and_then(Value::as_i64),
                rotate_on_read: false,
                preserve_on_cleanup: false,
                no_overwrite: false,
            };
            let any_flag = flags.mfa_required || flags.delete_on_read || flags.max_reads.is_some();
            let r = bb.store(n, v, None, if any_flag { Some(&flags) } else { None }, None,
                arg_bool(args, "overwrite", false)).await.map_err(|e| e.to_string())?;
            Ok(format!("stored '{}' ({}) at {}", r.resource_name, r.encryption_method, r.created_at))
        }
        "bbk_secret_delete" => {
            let n = arg_str(args, "name")?;
            bb.delete(n).await.map_err(|e| e.to_string())?;
            Ok(format!("deleted '{n}'"))
        }
        other => Err(format!("unknown online tool: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrips_and_rejects_wrong_passphrase() {
        let env = seal_envelope(b"top secret", "correct horse").unwrap();
        assert!(env.starts_with(ENVELOPE_PREFIX));
        // The plaintext must not appear in the envelope.
        assert!(!env.contains("top secret"));
        let out = open_envelope(&env, "correct horse").unwrap();
        assert_eq!(out, b"top secret");
        assert!(open_envelope(&env, "wrong").is_err());
        assert!(open_envelope("bbkx1:not-base64!!", "x").is_err());
        assert!(open_envelope("no-prefix", "x").is_err());
    }

    #[test]
    fn hash_matches_known_vector() {
        // SHA3-256("") known digest.
        let out = tool_hash(&json!({"data":"","algorithm":"sha3-256"})).unwrap();
        assert!(out.ends_with("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));
    }

    #[test]
    fn offline_tools_never_require_a_profile() {
        assert!(tool_random(&json!({"bytes":16,"encoding":"hex"})).unwrap().len() == 32);
        assert!(tool_derive_key(&json!({"passphrase":"pw","algorithm":"scrypt"})).is_ok());
        assert!(tool_fingerprint(&json!({"data":"hello"})).unwrap().contains("sha3-256"));
    }

    #[test]
    fn offline_config_hides_online_tools() {
        let cfg = McpConfig { profile: Some("x".into()), offline: true, allow_write: true, domain: None };
        let names: Vec<String> = tools_list(&cfg).iter()
            .map(|t| t["name"].as_str().unwrap().to_string()).collect();
        assert!(names.iter().all(|n| !n.starts_with("bbk_secret") && n != "bbk_status"));
        assert!(names.contains(&"bbk_hash".to_string()));
    }

    #[test]
    fn write_tools_hidden_without_allow_write() {
        let ro = McpConfig { profile: Some("x".into()), offline: false, allow_write: false, domain: None };
        let names: Vec<String> = tools_list(&ro).iter()
            .map(|t| t["name"].as_str().unwrap().to_string()).collect();
        assert!(names.contains(&"bbk_secret_get".to_string()));
        assert!(!names.contains(&"bbk_secret_put".to_string()));
        assert!(!names.contains(&"bbk_secret_delete".to_string()));
    }
}
