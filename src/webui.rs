//! Web console — a browser front-end that *is* the CLI.
//!
//! Design goal: as little new code as possible, and automatic consistency with
//! every future CLI change. So this does **not** re-implement any API. It serves
//! one self-contained page and a single `POST /run` endpoint that executes
//! *this very binary* (`std::env::current_exe()`) with the words the user typed.
//! Every command, flag, completion, and behavior is therefore inherited from the
//! CLI for free — add a subcommand tomorrow and it works in the web console with
//! no changes here.
//!
//! It is intentionally a thin local convenience: bind to loopback, and it runs
//! commands as whoever launched it (same trust level as a shell). Passphrases
//! are passed to the child via the environment, never on argv.

use actix_web::{web, App, HttpServer, HttpResponse, middleware};
use serde::{Deserialize, Serialize};
use std::process::Command;

// ---------------------------------------------------------------------------
// Structured dashboard API — used by the visual dashboard in index.html.
// Each endpoint re-invokes this binary (the same way /run does) but interprets
// the output as structured data rather than raw text.
// ---------------------------------------------------------------------------

/// Run the blackbook binary with the given args + optional profile/domain/passphrases.
/// Returns (success, stdout, stderr).
fn run_bbk(
    args: &[&str],
    profile: Option<&str>,
    domain: Option<&str>,
    profile_pass: Option<&str>,
    external_pass: Option<&str>,
) -> (bool, String, String) {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return (false, String::new(), format!("cannot locate binary: {e}")),
    };
    let mut cmd = Command::new(exe);
    if let Some(p) = profile { cmd.args(["-P", p]); }
    if let Some(d) = domain  { cmd.args(["-D", d]); }
    cmd.args(args);
    cmd.env("BLACKBOOK_NO_PROMPT", "1");
    if let Some(p) = profile_pass.filter(|s| !s.is_empty()) {
        cmd.env("BLACKBOOK_PASSPHRASE", p);
    }
    if let Some(p) = external_pass.filter(|s| !s.is_empty()) {
        cmd.env("BLACKBOOK_EXTERNAL_PASSPHRASE", p);
    }
    cmd.stdin(std::process::Stdio::null());
    match cmd.output() {
        Ok(o) => (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        ),
        Err(e) => (false, String::new(), e.to_string()),
    }
}

#[derive(Deserialize)]
struct UiCtx {
    #[serde(default)] profile:    Option<String>,
    #[serde(default)] domain:     Option<String>,
    #[serde(default)] passphrase: Option<String>,
}

/// GET /api/ui/profiles — list saved profiles + which is active.
async fn ui_profiles() -> HttpResponse {
    let (_, out, _) = run_bbk(&["profile", "ls"], None, None, None, None);
    let mut profiles: Vec<String> = Vec::new();
    let mut active: Option<String> = None;
    for raw in out.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('(') { continue; }
        if let Some(rest) = line.strip_prefix("* ") {
            let name = rest.trim().to_string();
            active = Some(name.clone());
            profiles.push(name);
        } else {
            profiles.push(line.to_string());
        }
    }
    HttpResponse::Ok().json(serde_json::json!({ "profiles": profiles, "active": active }))
}

/// GET /api/ui/domains — list domain names visible to a given profile.
async fn ui_domains(ctx: web::Query<UiCtx>) -> HttpResponse {
    let (ok, out, err) = run_bbk(
        &["domain", "ls"],
        ctx.profile.as_deref(), None,
        ctx.passphrase.as_deref(), None,
    );
    if !ok {
        return HttpResponse::Ok().json(serde_json::json!({ "ok": false, "error": err, "domains": [] }));
    }
    // Output: header line + separator + rows of "{name}  {created_at}  {desc}"
    let domains: Vec<String> = out.lines()
        .skip(2)  // skip "NAME  CREATED  DESCRIPTION" header and "---" separator
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('('))
        .filter_map(|l| {
            let name = l.split("  ").next()?.trim().to_string();
            if name.is_empty() { None } else { Some(name) }
        })
        .collect();
    HttpResponse::Ok().json(serde_json::json!({ "ok": true, "domains": domains }))
}

/// GET /api/ui/secrets — list secrets as JSON (calls `ls --json`).
async fn ui_secrets(ctx: web::Query<UiCtx>) -> HttpResponse {
    let (ok, out, err) = run_bbk(
        &["ls", "--json"],
        ctx.profile.as_deref(), ctx.domain.as_deref(),
        ctx.passphrase.as_deref(), None,
    );
    if !ok {
        return HttpResponse::Ok().json(serde_json::json!({ "ok": false, "error": err }));
    }
    let data: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|_| serde_json::json!({ "resources": [], "count": 0 }));
    HttpResponse::Ok().json(serde_json::json!({ "ok": true, "data": data }))
}

/// GET /api/ui/files — list files as JSON (calls `file ls --json`).
async fn ui_files(ctx: web::Query<UiCtx>) -> HttpResponse {
    let (ok, out, err) = run_bbk(
        &["file", "ls", "--json"],
        ctx.profile.as_deref(), ctx.domain.as_deref(),
        ctx.passphrase.as_deref(), None,
    );
    if !ok {
        return HttpResponse::Ok().json(serde_json::json!({ "ok": false, "error": err }));
    }
    let data: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|_| serde_json::json!({ "files": [], "count": 0 }));
    HttpResponse::Ok().json(serde_json::json!({ "ok": true, "data": data }))
}

/// GET /api/ui/commands — the full command catalog, walked from the live clap
/// command tree (the same `Cli::command()` the shell completion uses), so the
/// palette can never drift from the real CLI surface. Returns one entry per
/// non-hidden (sub)command with its path + one-line description.
async fn ui_commands() -> HttpResponse {
    use clap::CommandFactory;
    let root = crate::Cli::command();
    let mut out: Vec<serde_json::Value> = Vec::new();
    walk_commands(&root, &[], &mut out);
    HttpResponse::Ok().json(serde_json::json!({ "commands": out }))
}

fn walk_commands(cmd: &clap::Command, prefix: &[String], out: &mut Vec<serde_json::Value>) {
    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() { continue; }
        let name = sub.get_name().to_string();
        if name == "help" { continue; }
        let mut path = prefix.to_vec();
        path.push(name);
        let about = sub.get_about()
            .map(|s| s.to_string().lines().next().unwrap_or("").trim().to_string())
            .unwrap_or_default();
        // Does this node have any visible subcommands? If so it's a group the
        // user drills into; otherwise it's a runnable leaf.
        let has_subs = sub.get_subcommands().any(|s| !s.is_hide_set() && s.get_name() != "help");
        out.push(serde_json::json!({
            "path":  path.join(" "),
            "about": about,
            "leaf":  !has_subs,
            "group": prefix.first().cloned().unwrap_or_default(),
        }));
        if has_subs {
            walk_commands(sub, &path, out);
        }
    }
}

#[derive(Deserialize)]
struct RevealReq {
    name: String,
    #[serde(default)] profile:              Option<String>,
    #[serde(default)] domain:               Option<String>,
    #[serde(default)] passphrase:           Option<String>,
    #[serde(default)] external_passphrase:  Option<String>,
    #[serde(default)] mfa:                  Option<String>,
    #[serde(default)] request_id:           Option<String>,
}

/// POST /api/ui/reveal — read one secret value via `get NAME`.
async fn ui_reveal(req: web::Json<RevealReq>) -> HttpResponse {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return HttpResponse::Ok().json(serde_json::json!({ "ok": false, "error": e.to_string() })),
    };
    let mut cmd = Command::new(exe);
    // Global flags come before the subcommand.
    if let Some(p) = req.profile.as_deref() { cmd.args(["-P", p]); }
    if let Some(d) = req.domain.as_deref()  { cmd.args(["-D", d]); }
    if let Some(m) = req.mfa.as_deref()     { cmd.args(["-m", m]); }
    cmd.arg("get").arg(req.name.as_str());
    if let Some(rid) = req.request_id.as_deref() { cmd.args(["-r", rid]); }
    cmd.env("BLACKBOOK_NO_PROMPT", "1");
    if let Some(p) = req.passphrase.as_deref().filter(|s| !s.is_empty()) {
        cmd.env("BLACKBOOK_PASSPHRASE", p);
    }
    if let Some(p) = req.external_passphrase.as_deref().filter(|s| !s.is_empty()) {
        cmd.env("BLACKBOOK_EXTERNAL_PASSPHRASE", p);
    }
    cmd.stdin(std::process::Stdio::null());
    match cmd.output() {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
            HttpResponse::Ok().json(serde_json::json!({
                "ok": o.status.success(),
                "value": stdout.trim_end_matches('\n'),
                "stderr": stderr,
            }))
        }
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "ok": false, "error": e.to_string() })),
    }
}

/// The embedded single-page app. One file, no build step, no external assets.
const INDEX_HTML: &str = include_str!("webui/index.html");

#[derive(Deserialize)]
struct RunRequest {
    /// The full command line the user typed (without a leading "blackbook").
    line: String,
    /// Optional passphrases, passed to the child via env so they never hit argv
    /// or the process list. `profile` → $BLACKBOOK_PASSPHRASE (unlock),
    /// `external` → $BLACKBOOK_EXTERNAL_PASSPHRASE (client-side items).
    #[serde(default)] profile_passphrase: Option<String>,
    #[serde(default)] external_passphrase: Option<String>,
}

#[derive(Serialize)]
struct RunResponse {
    ok: bool,
    code: i32,
    stdout: String,
    stderr: String,
}

/// Split a command line into argv the way a POSIX-ish shell would, honoring
/// single and double quotes and backslash escapes — but performing **no**
/// expansion, globbing, piping, or substitution. The tokens go straight to
/// `Command` (no shell is ever invoked), so this can't run anything but the
/// blackbook binary with literal arguments.
fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut started = false;
    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => { in_single = !in_single; started = true; }
            '"' if !in_single => { in_double = !in_double; started = true; }
            '\\' if !in_single => {
                if let Some(&n) = chars.peek() { cur.push(n); chars.next(); started = true; }
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if started { out.push(std::mem::take(&mut cur)); started = false; }
            }
            c => { cur.push(c); started = true; }
        }
    }
    if in_single || in_double { return Err("unterminated quote".into()); }
    if started { out.push(cur); }
    Ok(out)
}

/// Subcommands the web console must never spawn: long-running servers (would
/// hang the request / recurse) and anything that opens an interactive prompt
/// the browser can't answer. Everything else is fair game.
fn is_blocked(argv: &[String]) -> Option<&'static str> {
    // Find the first non-global-flag token = the subcommand.
    let sub = argv.iter().find(|a| !a.starts_with('-')).map(|s| s.as_str());
    match sub {
        Some("server") => Some("`server` runs the API daemon — start it separately, not from the web console."),
        Some("web") => Some("`web` would start another console (no nesting)."),
        Some("__complete") => None, // used by the completion endpoint, but harmless directly
        _ => None,
    }
}

async fn index() -> HttpResponse {
    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(INDEX_HTML)
}

/// Run a blackbook command by re-invoking this binary. The heart of the reuse:
/// the web console is a thin shell over the exact same CLI.
async fn run(req: web::Json<RunRequest>) -> HttpResponse {
    let argv = match tokenize(&req.line) {
        Ok(v) => v,
        Err(e) => return HttpResponse::Ok().json(RunResponse {
            ok: false, code: -1, stdout: String::new(),
            stderr: format!("parse error: {e}"),
        }),
    };
    if argv.is_empty() {
        return HttpResponse::Ok().json(RunResponse { ok: true, code: 0, stdout: String::new(), stderr: String::new() });
    }
    if let Some(reason) = is_blocked(&argv) {
        return HttpResponse::Ok().json(RunResponse {
            ok: false, code: -1, stdout: String::new(), stderr: reason.into(),
        });
    }

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return HttpResponse::Ok().json(RunResponse {
            ok: false, code: -1, stdout: String::new(),
            stderr: format!("cannot locate blackbook binary: {e}"),
        }),
    };

    let mut cmd = Command::new(exe);
    cmd.args(&argv);
    // Forbid interactive passphrase prompts: a child that tried to prompt would
    // grab the terminal `blackbook web` runs in and hang the HTTP request
    // forever (rpassword reads the console directly, so closing stdin isn't
    // enough). With this set, the passphrase sites return a clear error the UI
    // turns into a "set your passphrase" prompt instead.
    cmd.env("BLACKBOOK_NO_PROMPT", "1");
    // Passphrases via env (never argv / process list). Empty → unset so the
    // child falls through to its own env/agent logic unchanged.
    if let Some(p) = req.profile_passphrase.as_deref().filter(|s| !s.is_empty()) {
        cmd.env("BLACKBOOK_PASSPHRASE", p);
    }
    if let Some(p) = req.external_passphrase.as_deref().filter(|s| !s.is_empty()) {
        cmd.env("BLACKBOOK_EXTERNAL_PASSPHRASE", p);
    }
    // Belt and suspenders: also close stdin.
    cmd.stdin(std::process::Stdio::null());

    match cmd.output() {
        Ok(o) => HttpResponse::Ok().json(RunResponse {
            ok: o.status.success(),
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }),
        Err(e) => HttpResponse::Ok().json(RunResponse {
            ok: false, code: -1, stdout: String::new(),
            stderr: format!("failed to run: {e}"),
        }),
    }
}

#[derive(Deserialize)]
struct CompleteRequest { line: String }

#[derive(Serialize)]
struct CompleteResponse { candidates: Vec<String> }

/// Tab-completion: reuse the CLI's own `__complete` brain so suggestions can
/// never drift from the real command surface.
async fn complete(req: web::Json<CompleteRequest>) -> HttpResponse {
    let mut argv = vec!["bbk".to_string()];
    match tokenize(&req.line) {
        Ok(v) => argv.extend(v),
        Err(_) => {}
    }
    // If the line ends in whitespace, the user is starting a new word.
    if req.line.ends_with(char::is_whitespace) || req.line.is_empty() {
        argv.push(String::new());
    }
    let exe = match std::env::current_exe() {
        Ok(p) => p, Err(_) => return HttpResponse::Ok().json(CompleteResponse { candidates: vec![] }),
    };
    let mut cmd = Command::new(exe);
    cmd.arg("__complete").arg("--").args(&argv);
    cmd.env("BLACKBOOK_NO_PROMPT", "1");
    cmd.stdin(std::process::Stdio::null());
    let candidates = match cmd.output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines().map(|s| s.to_string()).filter(|s| !s.is_empty()).collect(),
        Err(_) => vec![],
    };
    HttpResponse::Ok().json(CompleteResponse { candidates })
}

/// Launch the web console. Plain HTTP on loopback by default — it's a local
/// convenience that drives the local CLI, so it carries the user's own
/// credentials/profiles exactly as a terminal would.
pub async fn run_web(bind: &str) -> std::io::Result<()> {
    log::info!("Blackbook web console on http://{bind}  (drives the local CLI)");
    println!("\n  🕮  Blackbook web console → http://{bind}\n");
    let bind = bind.to_string();
    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Compress::default())
            .route("/", web::get().to(index))
            .route("/run", web::post().to(run))
            .route("/complete", web::post().to(complete))
            // Dashboard structured API
            .route("/api/ui/profiles", web::get().to(ui_profiles))
            .route("/api/ui/domains",  web::get().to(ui_domains))
            .route("/api/ui/secrets",  web::get().to(ui_secrets))
            .route("/api/ui/files",    web::get().to(ui_files))
            .route("/api/ui/commands", web::get().to(ui_commands))
            .route("/api/ui/reveal",   web::post().to(ui_reveal))
    })
    .bind(&bind)?
    .run()
    .await
}
