//! `bbk sync`: what this client does to keep in step with the server, in one
//! command. It runs by hand, keeps running (`--watch`), or follows the other
//! commands that use the profile (`--auto on`).
//!
//! Each pass makes every check in turn:
//! 1. this client's share identity is published, so others can send it keys;
//! 2. the keys of items this client sealed are rotated where who may read them
//!    changed;
//! 3. the keys other clients asked for are sent to them.
//!
//! Passphrase changes, which only an item's owner can make, are reported. A
//! new kind of check is a new step in [`pass`], which every way of syncing
//! runs.
//!
//! Per profile, `~/.bbk/sync/<profile>.json` holds the auto-sync setting and
//! when the last pass ran, and `<profile>.lock` is held while a pass runs, so
//! two processes never make the same rotation at once. Neither holds anything
//! secret: what the last notice said is kept only as a hash, since item names
//! are private.

use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;

use crate::client::{self, BlackbookClient, Session};
use crate::share_cli::{self, KeyWork};
use crate::{AppError, Result};

/// The interval when none is set: between the watcher's passes, and the
/// least time between the passes that follow commands.
const DEFAULT_EVERY: u64 = 60;

#[derive(Args)]
pub struct SyncArgs {
    /// Only send keys to this client. Every rotation that's due is still made.
    #[arg(long, conflicts_with_all = ["watch", "auto"])]
    to: Option<String>,
    /// Don't ask for confirmation.
    #[arg(short = 'y', long, conflicts_with = "auto")]
    yes: bool,
    /// Only show what would be done.
    #[arg(long, conflicts_with_all = ["watch", "auto"])]
    dry_run: bool,
    /// Keep running, syncing every --every, until stopped (Ctrl-C). It acts
    /// without asking, and keeps the profile open while it runs.
    #[arg(long, conflicts_with = "auto")]
    watch: bool,
    /// Sync on its own after each command that uses this profile, at most
    /// once every --every, acting without asking: `on` or `off`. With no
    /// value, shows the setting.
    #[arg(long, value_name = "on|off", num_args = 0..=1)]
    auto: Option<Option<Switch>>,
    /// The interval, in seconds or as 90s / 15m / 1h: saved with --auto (0
    /// syncs after every command), or for this --watch only. Defaults to the
    /// saved one, or 1m.
    #[arg(long, value_name = "DURATION")]
    every: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Switch {
    On,
    Off,
}

// ---------------------------------------------------------------------------
// Per-profile state
// ---------------------------------------------------------------------------

fn sync_dir() -> Result<PathBuf> {
    Ok(Session::bbk_dir()?.join("sync"))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `~/.bbk/sync/<profile>.json`.
#[derive(Default, Serialize, Deserialize)]
struct State {
    /// Whether a pass follows the commands that use the profile.
    #[serde(default)]
    auto: bool,
    /// The interval in seconds, if one was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    every: Option<u64>,
    /// When the last pass ran, in Unix seconds.
    #[serde(default)]
    last: u64,
    /// A hash of what the last pass after a command said needs the user, so
    /// that it's said again only when it changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notice: Option<String>,
}

impl State {
    /// The profile's state; the defaults if it has none or it can't be read.
    fn load(profile: &str) -> Self {
        sync_dir()
            .ok()
            .and_then(|d| std::fs::read(d.join(format!("{profile}.json"))).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, profile: &str) -> Result<()> {
        let dir = sync_dir()?;
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{profile}.json"));
        // Write then rename, so a reader never sees half a file.
        let tmp = dir.join(format!("{profile}.json.{}.tmp", std::process::id()));
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        Session::harden(&tmp)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn every(&self) -> u64 {
        self.every.unwrap_or(DEFAULT_EVERY)
    }

    /// Whether a pass should follow a command now (`always`: whatever the
    /// interval).
    fn due(&self, always: bool) -> bool {
        self.auto && (always || now_secs().saturating_sub(self.last) >= self.every())
    }
}

/// Held while a pass runs, so that two processes don't make the same
/// rotation, or write the key store, at once. The OS lets go of it if the
/// process ends.
struct PassLock {
    _file: std::fs::File,
}

impl PassLock {
    /// The lock, or `None` while another pass holds it.
    fn try_take(profile: &str) -> Result<Option<Self>> {
        let dir = sync_dir()?;
        std::fs::create_dir_all(&dir)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(format!("{profile}.lock")))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }

    /// The lock, once the pass holding it is done.
    async fn take(profile: &str) -> Result<Self> {
        let mut said = false;
        loop {
            if let Some(lock) = Self::try_take(profile)? {
                return Ok(lock);
            }
            if !said {
                eprintln!("another sync of this profile is running; waiting for it to finish");
                said = true;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// A pass
// ---------------------------------------------------------------------------

/// How a pass acts.
enum Mode {
    /// `bbk sync`: list what's found, then ask before acting, unless `yes`.
    ByHand {
        to: Option<String>,
        yes: bool,
        dry_run: bool,
    },
    /// The watcher, and the pass after a command: act without asking.
    OnItsOwn,
}

/// What a pass did, and what it couldn't do or leaves to the user.
#[derive(Default)]
struct Report {
    /// It acted: not a dry run, and not declined.
    acted: bool,
    /// There was work, and none of it could be done.
    stuck: bool,
    done: Vec<String>,
    notes: Vec<String>,
}

/// One pass of every check.
async fn pass(
    bb: &BlackbookClient,
    session: &Session,
    mode: &Mode,
    mfa: Option<String>,
) -> Result<Report> {
    let mut report = Report::default();
    let (by_hand, dry_run) = match mode {
        Mode::ByHand { dry_run, .. } => (true, *dry_run),
        Mode::OnItsOwn => (false, false),
    };

    // The share identity, published so that others can send this client
    // keys. By hand it's published again, in case the server lost it.
    if !dry_run {
        if let Err(e) = share_cli::publish(bb, session, by_hand).await {
            report
                .notes
                .push(format!("couldn't publish your share identity: {e}"));
        }
    }

    // Keys: the rotations due on items this client sealed, then the
    // requests for their keys.
    let to = match mode {
        Mode::ByHand { to, .. } => to.as_deref(),
        Mode::OnItsOwn => None,
    };
    let work = KeyWork::list(bb, to).await?;
    match mode {
        Mode::ByHand { yes, .. } => {
            work.print();
            if dry_run {
                return Ok(report);
            }
            if !work.is_empty() && !yes && !confirm(&work.question())? {
                println!("nothing rotated or sent");
                return Ok(report);
            }
        }
        Mode::OnItsOwn => report.notes.extend(work.by_hand()),
    }
    report.acted = true;
    if !work.is_empty() {
        let keys = work.run(bb, session, mfa).await;
        report.stuck = keys.done.is_empty() && !keys.not_yet.is_empty();
        report.done.extend(keys.done);
        report.notes.extend(keys.not_yet);
    }

    // A new kind of check goes here, as a step of its own.
    Ok(report)
}

fn confirm(question: &str) -> Result<bool> {
    use std::io::IsTerminal;
    if crate::credstore::prompts_suppressed() || !std::io::stdin().is_terminal() {
        return Err(AppError::Config(
            "not syncing without confirmation: pass --yes, or turn auto sync on (`bbk sync --auto on`)"
                .into(),
        ));
    }
    eprint!("{question} [y/N] ");
    let answer = crate::read_stdin_line();
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

/// Prints what a pass on its own did, each line after `prefix`. What it
/// couldn't do or leaves to the user is said again only when it changes
/// (`notice` holds a hash of what was said last), so the same note doesn't
/// follow every command.
fn print_on_its_own(result: &Result<Report>, prefix: &str, notice: &mut Option<String>) {
    let (done, notes) = match result {
        Ok(r) => (r.done.as_slice(), r.notes.clone()),
        Err(e) => (&[][..], vec![format!("couldn't sync: {e}")]),
    };
    for d in done {
        eprintln!("{prefix}{d}");
    }
    let hash = (!notes.is_empty()).then(|| hex::encode(Sha256::digest(notes.join("\n"))));
    if hash != *notice {
        for n in &notes {
            eprintln!("{prefix}{n}");
        }
        *notice = hash;
    }
}

/// A pass on its own, under the profile's lock, after which the profile's
/// state records it.
async fn pass_on_its_own(profile: &str, bb: &BlackbookClient, session: &Session, mut state: State) {
    let result = pass(bb, session, &Mode::OnItsOwn, None).await;
    print_on_its_own(&result, "sync: ", &mut state.notice);
    state.last = now_secs();
    let _ = state.save(profile);
}

/// After a command that used the active profile (`always`: or one that just
/// unlocked it, whatever the interval): syncs if auto sync is on for the
/// profile and the last pass was at least the interval ago. It says only what
/// it did and what needs the user, and never fails the command.
pub async fn after_command(always: bool) {
    let profile = client::active_profile();
    if !State::load(&profile).due(always) {
        return;
    }
    // Another pass is running, and does the work.
    let Ok(Some(_lock)) = PassLock::try_take(&profile) else {
        return;
    };
    // As it is now: another pass may have run since.
    let state = State::load(&profile);
    if !state.due(always) {
        return;
    }
    // The command just opened the profile, so it opens again without asking.
    // If it doesn't, there's no one to ask: the next command syncs.
    let Ok(session) = Session::load_unattended(&profile) else {
        return;
    };
    match crate::build_client(&session, None, None) {
        Ok(bb) => pass_on_its_own(&profile, &bb, &session, state).await,
        Err(e) => eprintln!("sync: couldn't sync: {e}"),
    }
}

/// After a login: syncs if auto sync is on for the profile, which the login
/// made active; otherwise says what's waiting on it.
pub async fn after_login(bb: &BlackbookClient, session: &Session) {
    let profile = client::active_profile();
    if !State::load(&profile).auto {
        share_cli::print_waiting(bb).await;
        return;
    }
    let Ok(Some(_lock)) = PassLock::try_take(&profile) else {
        return;
    };
    pass_on_its_own(&profile, bb, session, State::load(&profile)).await;
}

// ---------------------------------------------------------------------------
// `bbk sync`
// ---------------------------------------------------------------------------

/// "30s", "5m", "2h".
fn for_humans(secs: u64) -> String {
    match secs {
        s if s >= 3600 && s % 3600 == 0 => format!("{}h", s / 3600),
        s if s >= 60 && s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// "40s", "3m", "5h", "2d": how long ago, roughly.
fn ago(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

/// The watcher's timestamps, in UTC.
fn stamp() -> String {
    let t = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

fn parse_every(s: &str) -> Result<u64> {
    let secs = crate::crypto_cli::parse_duration(s)?;
    u64::try_from(secs)
        .map_err(|_| AppError::Config(format!("--every can't be negative (got '{s}')")))
}

pub async fn cmd_sync(args: SyncArgs, mfa: Option<String>) -> Result<()> {
    let profile = client::active_profile();
    let every = args.every.as_deref().map(parse_every).transpose()?;
    if let Some(switch) = args.auto {
        return set_auto(&profile, switch, every);
    }
    if args.watch {
        let every = every
            .unwrap_or_else(|| State::load(&profile).every())
            .max(1);
        return watch(&profile, every, mfa).await;
    }
    if every.is_some() {
        return Err(AppError::Config(
            "--every goes with --watch or --auto".into(),
        ));
    }
    let session = Session::load()?;
    let bb = crate::build_client(&session, None, None)?;
    let _lock = PassLock::take(&profile).await?;
    let mode = Mode::ByHand {
        to: args.to,
        yes: args.yes,
        dry_run: args.dry_run,
    };
    let report = pass(&bb, &session, &mode, mfa).await?;
    for line in report.done.iter().chain(&report.notes) {
        eprintln!("{line}");
    }
    if report.acted {
        let mut state = State::load(&profile);
        state.last = now_secs();
        let _ = state.save(&profile);
    }
    if report.stuck {
        return Err(AppError::Client("nothing was rotated or sent".into()));
    }
    Ok(())
}

/// `--auto [on|off]`: sets the profile's setting (and interval), then shows it.
fn set_auto(profile: &str, switch: Option<Switch>, every: Option<u64>) -> Result<()> {
    if !Session::path_for(profile)?.exists() {
        return Err(AppError::Config(format!(
            "there's no profile '{profile}' (see `bbk profile ls`)"
        )));
    }
    let mut state = State::load(profile);
    if switch.is_some() || every.is_some() {
        if let Some(s) = switch {
            state.auto = matches!(s, Switch::On);
        }
        if every.is_some() {
            state.every = every;
        }
        state.save(profile)?;
    }
    if state.auto {
        let when = match state.every() {
            0 => "after each command that uses it".to_string(),
            e => format!(
                "after a command that uses it, when it last did {} or more ago",
                for_humans(e)
            ),
        };
        println!("auto sync is on for profile '{profile}': bbk syncs {when}, rotating and sending keys without asking");
        println!("To sync while you aren't using bbk, keep `bbk sync --watch` running.");
    } else {
        println!("auto sync is off for profile '{profile}': run `bbk sync`, or keep `bbk sync --watch` running");
    }
    if state.last > 0 {
        println!(
            "last synced {} ago",
            ago(now_secs().saturating_sub(state.last))
        );
    }
    Ok(())
}

/// `--watch`: a pass every `every` seconds until stopped.
async fn watch(profile: &str, every: u64, mfa: Option<String>) -> Result<()> {
    // It keeps the profile open for as long as it runs: don't let a crash
    // write it to disk.
    crate::no_core_dumps();
    let mut session = Session::load()?;
    eprintln!(
        "syncing profile '{profile}' every {} until stopped (Ctrl-C)",
        for_humans(every)
    );
    // Its own record of what it last said, apart from the commands': what it
    // prints may go to a log no one reads at a prompt.
    let mut notice = None;
    // A code given with --watch is good for the first pass only.
    let mut mfa = mfa;
    let stop = tokio::signal::ctrl_c();
    tokio::pin!(stop);
    loop {
        // A new login to the profile is picked up while the profile is
        // unlocked; otherwise the watcher goes on with the one it opened.
        if let Ok(s) = Session::load_unattended(profile) {
            session = s;
        }
        if let Some(_lock) = PassLock::try_take(profile)? {
            let result = match crate::build_client(&session, None, None) {
                Ok(bb) => pass(&bb, &session, &Mode::OnItsOwn, mfa.take()).await,
                Err(e) => Err(e),
            };
            print_on_its_own(&result, &format!("{} ", stamp()), &mut notice);
            let mut state = State::load(profile);
            state.last = now_secs();
            let _ = state.save(profile);
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(every)) => {}
            _ = &mut stop => {
                eprintln!("stopped syncing");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_as_people_write_them() {
        assert_eq!(for_humans(0), "0s");
        assert_eq!(for_humans(45), "45s");
        assert_eq!(for_humans(90), "90s");
        assert_eq!(for_humans(300), "5m");
        assert_eq!(for_humans(7200), "2h");
        assert_eq!(ago(59), "59s");
        assert_eq!(ago(61), "1m");
        assert_eq!(ago(3 * 86_400 + 5), "3d");
        assert_eq!(parse_every("15m").unwrap(), 900);
        assert_eq!(parse_every("0").unwrap(), 0);
        assert!(parse_every("-5").is_err());
        assert!(parse_every("soon").is_err());
    }

    #[test]
    fn a_pass_follows_a_command_only_when_on_and_due() {
        let mut s = State::default();
        assert!(!s.due(true), "off: never");
        s.auto = true;
        assert!(s.due(false), "never synced: due");
        s.last = now_secs();
        assert!(!s.due(false), "just synced: not due");
        assert!(s.due(true), "after an unlock: due whatever the interval");
        s.every = Some(0);
        assert!(s.due(false), "an interval of 0: after every command");
        s.every = Some(3600);
        s.last = now_secs() - 3601;
        assert!(s.due(false), "the interval has passed");
    }

    #[test]
    fn a_note_is_said_again_only_when_it_changes() {
        let report = |notes: &[&str]| {
            Ok(Report {
                notes: notes.iter().map(|s| s.to_string()).collect(),
                ..Report::default()
            })
        };
        let mut notice = None;
        print_on_its_own(&report(&["a"]), "", &mut notice);
        let first = notice.clone();
        assert!(first.is_some());
        print_on_its_own(&report(&["a"]), "", &mut notice);
        assert_eq!(
            notice, first,
            "the same note: the same hash, so not said again"
        );
        print_on_its_own(&report(&["a", "b"]), "", &mut notice);
        assert_ne!(notice, first);
        print_on_its_own(&report(&[]), "", &mut notice);
        assert_eq!(notice, None, "nothing to say: a later note is new again");
    }
}
