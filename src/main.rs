//! sqlite3_rsync — binary front-end for the sqlite3_rsync_rs library.

#![allow(clippy::too_many_arguments)]

use libsqlite3_sys as ffi;
use log::{debug, error, info, warn};
use minimal_logger::MinimalLoggerConfig;
use sqlite3_rsync::{PROTOCOL_VERSION, SqliteRsync, current_time, origin_side, replica_side};
use std::process::{Child, Command, Stdio};

// ───────────────────────────────────────────────────────────────────────────
// Usage
// ───────────────────────────────────────────────────────────────────────────

const USAGE: &str = "\
sqlite3_rsync ORIGIN REPLICA ?OPTIONS?

One of ORIGIN or REPLICA is a pathname to a database on the local
machine and the other is of the form \"USER@HOST:PATH\" describing
a database on a remote machine.  This utility makes REPLICA into a
copy of ORIGIN

OPTIONS:

   --exe PATH      Name of the sqlite3_rsync program on the remote side
   --help          Show this help screen
   -p|--port PORT  Run SSH over TCP port PORT instead of the default 22
   --protocol N    Use sync protocol version N.
   --ssh PATH      Name of the SSH program used to reach the remote side
   -v              Verbose.  Multiple v's for increasing output
   --version       Show detailed version information
   --wal-only      Do not sync unless both databases are in WAL mode
";

// ───────────────────────────────────────────────────────────────────────────
// Safe-character table for shell argument escaping
//
// 0 = ordinary (no quoting needed)
// 1 = needs to be escaped / quoted
// 2 = illegal in a filename
// 3/4/5 = first byte of a 2/3/4-byte UTF-8 sequence (also illegal here)
// ───────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
static SAFE_CHAR: [u8; 256] = [
    /*      x0 x1 x2 x3  x4 x5 x6 x7  x8 x9 xa xb  xc xd xe xf */
    /* 0x */ 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 1x */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    /* 2x */ 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, /* 3x */ 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 1, 1, 0, 1, 1, /* 4x */ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 5x */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, /* 6x */ 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 7x */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1,
    /* 8x */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 9x */ 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* ax */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    /* bx */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* cx */ 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* dx */ 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    /* ex */ 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, /* fx */ 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
];

#[cfg(not(target_os = "windows"))]
static SAFE_CHAR: [u8; 256] = [
    /*      x0 x1 x2 x3  x4 x5 x6 x7  x8 x9 xa xb  xc xd xe xf */
    /* 0x */ 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 1x */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    /* 2x */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, /* 3x */ 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 1, 1, 0, 1, 1, /* 4x */ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 5x */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, /* 6x */ 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 7x */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1,
    /* 8x */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 9x */ 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* ax */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    /* bx */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* cx */ 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* dx */ 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    /* ex */ 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, /* fx */ 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
];

// ───────────────────────────────────────────────────────────────────────────
// Shell argument escaping  (mirrors append_escaped_arg from Fossil)
// ───────────────────────────────────────────────────────────────────────────

/// Append `z_in` to the shell command string `s`, quoting as required.
/// Returns `true` on success, `false` if `z_in` contains an illegal byte.
fn append_escaped_arg(s: &mut String, z_in: &str, is_filename: bool) -> bool {
    let mut need_escape = is_filename && z_in.starts_with('-');
    for &b in z_in.as_bytes() {
        let c = SAFE_CHAR[b as usize];
        if c >= 2 {
            eprintln!(
                "shell argument contains an illegal byte (0x{:02x}): {}",
                b, z_in
            );
            // Also log so callers get this even when stderr is redirected
            error!(
                "shell argument contains an illegal byte (0x{:02x}): {}",
                b, z_in
            );
            return false;
        }
        if c != 0 {
            need_escape = true;
        }
    }
    if !s.is_empty() {
        s.push(' ');
    }

    if !need_escape {
        if is_filename && z_in.starts_with('-') {
            #[cfg(target_os = "windows")]
            s.push_str(".\\");
            #[cfg(not(target_os = "windows"))]
            s.push_str("./");
        }
        s.push_str(z_in);
    } else {
        #[cfg(target_os = "windows")]
        {
            s.push('"');
            if is_filename && z_in.starts_with('-') {
                s.push_str(".\\");
            } else if z_in.starts_with('/') {
                s.push('.');
            }
            for b in z_in.bytes() {
                s.push(b as char);
                if b == b'"' {
                    s.push('"');
                }
                if b == b'\\' {
                    s.push('\\');
                }
                if b == b'%' && is_filename {
                    s.push_str("%cd:~,%");
                }
            }
            s.push('"');
        }
        #[cfg(not(target_os = "windows"))]
        {
            if z_in.contains('\'') {
                // Backslash-escape each special character
                if is_filename && z_in.starts_with('-') {
                    s.push_str("./");
                }
                for b in z_in.bytes() {
                    if SAFE_CHAR[b as usize] != 0 && SAFE_CHAR[b as usize] != 2 {
                        s.push('\\');
                    }
                    s.push(b as char);
                }
            } else {
                s.push('\'');
                if is_filename && z_in.starts_with('-') {
                    s.push_str("./");
                }
                s.push_str(z_in);
                s.push('\'');
            }
        }
    }
    true
}

/// Prepend a rich PATH= argument to the SSH command (Mac workaround).
fn add_path_argument(s: &mut String) {
    append_escaped_arg(
        s,
        "PATH=$HOME/bin:/usr/local/bin:/opt/homebrew/bin:/opt/local/bin:$PATH",
        false,
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Miscellaneous utilities
// ───────────────────────────────────────────────────────────────────────────

/// Return the tail (last path component) of a file path.
fn file_tail(path: &str) -> &str {
    path.rfind('/').map(|i| &path[i + 1..]).unwrap_or(path)
}

/// If `z` is "HOST:PATH" or "USER@HOST:PATH", return the index of the ':'.
/// Returns `None` for plain local paths (including Windows drive letters).
fn host_separator(z: &str) -> Option<usize> {
    #[cfg(target_os = "windows")]
    if z.len() >= 3
        && z.as_bytes()[0].is_ascii_alphabetic()
        && z.as_bytes()[1] == b':'
        && (z.as_bytes()[2] == b'/' || z.as_bytes()[2] == b'\\')
    {
        return None;
    }

    let pos = z.find(':')?;
    // Reject if there is a '/' or '\\' before the colon
    if z[..pos].contains('/') || z[..pos].contains('\\') {
        return None;
    }
    Some(pos)
}

/// Count the number of 'v' characters in a "-vvv…" argument.
fn num_vs(z: &str) -> u8 {
    let Some(z) = z.strip_prefix('-') else {
        return 0;
    };
    let z = z.strip_prefix('-').unwrap_or(z);
    let n = z.bytes().take_while(|&b| b == b'v').count();
    if n > 0 && n == z.len() { n as u8 } else { 0 }
}

// ───────────────────────────────────────────────────────────────────────────
// Child-process management  (popen2 / pclose2)
// ───────────────────────────────────────────────────────────────────────────

/// Spawn a child process running the shell command `cmd`.
/// Returns a `Child` with piped stdin / stdout.
fn popen2(cmd: &str) -> std::io::Result<Child> {
    #[cfg(target_os = "windows")]
    return Command::new("cmd")
        .args(["/C", cmd])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn();

    #[cfg(not(target_os = "windows"))]
    Command::new("sh")
        .args(["-c", cmd])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
}

/// Wait for a child process and return its exit code (0 on success).
fn pclose2(child: &mut Child) -> i32 {
    match child.wait() {
        Ok(status) => status.code().unwrap_or(1),
        Err(_) => 1,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// main()
// ───────────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let argc = args.len();

    // Pre-scan argv for -v flags to set the default log level.
    // RUST_LOG always takes precedence if set; -v flags set the default.
    let n_v: u8 = args[1..].iter().map(|a| num_vs(a)).sum();
    let default_level = match n_v {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    if std::env::var_os("RUST_LOG").is_none() {
        // SAFETY: called at program start, before any threads are spawned.
        unsafe { std::env::set_var("RUST_LOG", default_level) };
    }
    minimal_logger::init(minimal_logger::config_from_env()).expect("failed to initialise logger");

    let mut ctx = SqliteRsync::default();
    let mut is_origin = false;
    let mut is_replica_flag = false;
    let mut z_ssh = "ssh".to_owned();
    let mut i_port: i32 = 0;
    let mut z_exe = "sqlite3_rsync".to_owned();
    let mut z_remote_err: Option<String> = None;
    let mut z_remote_debug: Option<String> = None;

    unsafe {
        ffi::sqlite3_initialize();
    }
    let tm_start = current_time();

    let mut i = 1usize;
    while i < argc {
        // Normalise "--foo" → "-foo" so we can match with a single prefix
        let raw = &args[i];
        let z: &str = if raw.starts_with("--") && raw.len() > 2 {
            &raw[1..]
        } else {
            raw
        };

        macro_rules! next_arg {
            ($opt:expr) => {{
                i += 1;
                if i >= argc {
                    eprintln!("{}: missing argument to {}", args[0], $opt);
                    error!("{}: missing argument to {}", args[0], $opt);
                    std::process::exit(1);
                }
                &args[i]
            }};
        }

        if z == "-origin" {
            is_origin = true;
        } else if z == "-replica" {
            is_replica_flag = true;
        } else if num_vs(z) > 0 {
            ctx.e_verbose = ctx.e_verbose.saturating_add(num_vs(z));
        } else if z == "-protocol" {
            let v: u8 = next_arg!("--protocol").parse().unwrap_or(1);
            ctx.i_protocol = v.clamp(1, PROTOCOL_VERSION);
        } else if z == "-ssh" {
            z_ssh = next_arg!("--ssh").clone();
        } else if z == "-port" || z == "-p" {
            let port_str = next_arg!("--port");
            i_port = port_str.parse().unwrap_or(0);
            if !(1..=65535).contains(&i_port) {
                eprintln!("invalid TCP port number: \"{}\"", port_str);
                error!("invalid TCP port number: \"{}\"", port_str);
                std::process::exit(1);
            }
        } else if z == "-exe" {
            z_exe = next_arg!("--exe").clone();
        } else if z == "-wal-only" {
            ctx.b_wal_only = true;
        } else if z == "-version" {
            let ver = {
                let ptr = unsafe { ffi::sqlite3_sourceid() };
                if ptr.is_null() {
                    String::new()
                } else {
                    unsafe { std::ffi::CStr::from_ptr(ptr) }
                        .to_string_lossy()
                        .into_owned()
                }
            };
            println!("{}", ver);
            return;
        } else if z == "-help" || z == "--help" || z == "-?" {
            print!("{}", USAGE);
            return;
        } else if z == "-logfile" {
            let path = next_arg!("--logfile");
            ctx.p_log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok();
            if ctx.p_log.is_none() {
                eprintln!("cannot open \"{}\" for writing", path);
                error!("cannot open \"{}\" for writing", path);
                std::process::exit(1);
            }
        } else if z == "-errorfile" {
            ctx.z_err_file = Some(next_arg!("--errorfile").clone());
        } else if z == "-remote-errorfile" {
            z_remote_err = Some(next_arg!("--remote-errorfile").clone());
        } else if z == "-debugfile" {
            ctx.z_debug_file = Some(next_arg!("--debugfile").clone());
        } else if z == "-remote-debugfile" {
            z_remote_debug = Some(next_arg!("--remote-debugfile").clone());
        } else if z == "-commcheck" {
            ctx.b_comm_check = true;
        } else if z == "-arg-escape-check" {
            // Debug: print how we would shell-quote every argument
            let mut s = String::new();
            for (k, arg) in args.iter().enumerate() {
                append_escaped_arg(&mut s, arg, k != i);
            }
            println!("{}", s);
            return;
        } else if z.starts_with('-') {
            eprintln!("unknown option: \"{}\". Use --help for more detail.", raw);
            error!("unknown option: \"{}\". Use --help for more detail.", raw);
            std::process::exit(1);
        } else if ctx.z_origin.is_none() {
            ctx.z_origin = Some(z.to_owned());
        } else if ctx.z_replica.is_none() {
            ctx.z_replica = Some(z.to_owned());
        } else {
            eprintln!("Unknown argument: \"{}\"", raw);
            warn!("unexpected argument: \"{}\"", raw);
            std::process::exit(1);
        }
        i += 1;
    }

    if ctx.z_origin.is_none() {
        eprintln!("missing ORIGIN database filename");
        error!("missing ORIGIN database filename");
        std::process::exit(1);
    }
    if ctx.z_replica.is_none() {
        eprintln!("missing REPLICA database filename");
        error!("missing REPLICA database filename");
        std::process::exit(1);
    }
    if is_origin && is_replica_flag {
        eprintln!("bad option combination");
        error!("bad option combination");
        std::process::exit(1);
    }

    // ── Remote side: use stdin/stdout ──
    if is_origin {
        ctx.p_in = Some(Box::new(std::io::stdin()));
        ctx.p_out = Some(Box::new(std::io::stdout()));
        ctx.is_remote = true;
        origin_side(&mut ctx);
        return;
    }
    if is_replica_flag {
        ctx.p_in = Some(Box::new(std::io::stdin()));
        ctx.p_out = Some(Box::new(std::io::stdout()));
        ctx.is_remote = true;
        replica_side(&mut ctx);
        return;
    }

    let origin = ctx.z_origin.clone().unwrap();
    let replica = ctx.z_replica.clone().unwrap();

    let mut child: Option<Child>;

    /// Helper that builds the common SSH prefix into `cmd`.
    fn build_ssh_prefix(cmd: &mut String, z_ssh: &str, i_port: i32, host: &str, retry: bool) {
        append_escaped_arg(cmd, z_ssh, true);
        if i_port > 0 {
            cmd.push_str(&format!(" -p {}", i_port));
        }
        cmd.push_str(" -e none");
        append_escaped_arg(cmd, host, false);
        if retry {
            add_path_argument(cmd);
        }
    }

    /// Helper that appends common debug/error-file options.
    fn append_file_opts(
        cmd: &mut String,
        err_file: &Option<String>,
        debug_file: &Option<String>,
        wal_only: bool,
        b_comm_check: bool,
        verbose: &mut u8,
    ) {
        if b_comm_check {
            append_escaped_arg(cmd, "--commcheck", false);
            if *verbose == 0 {
                *verbose = 1;
            }
        }
        if let Some(f) = err_file {
            append_escaped_arg(cmd, "--errorfile", false);
            append_escaped_arg(cmd, f, true);
        }
        if let Some(f) = debug_file {
            append_escaped_arg(cmd, "--debugfile", false);
            append_escaped_arg(cmd, f, true);
        }
        if wal_only {
            append_escaped_arg(cmd, "--wal-only", false);
        }
    }

    if let Some(sep) = host_separator(&origin) {
        // ── Remote ORIGIN, local REPLICA ──
        let host = origin[..sep].to_owned();
        let remote_path = origin[sep + 1..].to_owned();
        ctx.z_origin = Some(host.clone());

        if host_separator(&replica).is_some() {
            eprintln!(
                "At least one of ORIGIN and REPLICA must be a local database\n\
                       You provided two remote databases."
            );
            error!("both ORIGIN and REPLICA are remote; at least one must be local");
            std::process::exit(1);
        }

        let mut i_retry = 0u32;
        loop {
            let mut cmd = String::new();
            build_ssh_prefix(&mut cmd, &z_ssh, i_port, &host, i_retry > 0);
            append_escaped_arg(&mut cmd, &z_exe, true);
            append_escaped_arg(&mut cmd, "--origin", false);
            append_file_opts(
                &mut cmd,
                &z_remote_err,
                &z_remote_debug,
                ctx.b_wal_only,
                ctx.b_comm_check,
                &mut ctx.e_verbose,
            );
            append_escaped_arg(&mut cmd, &remote_path, true);
            append_escaped_arg(&mut cmd, file_tail(&replica), true);
            if ctx.e_verbose < 2 && i_retry == 0 {
                append_escaped_arg(&mut cmd, "2>/dev/null", false);
            }
            if ctx.e_verbose >= 2 {
                println!("{}", cmd);
            }
            debug!("spawning remote-origin: {}", cmd);

            match popen2(&cmd) {
                Err(_) => {
                    if i_retry >= 1 {
                        eprintln!("Could not start auxiliary process: {}", cmd);
                        error!("could not start auxiliary process: {}", cmd);
                        std::process::exit(1);
                    }
                    if ctx.e_verbose >= 2 {
                        println!("ssh FAILED.  Retry with a PATH= argument...");
                    }
                    debug!("ssh FAILED, will retry with PATH= argument");
                    i_retry += 1;
                    continue;
                }
                Ok(mut c) => {
                    ctx.p_in = Some(Box::new(c.stdout.take().unwrap()));
                    ctx.p_out = Some(Box::new(c.stdin.take().unwrap()));
                    child = Some(c);
                }
            }
            replica_side(&mut ctx);
            if ctx.n_hash_sent == 0 && i_retry == 0 {
                ctx.p_in = None;
                ctx.p_out = None;
                if let Some(ref mut c) = child {
                    let _ = c.wait();
                }
                drop(child.take());
                i_retry += 1;
                continue;
            }
            break;
        }
    } else if let Some(sep) = host_separator(&replica) {
        // ── Local ORIGIN, remote REPLICA ──
        let host = replica[..sep].to_owned();
        let remote_path = replica[sep + 1..].to_owned();
        ctx.z_replica = Some(host.clone());

        let mut i_retry = 0u32;
        loop {
            let mut cmd = String::new();
            build_ssh_prefix(&mut cmd, &z_ssh, i_port, &host, i_retry == 1);
            append_escaped_arg(&mut cmd, &z_exe, true);
            append_escaped_arg(&mut cmd, "--replica", false);
            append_file_opts(
                &mut cmd,
                &z_remote_err,
                &z_remote_debug,
                ctx.b_wal_only,
                ctx.b_comm_check,
                &mut ctx.e_verbose,
            );
            append_escaped_arg(&mut cmd, file_tail(&origin), true);
            append_escaped_arg(&mut cmd, &remote_path, true);
            if ctx.e_verbose < 2 && i_retry == 0 {
                append_escaped_arg(&mut cmd, "2>/dev/null", false);
            }
            if ctx.e_verbose >= 2 {
                println!("{}", cmd);
            }
            debug!("spawning remote-replica: {}", cmd);

            match popen2(&cmd) {
                Err(_) => {
                    if i_retry >= 1 {
                        eprintln!("Could not start auxiliary process: {}", cmd);
                        error!("could not start auxiliary process: {}", cmd);
                        std::process::exit(1);
                    }
                    if ctx.e_verbose >= 2 {
                        println!("ssh FAILED.  Retry with a PATH= argument...");
                    }
                    debug!("ssh FAILED, will retry with PATH= argument");
                    i_retry += 1;
                    continue;
                }
                Ok(mut c) => {
                    ctx.p_in = Some(Box::new(c.stdout.take().unwrap()));
                    ctx.p_out = Some(Box::new(c.stdin.take().unwrap()));
                    child = Some(c);
                }
            }
            origin_side(&mut ctx);
            if ctx.n_hash_sent == 0 && i_retry == 0 {
                ctx.p_in = None;
                ctx.p_out = None;
                if let Some(ref mut c) = child {
                    let _ = c.wait();
                }
                drop(child.take());
                i_retry += 1;
                continue;
            }
            break;
        }
    } else {
        // ── Both local: spawn self as --replica subprocess ──
        let exe = std::env::current_exe().unwrap_or_else(|_| args[0].clone().into());
        let exe_str = exe.to_string_lossy();
        let mut cmd = String::new();
        append_escaped_arg(&mut cmd, &exe_str, true);
        append_escaped_arg(&mut cmd, "--replica", false);
        if ctx.b_comm_check {
            append_escaped_arg(&mut cmd, "--commcheck", false);
        }
        if let Some(ref f) = z_remote_err {
            append_escaped_arg(&mut cmd, "--errorfile", false);
            append_escaped_arg(&mut cmd, f, true);
        }
        if let Some(ref f) = z_remote_debug {
            append_escaped_arg(&mut cmd, "--debugfile", false);
            append_escaped_arg(&mut cmd, f, true);
        }
        append_escaped_arg(&mut cmd, &origin, true);
        append_escaped_arg(&mut cmd, &replica, true);
        if ctx.e_verbose >= 2 {
            println!("{}", cmd);
        }
        debug!("spawning local replica: {}", cmd);

        match popen2(&cmd) {
            Err(_) => {
                eprintln!("Could not start auxiliary process: {}", cmd);
                error!("could not start auxiliary process: {}", cmd);
                std::process::exit(1);
            }
            Ok(mut c) => {
                ctx.p_in = Some(Box::new(c.stdout.take().unwrap()));
                ctx.p_out = Some(Box::new(c.stdin.take().unwrap()));
                child = Some(c);
            }
        }
        origin_side(&mut ctx);
    }

    // Close pipes, then wait for child
    ctx.p_in = None;
    ctx.p_out = None;
    if let Some(ref mut c) = child {
        let rc = pclose2(c);
        if rc != 0 {
            ctx.n_err += 1;
        }
    }
    drop(ctx.p_log);

    let tm_end = current_time();
    let tm_elapse = tm_end - tm_start;

    if ctx.n_err > 0 {
        error!("databases were not synced due to errors");
    }
    let sz_total = ctx.n_page as i64 * ctx.sz_page as i64;
    let n_io = (ctx.n_out + ctx.n_in) as i64;
    if tm_elapse > 0 {
        info!(
            "sent {} bytes, received {} bytes, {:.2} bytes/sec",
            ctx.n_out,
            ctx.n_in,
            1000.0 * n_io as f64 / tm_elapse as f64
        );
    } else {
        info!("sent {} bytes, received {} bytes", ctx.n_out, ctx.n_in);
    }
    if ctx.n_err == 0 {
        if n_io > 0 && n_io <= sz_total {
            info!(
                "total size {}  speedup is {:.2}",
                sz_total,
                sz_total as f64 / n_io as f64
            );
        } else {
            info!("total size {}", sz_total);
        }
    }
    debug!(
        "hashes: {}  hash-rounds: {}  page updates: {}  protocol: {}",
        ctx.n_hash_sent, ctx.n_round, ctx.n_page_sent, ctx.i_protocol
    );

    unsafe {
        ffi::sqlite3_shutdown();
    }
    std::process::exit(ctx.n_err as i32);
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── file_tail ────────────────────────────────────────────────────────────

    #[test]
    fn file_tail_plain_filename() {
        assert_eq!(file_tail("mydb.sqlite"), "mydb.sqlite");
    }

    #[test]
    fn file_tail_with_path() {
        assert_eq!(file_tail("/home/user/mydb.sqlite"), "mydb.sqlite");
    }

    #[test]
    fn file_tail_trailing_slash() {
        assert_eq!(file_tail("/home/user/"), "");
    }

    #[test]
    fn file_tail_empty() {
        assert_eq!(file_tail(""), "");
    }

    // ── host_separator ───────────────────────────────────────────────────────

    #[test]
    fn host_separator_user_at_host() {
        let s = "user@host.example.com:/path/to/db";
        let pos = host_separator(s).unwrap();
        assert_eq!(&s[..pos], "user@host.example.com");
        assert_eq!(&s[pos + 1..], "/path/to/db");
    }

    #[test]
    fn host_separator_simple_host() {
        let s = "host:/data/db.sqlite";
        assert_eq!(host_separator(s), Some(4));
    }

    #[test]
    fn host_separator_local_path() {
        assert_eq!(host_separator("/local/path.db"), None);
    }

    #[test]
    fn host_separator_relative_path() {
        assert_eq!(host_separator("relative/path.db"), None);
    }

    #[test]
    fn host_separator_slash_before_colon() {
        // "/dir/host:path" — the slash comes before the colon, so it's local
        assert_eq!(host_separator("/dir/host:path"), None);
    }

    #[test]
    fn host_separator_no_colon() {
        assert_eq!(host_separator("nodomain"), None);
    }

    // ── num_vs ───────────────────────────────────────────────────────────────

    #[test]
    fn num_vs_single_v() {
        assert_eq!(num_vs("-v"), 1);
    }

    #[test]
    fn num_vs_triple_v() {
        assert_eq!(num_vs("-vvv"), 3);
    }

    #[test]
    fn num_vs_double_dash() {
        assert_eq!(num_vs("--vvv"), 3);
    }

    #[test]
    fn num_vs_not_v_flag() {
        assert_eq!(num_vs("-verbose"), 0);
    }

    #[test]
    fn num_vs_no_dash() {
        assert_eq!(num_vs("vvv"), 0);
    }

    #[test]
    fn num_vs_empty() {
        assert_eq!(num_vs(""), 0);
    }

    #[test]
    fn num_vs_mixed() {
        // "-vvvx" is not a pure v-flag
        assert_eq!(num_vs("-vvvx"), 0);
    }

    // ── append_escaped_arg ───────────────────────────────────────────────────

    #[test]
    fn escaped_arg_plain_word() {
        let mut s = String::new();
        let ok = append_escaped_arg(&mut s, "hello", false);
        assert!(ok);
        assert_eq!(s, "hello");
    }

    #[test]
    fn escaped_arg_space_in_value() {
        let mut s = String::new();
        let ok = append_escaped_arg(&mut s, "hello world", false);
        assert!(ok);
        // Must be quoted somehow
        assert!(s.contains("hello") && s.contains("world"));
        assert!(s.starts_with('\'') || s.starts_with('"'));
    }

    #[test]
    fn escaped_arg_multiple_args_space_separated() {
        let mut s = String::new();
        append_escaped_arg(&mut s, "ssh", false);
        append_escaped_arg(&mut s, "host", false);
        assert!(s.contains(' '));
    }

    #[test]
    fn escaped_arg_filename_starting_with_dash() {
        let mut s = String::new();
        let ok = append_escaped_arg(&mut s, "-mydb.sqlite", true);
        assert!(ok);
        // Should prepend ./ to prevent shell misinterpretation
        assert!(s.contains("./") || s.contains(".\\"));
    }

    // ── write_pow2 / read_pow2 round-trip, etc. moved to lib.rs ─────────────
}
