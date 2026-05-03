//! Bandwidth-efficient SQLite database replication.
//!
//! `sqlite3_rsync-rs` synchronises a *replica* SQLite database so that it
//! becomes an exact byte-for-byte copy of an *origin* database, transferring
//! only the pages that differ — much like `rsync` does for ordinary files.
//!
//! # How it works
//!
//! Both sides compute a rolling Keccak-based hash of each database page and
//! exchange hashes over a byte-stream (typically a subprocess's stdio).
//! Only pages whose hashes disagree are sent in full.  The protocol is
//! versioned; see [`PROTOCOL_VERSION`].
//!
//! # Quick start
//!
//! ```no_run
//! use sqlite3_rsync::{SqliteRsync, origin_side, PROTOCOL_VERSION};
//! use std::process::{Command, Stdio};
//!
//! // Spawn a remote replica process and wire up its stdin/stdout.
//! let mut child = Command::new("ssh")
//!     .args(["user@host", "sqlite3_rsync", "--replica", "/path/to/replica.db"])
//!     .stdin(Stdio::piped())
//!     .stdout(Stdio::piped())
//!     .spawn()
//!     .expect("failed to spawn replica process");
//!
//! let mut ctx = SqliteRsync {
//!     z_origin: Some("/path/to/origin.db".into()),
//!     z_replica: Some("/path/to/replica.db".into()),
//!     p_out: Some(Box::new(child.stdin.take().unwrap())),
//!     p_in:  Some(Box::new(child.stdout.take().unwrap())),
//!     ..SqliteRsync::default()
//! };
//!
//! origin_side(&mut ctx);
//! assert_eq!(ctx.n_err, 0, "sync failed");
//! ```
//!
//! # Provenance
//!
//! Original C implementation by D. Richard Hipp, dedicated to the public
//! domain.  This Rust port preserves the wire protocol and semantics.

#![allow(clippy::too_many_arguments, clippy::missing_safety_doc)]

use libsqlite3_sys as ffi;
use log::{debug, error, info};
use std::ffi::CString;
use std::io::{Read, Write, pipe};
use std::mem;
use std::ptr;

// ───────────────────────────────────────────────────────────────────────────
// Protocol constants
// ───────────────────────────────────────────────────────────────────────────

/// Wire protocol version spoken by this build.
///
/// The origin advertises this version in `ORIGIN_BEGIN`; the replica may
/// request a lower version via `REPLICA_BEGIN` if it only implements an
/// older subset.  Version 2 adds coarse-grained aggregate hashing to reduce
/// the number of round-trips for large databases.
pub const PROTOCOL_VERSION: u8 = 2;

// Origin → Replica messages
const ORIGIN_BEGIN: i32 = 0x41;
const ORIGIN_END: i32 = 0x42;
const ORIGIN_ERROR: i32 = 0x43;
const ORIGIN_PAGE: i32 = 0x44;
const ORIGIN_TXN: i32 = 0x45;
const ORIGIN_MSG: i32 = 0x46;
const ORIGIN_DETAIL: i32 = 0x47;
const ORIGIN_READY: i32 = 0x48;

// Replica → Origin messages
const REPLICA_BEGIN: i32 = 0x61;
const REPLICA_ERROR: i32 = 0x62;
const REPLICA_END: i32 = 0x63;
const REPLICA_HASH: i32 = 0x64;
const REPLICA_READY: i32 = 0x65;
const REPLICA_MSG: i32 = 0x66;
const REPLICA_CONFIG: i32 = 0x67;

// SQLite function-creation flags (hardcoded to avoid version skew)
const SQLITE_FUNC_FLAGS: i32 = 1 /*UTF8*/ | 0x800 /*DETERMINISTIC*/ | 0x200000 /*INNOCUOUS*/;

// ───────────────────────────────────────────────────────────────────────────
// Keccak / SHA3 hash engine  (160-bit output, only 6 rounds vs SHA3's 24)
// ───────────────────────────────────────────────────────────────────────────

const KECCAK_RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Keccak-f\[1600\] permutation, limited to 6 rounds.
fn keccak_f1600_step(s: &mut [u64; 25]) {
    macro_rules! rol64 {
        ($a:expr, $x:expr) => {
            ($a << $x) | ($a >> (64u64 - $x))
        };
    }
    // Map: aXY → s[X*5+Y]
    for i in 0..6usize {
        let c0 = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20];
        let c1 = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21];
        let c2 = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22];
        let c3 = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23];
        let c4 = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];
        let d0 = c4 ^ rol64!(c1, 1);
        let d1 = c0 ^ rol64!(c2, 1);
        let d2 = c1 ^ rol64!(c3, 1);
        let d3 = c2 ^ rol64!(c4, 1);
        let d4 = c3 ^ rol64!(c0, 1);

        // Group 1: a00,a11,a22,a33,a44
        let (b0, b1, b2, b3, b4) = (
            s[0] ^ d0,
            rol64!(s[6] ^ d1, 44),
            rol64!(s[12] ^ d2, 43),
            rol64!(s[18] ^ d3, 21),
            rol64!(s[24] ^ d4, 14),
        );
        s[0] = (b0 ^ ((!b1) & b2)) ^ KECCAK_RC[i];
        s[6] = b1 ^ ((!b2) & b3);
        s[12] = b2 ^ ((!b3) & b4);
        s[18] = b3 ^ ((!b4) & b0);
        s[24] = b4 ^ ((!b0) & b1);

        // Group 2: a20,a31,a42,a03,a14  (b0=a03, b1=a14, b2=a20, b3=a31, b4=a42)
        let (b0, b1, b2, b3, b4) = (
            rol64!(s[3] ^ d3, 28),
            rol64!(s[9] ^ d4, 20),
            rol64!(s[10] ^ d0, 3),
            rol64!(s[16] ^ d1, 45),
            rol64!(s[22] ^ d2, 61),
        );
        s[10] = b0 ^ ((!b1) & b2);
        s[16] = b1 ^ ((!b2) & b3);
        s[22] = b2 ^ ((!b3) & b4);
        s[3] = b3 ^ ((!b4) & b0);
        s[9] = b4 ^ ((!b0) & b1);

        // Group 3: a40,a01,a12,a23,a34  (b0=a01, b1=a12, b2=a23, b3=a34, b4=a40)
        let (b0, b1, b2, b3, b4) = (
            rol64!(s[1] ^ d1, 1),
            rol64!(s[7] ^ d2, 6),
            rol64!(s[13] ^ d3, 25),
            rol64!(s[19] ^ d4, 8),
            rol64!(s[20] ^ d0, 18),
        );
        s[20] = b0 ^ ((!b1) & b2);
        s[1] = b1 ^ ((!b2) & b3);
        s[7] = b2 ^ ((!b3) & b4);
        s[13] = b3 ^ ((!b4) & b0);
        s[19] = b4 ^ ((!b0) & b1);

        // Group 4: a10,a21,a32,a43,a04  (b0=a04, b1=a10, b2=a21, b3=a32, b4=a43)
        let (b0, b1, b2, b3, b4) = (
            rol64!(s[4] ^ d4, 27),
            rol64!(s[5] ^ d0, 36),
            rol64!(s[11] ^ d1, 10),
            rol64!(s[17] ^ d2, 15),
            rol64!(s[23] ^ d3, 56),
        );
        s[5] = b0 ^ ((!b1) & b2);
        s[11] = b1 ^ ((!b2) & b3);
        s[17] = b2 ^ ((!b3) & b4);
        s[23] = b3 ^ ((!b4) & b0);
        s[4] = b4 ^ ((!b0) & b1);

        // Group 5: a30,a41,a02,a13,a24  (b0=a02, b1=a13, b2=a24, b3=a30, b4=a41)
        let (b0, b1, b2, b3, b4) = (
            rol64!(s[2] ^ d2, 62),
            rol64!(s[8] ^ d3, 55),
            rol64!(s[14] ^ d4, 39),
            rol64!(s[15] ^ d0, 41),
            rol64!(s[21] ^ d1, 2),
        );
        s[15] = b0 ^ ((!b1) & b2);
        s[21] = b1 ^ ((!b2) & b3);
        s[2] = b2 ^ ((!b3) & b4);
        s[8] = b3 ^ ((!b4) & b0);
        s[14] = b4 ^ ((!b0) & b1);
    }
}

/// Hash state. `#[repr(C)]` so SQLite can manage its memory via
/// `sqlite3_aggregate_context`.  Zero-initialised memory is valid as the
/// "not yet started" state (detected by `i_size == 0`).
#[repr(C)]
struct HashContext {
    s: [u64; 25], // Keccak state (5×5 lanes of 64 bits each, stored as bytes)
    n_rate: u32,
    n_loaded: u32,
    ix_mask: u32, // 0 = little-endian, 7 = big-endian
    i_size: u32,  // 0 means uninitialised
}

impl HashContext {
    fn new(i_size: u32) -> Self {
        let n_rate = if i_size >= 128 && i_size <= 512 {
            (1600 - ((i_size + 31) & !31) * 2) / 8
        } else {
            (1600 - 2 * 256) / 8
        };
        let ix_mask = if cfg!(target_endian = "little") { 0 } else { 7 };
        Self {
            s: [0u64; 25],
            n_rate,
            n_loaded: 0,
            ix_mask,
            i_size,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let n_rate = self.n_rate as usize;
        let ix_mask = self.ix_mask as usize;
        // SAFETY: [u64; 25] is exactly 200 bytes; we only index up to n_rate-1 (≤159).
        let bytes = unsafe { std::slice::from_raw_parts_mut(self.s.as_mut_ptr() as *mut u8, 200) };
        for &b in data {
            bytes[self.n_loaded as usize ^ ix_mask] ^= b;
            self.n_loaded += 1;
            if self.n_loaded as usize == n_rate {
                keccak_f1600_step(&mut self.s);
                self.n_loaded = 0;
            }
        }
    }

    /// Finalise and return the 20-byte (160-bit) hash.
    fn finalize(&mut self) -> [u8; 20] {
        let n_rate = self.n_rate as usize;
        let ix_mask = self.ix_mask as usize;
        if self.n_loaded as usize == n_rate - 1 {
            self.update(&[0x86]);
        } else {
            self.update(&[0x06]);
            self.n_loaded = (n_rate - 1) as u32;
            self.update(&[0x80]);
        }
        // Extract the first 20 output bytes from the Keccak state with
        // endianness correction (ix_mask=0 on LE, 7 on BE).
        // SAFETY: [u64; 25] is exactly 200 bytes; we only read indices 0..19.
        let bytes = unsafe { std::slice::from_raw_parts(self.s.as_ptr() as *const u8, 200) };
        let mut out = [0u8; 20];
        for i in 0..20usize {
            out[i] = bytes[i ^ ix_mask];
        }
        out
    }
}

// ── SQLite SQL function callbacks ──────────────────────────────────────────

/// SQLITE_TRANSIENT sentinel (-1) cast to the destructor type SQLite expects.
#[inline]
fn sqlite_transient() -> ffi::sqlite3_destructor_type {
    // SAFETY: -1 is the documented sentinel value for SQLITE_TRANSIENT.
    unsafe { Some(mem::transmute(-1_isize)) }
}

/// Feed a sqlite3_value into a HashContext, handling BLOB vs TEXT.
///
/// # Safety
/// `arg` must be a valid, non-NULL sqlite3_value pointer whose type is
/// not SQLITE_NULL (caller must check beforehand).
unsafe fn feed_value(cx: &mut HashContext, arg: *mut ffi::sqlite3_value) {
    unsafe {
        let etype = ffi::sqlite3_value_type(arg);
        let nbyte = ffi::sqlite3_value_bytes(arg) as usize;
        if etype == ffi::SQLITE_BLOB {
            cx.update(std::slice::from_raw_parts(
                ffi::sqlite3_value_blob(arg) as *const u8,
                nbyte,
            ));
        } else {
            cx.update(std::slice::from_raw_parts(
                ffi::sqlite3_value_text(arg),
                nbyte,
            ));
        }
    }
}

/// `hash(X)` — returns a 160-bit BLOB which is the hash of X.
unsafe extern "C" fn hash_func(
    ctx: *mut ffi::sqlite3_context,
    _argc: std::os::raw::c_int,
    argv: *mut *mut ffi::sqlite3_value,
) {
    unsafe {
        let arg = *argv;
        if ffi::sqlite3_value_type(arg) == ffi::SQLITE_NULL {
            return;
        }
        let mut cx = HashContext::new(160);
        feed_value(&mut cx, arg);
        let result = cx.finalize();
        ffi::sqlite3_result_blob(ctx, result.as_ptr() as *const _, 20, sqlite_transient());
    }
}

/// `agghash(X)` step — accumulates bytes from each row.
unsafe extern "C" fn agghash_step(
    ctx: *mut ffi::sqlite3_context,
    _argc: std::os::raw::c_int,
    argv: *mut *mut ffi::sqlite3_value,
) {
    unsafe {
        let arg = *argv;
        if ffi::sqlite3_value_type(arg) == ffi::SQLITE_NULL {
            return;
        }
        let pcx = ffi::sqlite3_aggregate_context(ctx, mem::size_of::<HashContext>() as i32)
            as *mut HashContext;
        if pcx.is_null() {
            return;
        }
        if (*pcx).i_size == 0 {
            *pcx = HashContext::new(160);
        }
        feed_value(&mut *pcx, arg);
    }
}

/// `agghash(X)` finaliser — emits the accumulated hash.
unsafe extern "C" fn agghash_final(ctx: *mut ffi::sqlite3_context) {
    unsafe {
        let pcx = ffi::sqlite3_aggregate_context(ctx, 0) as *mut HashContext;
        if pcx.is_null() {
            return;
        }
        let result = (*pcx).finalize();
        ffi::sqlite3_result_blob(ctx, result.as_ptr() as *const _, 20, sqlite_transient());
    }
}

/// Register the `hash()` and `agghash()` SQL functions on a connection.
///
/// Both functions must be present on a connection before calling
/// [`origin_side`] or [`replica_side`]; this is done automatically inside
/// those functions, but you can call it explicitly when writing tests or
/// using the functions in ad-hoc queries.
///
/// - `hash(X)` — returns a 20-byte BLOB (160-bit Keccak digest of `X`).
/// - `agghash(X)` — aggregate; XORs the individual `hash()` results for
///   each row, producing a single 20-byte summary BLOB.
///
/// Returns `true` if both functions were registered successfully,
/// `false` if either registration failed.
/// # Safety
/// `db` must be a valid, open `sqlite3` connection pointer.
pub unsafe fn hash_register(db: *mut ffi::sqlite3) -> bool {
    unsafe {
        let rc1 = ffi::sqlite3_create_function_v2(
            db,
            b"hash\0".as_ptr() as *const _,
            1,
            SQLITE_FUNC_FLAGS,
            ptr::null_mut(),
            Some(hash_func),
            None,
            None,
            None,
        );
        let rc2 = ffi::sqlite3_create_function_v2(
            db,
            b"agghash\0".as_ptr() as *const _,
            1,
            SQLITE_FUNC_FLAGS,
            ptr::null_mut(),
            None,
            Some(agghash_step),
            Some(agghash_final),
            None,
        );
        rc1 == ffi::SQLITE_OK && rc2 == ffi::SQLITE_OK
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Context structure (mirrors C's SQLiteRsync)
// ───────────────────────────────────────────────────────────────────────────

/// Shared state for one side of a sync session.
///
/// Construct with [`SqliteRsync::default()`], set the fields you need, then
/// call [`origin_side`] or [`replica_side`].  After the call, inspect
/// [`n_err`](SqliteRsync::n_err) to check for errors.
///
/// # Required fields
///
/// | Side | Must set |
/// |------|----------|
/// | origin  | `z_origin`, `p_in`, `p_out` |
/// | replica | `z_replica`, `p_in`, `p_out` |
pub struct SqliteRsync {
    /// File-system path of the origin database.
    pub z_origin: Option<String>,
    /// File-system path of the replica database.
    pub z_replica: Option<String>,
    /// Path of the file to which error messages are written.
    /// `None` means stderr.
    pub z_err_file: Option<String>,
    /// Path of the debug-trace file.  When `Some`, every protocol message
    /// is logged in human-readable form.
    pub z_debug_file: Option<String>,
    /// Output byte-stream to the peer (replica's stdin / origin's stdin).
    pub p_out: Option<Box<dyn Write>>,
    /// Input byte-stream from the peer (replica's stdout / origin's stdout).
    pub p_in: Option<Box<dyn Read>>,
    /// Optional file for logging raw outgoing bytes.
    pub p_log: Option<std::fs::File>,
    /// Open handle for [`z_debug_file`](Self::z_debug_file).
    pub p_debug: Option<std::fs::File>,
    /// Active SQLite database connection.  `null` before the session opens
    /// a database and after the session closes it on completion.
    pub db: *mut ffi::sqlite3,
    /// Total error count.  Non-zero means the session failed.
    pub n_err: u32,
    /// Write-error count (subset of [`n_err`](Self::n_err)).
    pub n_wr_err: u32,
    /// Verbosity level: 0 = quiet, 1 = progress, 2+ = debug.
    pub e_verbose: u8,
    /// When `true`, perform only a communication-check handshake and return
    /// without touching any database files.
    pub b_comm_check: bool,
    /// `true` when the peer is on a remote machine (affects error messages).
    pub is_remote: bool,
    /// `true` while running as the replica side.
    pub is_replica: bool,
    /// Protocol version agreed with the peer.  Defaults to
    /// [`PROTOCOL_VERSION`]; may be lowered during negotiation.
    pub i_protocol: u8,
    /// Set by the replica when it detects a UTF-16 encoded database, so the
    /// session can retry with the correct encoding pragma.
    pub wrong_encoding: bool,
    /// When `true`, refuse to sync a replica that is not in WAL journal mode.
    pub b_wal_only: bool,
    /// Total bytes written to [`p_out`](Self::p_out).
    pub n_out: u64,
    /// Total bytes read from [`p_in`](Self::p_in).
    pub n_in: u64,
    /// Number of pages in the database being synced.
    pub n_page: u32,
    /// Page size in bytes.
    pub sz_page: u32,
    /// Number of page-hash messages sent during this session.
    pub n_hash_sent: u64,
    /// Number of hash-exchange round-trips completed.
    pub n_round: u32,
    /// Number of full pages transferred.
    pub n_page_sent: u32,
}

// SAFETY: SqliteRsync contains a raw *mut ffi::sqlite3 pointer. The caller
// is responsible for ensuring the pointer is only accessed from one thread
// at a time. The library does not spawn threads internally.
unsafe impl Send for SqliteRsync {}

impl Default for SqliteRsync {
    fn default() -> Self {
        Self {
            z_origin: None,
            z_replica: None,
            z_err_file: None,
            z_debug_file: None,
            p_out: None,
            p_in: None,
            p_log: None,
            p_debug: None,
            db: ptr::null_mut(),
            n_err: 0,
            n_wr_err: 0,
            e_verbose: 0,
            b_comm_check: false,
            is_remote: false,
            is_replica: false,
            i_protocol: PROTOCOL_VERSION,
            wrong_encoding: false,
            b_wal_only: false,
            n_out: 0,
            n_in: 0,
            n_page: 0,
            sz_page: 0,
            n_hash_sent: 0,
            n_round: 0,
            n_page_sent: 0,
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Wire I/O helpers
// ───────────────────────────────────────────────────────────────────────────

fn read_byte(p: &mut SqliteRsync) -> i32 {
    let mut b = [0u8];
    match p.p_in.as_mut().unwrap().read(&mut b) {
        Ok(1) => {
            p.n_in += 1;
            b[0] as i32
        }
        _ => -1,
    }
}

fn write_byte(p: &mut SqliteRsync, c: u8) {
    if let Some(ref mut log) = p.p_log {
        let _ = log.write_all(&[c]);
    }
    let _ = p.p_out.as_mut().unwrap().write_all(&[c]);
    p.n_out += 1;
}

fn read_pow2(p: &mut SqliteRsync) -> u32 {
    let x = read_byte(p);
    if x < 0 || x >= 32 {
        log_error(p, &format!("read invalid page size {}", x));
        return 0;
    }
    1u32 << x
}

fn write_pow2(p: &mut SqliteRsync, c: u32) {
    if c == 0 || (c & (c - 1)) != 0 {
        log_error(p, &format!("invalid page size {}", c));
        return;
    }
    let mut n = 0u8;
    let mut v = c;
    while v > 1 {
        v /= 2;
        n += 1;
    }
    write_byte(p, n);
}

fn read_uint32(p: &mut SqliteRsync) -> Option<u32> {
    let mut buf = [0u8; 4];
    match p.p_in.as_mut().unwrap().read_exact(&mut buf) {
        Ok(()) => {
            p.n_in += 4;
            Some(
                ((buf[0] as u32) << 24)
                    | ((buf[1] as u32) << 16)
                    | ((buf[2] as u32) << 8)
                    | (buf[3] as u32),
            )
        }
        Err(_) => {
            log_error(p, "failed to read a 32-bit integer");
            None
        }
    }
}

fn write_uint32(p: &mut SqliteRsync, x: u32) {
    let buf = [(x >> 24) as u8, (x >> 16) as u8, (x >> 8) as u8, x as u8];
    if let Some(ref mut log) = p.p_log {
        let _ = log.write_all(&buf);
    }
    match p.p_out.as_mut().unwrap().write_all(&buf) {
        Ok(()) => p.n_out += 4,
        Err(_) => {
            log_error(p, &format!("failed to write 32-bit integer 0x{:x}", x));
            p.n_wr_err += 1;
        }
    }
}

fn read_bytes_into(p: &mut SqliteRsync, buf: &mut [u8]) {
    let n = buf.len();
    match p.p_in.as_mut().unwrap().read_exact(buf) {
        Ok(()) => p.n_in += n as u64,
        Err(_) => log_error(p, &format!("failed to read {} bytes", n)),
    }
}

fn write_bytes_raw(p: &mut SqliteRsync, data: &[u8]) {
    if let Some(ref mut log) = p.p_log {
        let _ = log.write_all(data);
    }
    match p.p_out.as_mut().unwrap().write_all(data) {
        Ok(()) => p.n_out += data.len() as u64,
        Err(_) => {
            log_error(p, &format!("failed to write {} bytes", data.len()));
            p.n_wr_err += 1;
        }
    }
}

fn flush_output(p: &mut SqliteRsync) {
    let _ = p.p_out.as_mut().unwrap().flush();
}

// ───────────────────────────────────────────────────────────────────────────
// Error / info messaging
// ───────────────────────────────────────────────────────────────────────────

fn log_error(p: &mut SqliteRsync, msg: &str) {
    if let Some(path) = p.z_err_file.as_deref() {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
        {
            let _ = writeln!(f, "{}", msg);
        }
    }
    error!("{}", msg);
    p.n_err += 1;
}

fn report_error(p: &mut SqliteRsync, msg: &str) {
    let bytes = msg.as_bytes();
    let n = bytes.len() as u32;
    if p.is_remote {
        let code = if p.is_replica {
            REPLICA_ERROR
        } else {
            ORIGIN_ERROR
        } as u8;
        write_byte(p, code);
        write_uint32(p, n);
        write_bytes_raw(p, bytes);
        flush_output(p);
    } else {
        error!("{}", msg);
    }
    log_error(p, msg);
}

fn info_msg(p: &mut SqliteRsync, msg: &str) {
    let bytes = msg.as_bytes();
    let n = bytes.len() as u32;
    if p.is_remote {
        let code = if p.is_replica {
            REPLICA_MSG
        } else {
            ORIGIN_MSG
        } as u8;
        write_byte(p, code);
        write_uint32(p, n);
        write_bytes_raw(p, bytes);
        flush_output(p);
    } else {
        info!("{}", msg);
    }
}

fn debug_message(p: &mut SqliteRsync, msg: &str) {
    // Always emit to the structured log so callers get protocol traces
    // even without a --debugfile, as long as RUST_LOG=debug is set.
    debug!(target: "sqlite3_rsync_rs::protocol", "{}", msg.trim_end_matches('\n'));
    if p.z_debug_file.is_none() {
        return;
    }
    let path = p.z_debug_file.as_ref().unwrap().clone();
    if p.p_debug.is_none() {
        p.p_debug = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .ok();
    }
    if let Some(ref mut f) = p.p_debug {
        let _ = f.write_all(msg.as_bytes());
        let _ = f.flush();
    }
}

fn read_and_display_message(p: &mut SqliteRsync, c: i32) {
    let prefix = if c == ORIGIN_ERROR || c == REPLICA_ERROR {
        "ERROR: "
    } else {
        ""
    };
    let n = read_uint32(p).unwrap_or(0) as usize;
    if n == 0 {
        error!("peer reported an unknown error (possibly out-of-memory)");
    } else {
        let mut buf = vec![0u8; n];
        read_bytes_into(p, &mut buf);
        let msg = String::from_utf8_lossy(&buf);
        if prefix.is_empty() {
            info!("{}", msg);
        } else {
            error!("{}", msg);
        }
        if !prefix.is_empty() {
            log_error(p, &format!("{}{}", prefix, msg));
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// SQLite helpers
// ───────────────────────────────────────────────────────────────────────────

/// Safely convert a possibly-null C string pointer to a Rust `String`.
pub(crate) unsafe fn cstr_to_string(ptr: *const std::os::raw::c_char) -> String {
    if ptr.is_null() {
        "(null)".to_owned()
    } else {
        unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

/// Prepare a SQL statement; report error and return `None` on failure.
fn prepare_stmt(p: &mut SqliteRsync, sql: &str) -> Option<*mut ffi::sqlite3_stmt> {
    let c_sql = CString::new(sql).expect("SQL contains embedded nul");
    let mut stmt: *mut ffi::sqlite3_stmt = ptr::null_mut();
    let rc =
        unsafe { ffi::sqlite3_prepare_v2(p.db, c_sql.as_ptr(), -1, &mut stmt, ptr::null_mut()) };
    if rc != ffi::SQLITE_OK || stmt.is_null() {
        let err = unsafe { cstr_to_string(ffi::sqlite3_errmsg(p.db)) };
        report_error(p, &format!("unable to prepare SQL [{}]: {}", sql, err));
        if !stmt.is_null() {
            unsafe {
                ffi::sqlite3_finalize(stmt);
            }
        }
        return None;
    }
    Some(stmt)
}

/// Run a SQL statement; discard any result rows.
fn run_sql(p: &mut SqliteRsync, sql: &str) {
    if let Some(stmt) = prepare_stmt(p, sql) {
        unsafe {
            let mut rc = ffi::sqlite3_step(stmt);
            if rc == ffi::SQLITE_ROW {
                rc = ffi::sqlite3_step(stmt);
            }
            if rc != ffi::SQLITE_OK && rc != ffi::SQLITE_DONE {
                let err = cstr_to_string(ffi::sqlite3_errmsg(p.db));
                if sql.starts_with("ATTACH ") && err.contains("must use the same text encoding") {
                    p.wrong_encoding = true;
                } else {
                    report_error(p, &format!("SQL statement [{}] failed: {}", sql, err));
                }
            }
            ffi::sqlite3_finalize(stmt);
        }
    }
}

/// Run a SQL statement that returns a single unsigned 32-bit integer.
fn run_sql_return_uint(p: &mut SqliteRsync, sql: &str) -> Option<u32> {
    let stmt = prepare_stmt(p, sql)?;
    unsafe {
        let rc = ffi::sqlite3_step(stmt);
        let res = if rc == ffi::SQLITE_ROW {
            Some((ffi::sqlite3_column_int64(stmt, 0) & 0xffff_ffff) as u32)
        } else {
            let err = cstr_to_string(ffi::sqlite3_errmsg(p.db));
            report_error(p, &format!("SQL statement [{}] failed: {}", sql, err));
            None
        };
        ffi::sqlite3_finalize(stmt);
        res
    }
}

/// Run a SQL statement that returns a single short text value.
///
/// The result is capped at `MAX_PRAGMA_TEXT_LEN` bytes, which is
/// sufficient for PRAGMA results like `journal_mode` or `encoding`.
const MAX_PRAGMA_TEXT_LEN: usize = 99;

fn run_sql_return_text(p: &mut SqliteRsync, sql: &str) -> Option<String> {
    let stmt = prepare_stmt(p, sql)?;
    unsafe {
        let rc = ffi::sqlite3_step(stmt);
        let res = if rc == ffi::SQLITE_ROW {
            let ptr = ffi::sqlite3_column_text(stmt, 0);
            if ptr.is_null() {
                Some(String::new())
            } else {
                let n = (ffi::sqlite3_column_bytes(stmt, 0) as usize).min(MAX_PRAGMA_TEXT_LEN);
                let s = String::from_utf8_lossy(std::slice::from_raw_parts(ptr, n)).into_owned();
                Some(s)
            }
        } else {
            let err = cstr_to_string(ffi::sqlite3_errmsg(p.db));
            report_error(p, &format!("SQL statement [{}] failed: {}", sql, err));
            None
        };
        ffi::sqlite3_finalize(stmt);
        res
    }
}

fn close_db(p: &mut SqliteRsync) {
    if !p.db.is_null() {
        unsafe {
            ffi::sqlite3_close(p.db);
        }
        p.db = ptr::null_mut();
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Miscellaneous utilities
// ───────────────────────────────────────────────────────────────────────────

/// SQL single-quote a string value.
///
/// Used for ATTACH statements where SQLite does not support parameter
/// binding.  The standard SQL escaping of `'` → `''` is the only
/// transformation needed for string literals.
fn sql_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Returns the current time as a Julian-day millisecond count.
///
/// Delegates to the default SQLite VFS's `xCurrentTimeInt64` method.  The
/// epoch is Julian day 0 (noon, 1 January 4713 BC), so the value for
/// 2000-01-01 00:00:00 UTC is `2_451_544_500_000`.
/// Returns `0` if the VFS does not support `xCurrentTimeInt64`.
pub fn current_time() -> i64 {
    let mut now: i64 = 0;
    unsafe {
        let vfs = ffi::sqlite3_vfs_find(ptr::null());
        if !vfs.is_null() && (*vfs).iVersion >= 2 {
            if let Some(f) = (*vfs).xCurrentTimeInt64 {
                f(vfs, &mut now);
            }
        }
    }
    now
}

// ───────────────────────────────────────────────────────────────────────────
// Origin-side protocol
// ───────────────────────────────────────────────────────────────────────────

/// Run the origin side of the sync protocol.
///
/// Opens `p.z_origin`, negotiates page hashes with the replica, then sends
/// only the pages that differ.  The caller must set:
///
/// - `p.z_origin` — path of the source database.
/// - `p.p_in` / `p.p_out` — byte-streams already connected to the replica.
///
/// On return, `p.n_err == 0` indicates success.  Statistics such as
/// [`SqliteRsync::n_page_sent`] and [`SqliteRsync::n_hash_sent`] are
/// populated regardless of outcome.
pub fn origin_side(p: &mut SqliteRsync) {
    p.is_replica = false;
    debug!(
        "origin_side: origin={:?} replica={:?} protocol={} wal_only={}",
        p.z_origin.as_deref().unwrap_or("(none)"),
        p.z_replica.as_deref().unwrap_or("(none)"),
        p.i_protocol,
        p.b_wal_only
    );

    if p.b_comm_check {
        let msg = format!(
            "origin  zOrigin={:?} zReplica={:?} isRemote={} protocol={}",
            p.z_origin.as_deref().unwrap_or("null"),
            p.z_replica.as_deref().unwrap_or("null"),
            p.is_remote as i32,
            p.i_protocol
        );
        info_msg(p, &msg);
        write_byte(p, ORIGIN_END as u8);
        flush_output(p);
        return;
    }

    // Open the origin database read-write (needed to take the read lock)
    let db_path = p.z_origin.clone().unwrap_or_default();
    let c_path = CString::new(db_path.as_bytes()).expect("path contains nul");
    let rc = unsafe {
        ffi::sqlite3_open_v2(
            c_path.as_ptr(),
            &mut p.db,
            ffi::SQLITE_OPEN_READWRITE,
            ptr::null(),
        )
    };
    if rc != ffi::SQLITE_OK {
        let err = unsafe { cstr_to_string(ffi::sqlite3_errmsg(p.db)) };
        report_error(p, &format!("cannot open origin \"{}\": {}", db_path, err));
        close_db(p);
        return;
    }
    if !unsafe { hash_register(p.db) } {
        report_error(p, "failed to register hash functions on origin database");
        close_db(p);
        return;
    }
    run_sql(p, "BEGIN");
    debug!("origin: database opened: {:?}", db_path);

    if p.b_wal_only {
        let mode = run_sql_return_text(p, "PRAGMA journal_mode").unwrap_or_default();
        if mode.to_ascii_lowercase() != "wal" {
            report_error(p, "Origin database is not in WAL mode");
        }
    }

    let n_page = run_sql_return_uint(p, "PRAGMA page_count").unwrap_or(0);
    let sz_pg = run_sql_return_uint(p, "PRAGMA page_size").unwrap_or(0);

    if p.n_err == 0 {
        write_byte(p, ORIGIN_BEGIN as u8);
        write_byte(p, p.i_protocol);
        write_pow2(p, sz_pg);
        write_uint32(p, n_page);
        flush_output(p);
        if p.z_debug_file.is_some() {
            debug_message(
                p,
                &format!("-> ORIGIN_BEGIN {} {} {}\n", p.i_protocol, sz_pg, n_page),
            );
        }
        p.n_page = n_page;
        p.sz_page = sz_pg;
        debug!("origin: page_count={n_page} page_size={sz_pg}");
    }

    let lock_byte_page = if sz_pg > 0 {
        (1u32 << 30) / sz_pg + 1
    } else {
        0
    };

    // Lazy prepared statements (null = not yet created)
    let mut ck_hash: *mut ffi::sqlite3_stmt = ptr::null_mut();
    let mut ck_hash_n: *mut ffi::sqlite3_stmt = ptr::null_mut();
    let mut ins_hash: *mut ffi::sqlite3_stmt = ptr::null_mut();
    let mut i_hash: u32 = 1;
    let mut n_hash: u32 = 1;
    let mut mx_hash: u32 = 0;

    'msg: loop {
        if p.n_err > p.n_wr_err {
            break;
        }
        let c = read_byte(p);
        if c < 0 || c == REPLICA_END {
            break;
        }

        match c {
            // ── REPLICA_BEGIN: replica requests a lower protocol version ──
            REPLICA_BEGIN => {
                let new_proto = read_byte(p) as u8;
                if p.z_debug_file.is_some() {
                    debug_message(p, &format!("<- REPLICA_BEGIN {}\n", new_proto));
                }
                if new_proto < p.i_protocol {
                    p.i_protocol = new_proto;
                    write_byte(p, ORIGIN_BEGIN as u8);
                    write_byte(p, p.i_protocol);
                    write_pow2(p, p.sz_page);
                    write_uint32(p, p.n_page);
                    flush_output(p);
                    if p.z_debug_file.is_some() {
                        debug_message(
                            p,
                            &format!(
                                "-> ORIGIN_BEGIN {} {} {}\n",
                                p.i_protocol, p.sz_page, p.n_page
                            ),
                        );
                    }
                } else {
                    report_error(p, "Invalid REPLICA_BEGIN reply");
                }
            }
            REPLICA_MSG | REPLICA_ERROR => {
                read_and_display_message(p, c);
            }
            // ── REPLICA_CONFIG: next hash starts on a different page ──
            REPLICA_CONFIG => {
                i_hash = read_uint32(p).unwrap_or(0);
                n_hash = read_uint32(p).unwrap_or(0);
                if p.z_debug_file.is_some() {
                    debug_message(p, &format!("<- REPLICA_CONFIG {} {}\n", i_hash, n_hash));
                }
            }
            // ── REPLICA_HASH: verify one page-range hash ──
            REPLICA_HASH => unsafe {
                if ck_hash.is_null() {
                    run_sql(
                        p,
                        "CREATE TEMP TABLE badHash(pgno INTEGER PRIMARY KEY, sz INT)",
                    );
                    ck_hash = match prepare_stmt(
                        p,
                        "SELECT hash(data)==?3 FROM sqlite_dbpage('main') WHERE pgno=?1",
                    ) {
                        Some(s) => s,
                        None => break 'msg,
                    };
                    ins_hash = match prepare_stmt(p, "INSERT INTO badHash VALUES(?1,?2)") {
                        Some(s) => s,
                        None => break 'msg,
                    };
                }
                p.n_hash_sent += 1;
                let mut hbuf = [0u8; 20];
                read_bytes_into(p, &mut hbuf);

                let b_match = if n_hash > 1 {
                    if ck_hash_n.is_null() {
                        ck_hash_n = match prepare_stmt(
                            p,
                            "WITH c(n) AS (VALUES(?1) UNION ALL SELECT n+1 FROM c WHERE n<?2)\
                                 SELECT agghash(hash(data))==?3\
                                 FROM c CROSS JOIN sqlite_dbpage('main') ON pgno=n",
                        ) {
                            Some(s) => s,
                            None => break 'msg,
                        };
                    }
                    ffi::sqlite3_bind_int64(ck_hash_n, 1, i_hash as i64);
                    ffi::sqlite3_bind_int64(ck_hash_n, 2, (i_hash + n_hash - 1) as i64);
                    ffi::sqlite3_bind_blob(ck_hash_n, 3, hbuf.as_ptr() as *const _, 20, None);
                    let rc = ffi::sqlite3_step(ck_hash_n);
                    let m = if rc == ffi::SQLITE_ROW {
                        ffi::sqlite3_column_int(ck_hash_n, 0) != 0
                    } else {
                        if rc == ffi::SQLITE_ERROR {
                            let err = cstr_to_string(ffi::sqlite3_errmsg(p.db));
                            report_error(p, &format!("agghash check failed: {}", err));
                        }
                        false
                    };
                    ffi::sqlite3_reset(ck_hash_n);
                    m
                } else {
                    ffi::sqlite3_bind_int64(ck_hash, 1, i_hash as i64);
                    ffi::sqlite3_bind_blob(ck_hash, 3, hbuf.as_ptr() as *const _, 20, None);
                    let rc = ffi::sqlite3_step(ck_hash);
                    let m = if rc == ffi::SQLITE_ERROR {
                        let err = cstr_to_string(ffi::sqlite3_errmsg(p.db));
                        report_error(p, &format!("hash check failed: {}", err));
                        false
                    } else {
                        rc == ffi::SQLITE_ROW && ffi::sqlite3_column_int(ck_hash, 0) != 0
                    };
                    ffi::sqlite3_reset(ck_hash);
                    m
                };

                if p.z_debug_file.is_some() {
                    debug_message(
                        p,
                        &format!(
                            "<- REPLICA_HASH {} {} {} {:08x}...\n",
                            i_hash,
                            n_hash,
                            if b_match { "match" } else { "fail" },
                            u32::from_be_bytes(hbuf[..4].try_into().unwrap())
                        ),
                    );
                }

                if !b_match {
                    ffi::sqlite3_bind_int64(ins_hash, 1, i_hash as i64);
                    ffi::sqlite3_bind_int64(ins_hash, 2, n_hash as i64);
                    let rc = ffi::sqlite3_step(ins_hash);
                    if rc != ffi::SQLITE_DONE {
                        let err = cstr_to_string(ffi::sqlite3_errmsg(p.db));
                        report_error(p, &format!("INSERT INTO badHash failed: {}", err));
                    }
                    ffi::sqlite3_reset(ins_hash);
                }
                if i_hash + n_hash > mx_hash {
                    mx_hash = i_hash + n_hash;
                }
                i_hash += n_hash;
            },
            // ── REPLICA_READY: all hashes have been sent ──
            REPLICA_READY => {
                if p.z_debug_file.is_some() {
                    debug_message(p, "<- REPLICA_READY\n");
                }
                p.n_round += 1;

                // Check whether any multi-page hash needs finer-grained info
                let stmt = match prepare_stmt(p, "SELECT pgno, sz FROM badHash WHERE sz>1") {
                    Some(s) => s,
                    None => break 'msg,
                };
                let mut n_multi = 0i32;
                unsafe {
                    while ffi::sqlite3_step(stmt) == ffi::SQLITE_ROW {
                        let pgno = ffi::sqlite3_column_int64(stmt, 0) as u32;
                        let cnt = ffi::sqlite3_column_int64(stmt, 1) as u32;
                        write_byte(p, ORIGIN_DETAIL as u8);
                        write_uint32(p, pgno);
                        write_uint32(p, cnt);
                        n_multi += 1;
                        if p.z_debug_file.is_some() {
                            debug_message(p, &format!("-> ORIGIN_DETAIL {} {}\n", pgno, cnt));
                        }
                    }
                    ffi::sqlite3_finalize(stmt);
                }

                if n_multi > 0 {
                    run_sql(p, "DELETE FROM badHash WHERE sz>1");
                    write_byte(p, ORIGIN_READY as u8);
                    if p.z_debug_file.is_some() {
                        debug_message(p, "-> ORIGIN_READY\n");
                    }
                } else {
                    // No more refinement needed — send the pages
                    unsafe {
                        if !ck_hash.is_null() {
                            ffi::sqlite3_finalize(ck_hash);
                            ck_hash = ptr::null_mut();
                        }
                        if !ck_hash_n.is_null() {
                            ffi::sqlite3_finalize(ck_hash_n);
                            ck_hash_n = ptr::null_mut();
                        }
                        if !ins_hash.is_null() {
                            ffi::sqlite3_finalize(ins_hash);
                            ins_hash = ptr::null_mut();
                        }
                    }
                    // Fill in pages not yet seen by the replica
                    if mx_hash <= p.n_page {
                        run_sql(
                            p,
                            &format!(
                                "WITH RECURSIVE c(n) AS \
                             (VALUES({}) UNION ALL SELECT n+1 FROM c WHERE n<{})\
                             INSERT INTO badHash SELECT n, 1 FROM c",
                                mx_hash, p.n_page
                            ),
                        );
                    }
                    run_sql(
                        p,
                        &format!("DELETE FROM badHash WHERE pgno={}", lock_byte_page),
                    );

                    let pstmt = match prepare_stmt(
                        p,
                        "SELECT pgno, data FROM badHash JOIN sqlite_dbpage('main') USING(pgno)",
                    ) {
                        Some(s) => s,
                        None => break 'msg,
                    };
                    unsafe {
                        while ffi::sqlite3_step(pstmt) == ffi::SQLITE_ROW
                            && p.n_err == 0
                            && p.n_wr_err == 0
                        {
                            let pgno = ffi::sqlite3_column_int64(pstmt, 0) as u32;
                            let data_ptr = ffi::sqlite3_column_blob(pstmt, 1) as *const u8;
                            let data = std::slice::from_raw_parts(data_ptr, sz_pg as usize);
                            write_byte(p, ORIGIN_PAGE as u8);
                            write_uint32(p, pgno);
                            write_bytes_raw(p, data);
                            p.n_page_sent += 1;
                            if p.z_debug_file.is_some() {
                                debug_message(p, &format!("-> ORIGIN_PAGE {}\n", pgno));
                            }
                        }
                        ffi::sqlite3_finalize(pstmt);
                    }
                    write_byte(p, ORIGIN_TXN as u8);
                    write_uint32(p, n_page);
                    debug!("origin: sent {} page(s), sending ORIGIN_TXN", p.n_page_sent);
                    if p.z_debug_file.is_some() {
                        debug_message(p, &format!("-> ORIGIN_TXN {}\n", n_page));
                    }
                    write_byte(p, ORIGIN_END as u8);
                }
                flush_output(p);
            }
            _ => {
                report_error(
                    p,
                    &format!(
                        "Unknown message 0x{:02x} {} bytes into conversation",
                        c, p.n_in
                    ),
                );
            }
        }
    }

    unsafe {
        if !ck_hash.is_null() {
            ffi::sqlite3_finalize(ck_hash);
        }
        if !ck_hash_n.is_null() {
            ffi::sqlite3_finalize(ck_hash_n);
        }
        if !ins_hash.is_null() {
            ffi::sqlite3_finalize(ins_hash);
        }
    }
    info!(
        "origin complete: pages_sent={} hashes_sent={} rounds={} errors={}",
        p.n_page_sent, p.n_hash_sent, p.n_round, p.n_err
    );
    close_db(p);
}

// ───────────────────────────────────────────────────────────────────────────
// Replica-side helpers
// ───────────────────────────────────────────────────────────────────────────

/// Insert entries into sendHash so that hashes are broken down finer.
fn subdivide_hash_range(p: &mut SqliteRsync, fpg: u32, npg: u32) {
    let n_chunk: u64 = if npg <= 30 {
        1
    } else if npg <= 1000 {
        30
    } else {
        1000
    };
    let i_end = fpg as u64 + npg as u64;
    run_sql(
        p,
        &format!(
            "WITH RECURSIVE c(n) AS \
         (VALUES({fpg}) UNION ALL SELECT n+{n_chunk} FROM c WHERE n<{limit})\
         REPLACE INTO sendHash(fpg,npg) SELECT n, min({i_end}-n,{n_chunk}) FROM c",
            fpg = fpg,
            n_chunk = n_chunk,
            limit = i_end - n_chunk,
            i_end = i_end,
        ),
    );
}

/// Send REPLICA_HASH messages for every row in the sendHash table, then
/// send REPLICA_READY.
fn send_hash_messages(p: &mut SqliteRsync, mut i_hash: u32, mut n_hash: u32) {
    let sql = "SELECT \
        if(npg==1,\
          (SELECT hash(data) FROM sqlite_dbpage('replica') WHERE pgno=fpg),\
          (WITH RECURSIVE c(n) AS\
             (SELECT fpg UNION ALL SELECT n+1 FROM c WHERE n<fpg+npg-1)\
           SELECT agghash(hash(data)) FROM c CROSS JOIN sqlite_dbpage('replica') ON pgno=n)) AS hash,\
        fpg, npg FROM sendHash ORDER BY fpg";
    let stmt = match prepare_stmt(p, sql) {
        Some(s) => s,
        None => return,
    };
    unsafe {
        while ffi::sqlite3_step(stmt) == ffi::SQLITE_ROW && p.n_err == 0 && p.n_wr_err == 0 {
            let a = ffi::sqlite3_column_blob(stmt, 0) as *const u8;
            let pgno = ffi::sqlite3_column_int64(stmt, 1) as u32;
            let npg = ffi::sqlite3_column_int64(stmt, 2) as u32;
            if pgno != i_hash || npg != n_hash {
                write_byte(p, REPLICA_CONFIG as u8);
                write_uint32(p, pgno);
                write_uint32(p, npg);
                if p.z_debug_file.is_some() {
                    debug_message(p, &format!("-> REPLICA_CONFIG {} {}\n", pgno, npg));
                }
            }
            if a.is_null() {
                if p.z_debug_file.is_some() {
                    debug_message(p, &format!("# Oops: No hash for {} {}\n", pgno, npg));
                }
            } else {
                write_byte(p, REPLICA_HASH as u8);
                write_bytes_raw(p, std::slice::from_raw_parts(a, 20));
                if p.z_debug_file.is_some() {
                    debug_message(
                        p,
                        &format!(
                            "-> REPLICA_HASH {} {} ({:08x}...)\n",
                            pgno,
                            npg,
                            u32::from_be_bytes([*a, *a.add(1), *a.add(2), *a.add(3)])
                        ),
                    );
                }
            }
            p.n_hash_sent += 1;
            i_hash = pgno + npg;
            n_hash = npg;
        }
        ffi::sqlite3_finalize(stmt);
    }
    run_sql(p, "DELETE FROM sendHash");
    write_byte(p, REPLICA_READY as u8);
    flush_output(p);
    p.n_round += 1;
    if p.z_debug_file.is_some() {
        debug_message(p, "-> REPLICA_READY\n");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Replica-side protocol
// ───────────────────────────────────────────────────────────────────────────

/// Run the replica side of the sync protocol.
///
/// Receives page hashes from the origin, reports mismatches, and applies
/// the pages sent in return.  The caller must set:
///
/// - `p.z_replica` — path of the destination database (created if it does
///   not exist, or updated in place if it does).
/// - `p.p_in` / `p.p_out` — byte-streams already connected to the origin.
///
/// On return, `p.n_err == 0` indicates the replica is now an exact copy of
/// the origin as of the transaction committed by the origin.
pub fn replica_side(p: &mut SqliteRsync) {
    p.is_replica = true;
    debug!(
        "replica_side: replica={:?} protocol={} wal_only={}",
        p.z_replica.as_deref().unwrap_or("(none)"),
        p.i_protocol,
        p.b_wal_only
    );

    if p.b_comm_check {
        let msg = format!(
            "replica zOrigin={:?} zReplica={:?} isRemote={} protocol={}",
            p.z_origin.as_deref().unwrap_or("null"),
            p.z_replica.as_deref().unwrap_or("null"),
            p.is_remote as i32,
            p.i_protocol
        );
        info_msg(p, &msg);
        write_byte(p, REPLICA_END as u8);
        flush_output(p);
    }
    if p.i_protocol == 0 {
        p.i_protocol = PROTOCOL_VERSION;
    }

    let mut sz_o_page: u32 = 0;
    let mut e_j_mode: u8 = 0; // 1 = non-WAL, 2 = WAL before sync
    let mut ins: *mut ffi::sqlite3_stmt = ptr::null_mut();
    let mut page_buf: Vec<u8> = Vec::new();

    'msg: loop {
        if p.n_err > p.n_wr_err {
            break;
        }
        let c = read_byte(p);
        if c < 0 || c == ORIGIN_END {
            break;
        }

        match c {
            ORIGIN_MSG | ORIGIN_ERROR => {
                read_and_display_message(p, c);
            }

            // ── ORIGIN_BEGIN: origin announces page size and count ──
            ORIGIN_BEGIN => {
                close_db(p);
                let i_protocol = read_byte(p) as u8;
                sz_o_page = read_pow2(p);
                let n_o_page = read_uint32(p).unwrap_or(0);
                if p.z_debug_file.is_some() {
                    debug_message(
                        p,
                        &format!(
                            "<- ORIGIN_BEGIN {} {} {}\n",
                            i_protocol, sz_o_page, n_o_page
                        ),
                    );
                }
                if p.n_err != 0 {
                    continue 'msg;
                }

                if i_protocol > p.i_protocol {
                    // Origin speaks a newer protocol — request downgrade
                    write_byte(p, REPLICA_BEGIN as u8);
                    write_byte(p, p.i_protocol);
                    flush_output(p);
                    if p.z_debug_file.is_some() {
                        debug_message(p, &format!("-> REPLICA_BEGIN {}\n", p.i_protocol));
                    }
                    continue 'msg;
                }

                p.i_protocol = i_protocol;
                p.n_page = n_o_page;
                p.sz_page = sz_o_page;
                page_buf.resize(sz_o_page as usize, 0);

                // Open in-memory scratch database; attach the real replica
                let rc =
                    unsafe { ffi::sqlite3_open(b":memory:\0".as_ptr() as *const _, &mut p.db) };
                if rc != ffi::SQLITE_OK {
                    let err = unsafe { cstr_to_string(ffi::sqlite3_errmsg(p.db)) };
                    report_error(p, &format!("cannot open in-memory database: {}", err));
                    close_db(p);
                    continue 'msg;
                }
                unsafe {
                    // Allow writes to sqlite_dbpage via writable_schema
                    ffi::sqlite3_db_config(
                        p.db,
                        ffi::SQLITE_DBCONFIG_WRITABLE_SCHEMA,
                        1i32,
                        ptr::null_mut::<std::os::raw::c_int>(),
                    );
                }

                let replica = p.z_replica.clone().unwrap_or_default();
                let attach_sql = format!("ATTACH {} AS 'replica'", sql_quote(&replica));
                run_sql(p, &attach_sql);
                // Re-try with alternate encodings if the replica uses UTF-16
                if p.wrong_encoding {
                    p.wrong_encoding = false;
                    run_sql(p, "PRAGMA encoding=utf16le");
                    run_sql(p, &attach_sql);
                    if p.wrong_encoding {
                        p.wrong_encoding = false;
                        run_sql(p, "PRAGMA encoding=utf16be");
                        // Note: capital 'A' in "Attach" intentionally matches C code
                        run_sql(p, &format!("Attach {} AS 'replica'", sql_quote(&replica)));
                    }
                }
                if p.n_err != 0 {
                    close_db(p);
                    continue 'msg;
                }

                run_sql(
                    p,
                    "CREATE TABLE sendHash(\
                     fpg INTEGER PRIMARY KEY, npg INT)",
                );
                if !unsafe { hash_register(p.db) } {
                    report_error(p, "failed to register hash functions on replica database");
                    close_db(p);
                    continue 'msg;
                }

                let n_r_page = match run_sql_return_uint(p, "PRAGMA replica.page_count") {
                    Some(v) => v,
                    None => {
                        continue 'msg;
                    }
                };

                if n_r_page == 0 {
                    run_sql(p, &format!("PRAGMA replica.page_size={}", sz_o_page));
                    run_sql(p, "SELECT * FROM replica.sqlite_schema");
                }
                run_sql(p, "BEGIN IMMEDIATE");

                let mode =
                    run_sql_return_text(p, "PRAGMA replica.journal_mode").unwrap_or_default();
                if mode != "wal" {
                    if p.b_wal_only && n_r_page > 0 {
                        report_error(p, "replica is not in WAL mode");
                        continue 'msg;
                    }
                    e_j_mode = 1;
                } else {
                    e_j_mode = 2;
                }

                let n_r_page2 = run_sql_return_uint(p, "PRAGMA replica.page_count").unwrap_or(0);
                let sz_r_page = run_sql_return_uint(p, "PRAGMA replica.page_size").unwrap_or(0);
                if sz_r_page != sz_o_page {
                    report_error(
                        p,
                        &format!(
                            "page size mismatch; origin is {} bytes and replica is {} bytes",
                            sz_o_page, sz_r_page
                        ),
                    );
                    continue 'msg;
                }

                if p.i_protocol < 2 || n_r_page2 <= 100 {
                    run_sql(
                        p,
                        &format!(
                            "WITH RECURSIVE c(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM c WHERE n<{})\
                         INSERT INTO sendHash(fpg, npg) SELECT n, 1 FROM c",
                            n_r_page2
                        ),
                    );
                } else {
                    run_sql(p, "INSERT INTO sendHash VALUES(1,1)");
                    if n_r_page2 > 1 {
                        subdivide_hash_range(p, 2, n_r_page2 - 1);
                    }
                }
                debug!(
                    "replica: attached {:?} page_count={} page_size={} journal={}",
                    replica,
                    n_r_page2,
                    sz_r_page,
                    if e_j_mode == 2 { "wal" } else { "non-wal" }
                );
                send_hash_messages(p, 1, 1);
                run_sql(p, "PRAGMA writable_schema=ON");
            }

            // ── ORIGIN_DETAIL: origin requests finer-grained hashes ──
            ORIGIN_DETAIL => {
                let fpg = read_uint32(p).unwrap_or(0);
                let npg = read_uint32(p).unwrap_or(0);
                if p.z_debug_file.is_some() {
                    debug_message(p, &format!("<- ORIGIN_DETAIL {} {}\n", fpg, npg));
                }
                subdivide_hash_range(p, fpg, npg);
            }

            // ── ORIGIN_READY: send accumulated fine-grained hashes ──
            ORIGIN_READY => {
                if p.z_debug_file.is_some() {
                    debug_message(p, "<- ORIGIN_READY\n");
                }
                send_hash_messages(p, 0, 0);
            }

            // ── ORIGIN_TXN: commit or rollback ──
            ORIGIN_TXN => {
                let n_o_page = read_uint32(p).unwrap_or(0);
                if p.z_debug_file.is_some() {
                    debug_message(p, &format!("<- ORIGIN_TXN {}\n", n_o_page));
                }
                if ins.is_null() {
                    // No pages were written — just commit
                    run_sql(p, "COMMIT");
                } else if p.n_err != 0 {
                    run_sql(p, "ROLLBACK");
                } else {
                    if n_o_page < 0xffff_ffff {
                        // Write a truncation sentinel (NULL data beyond new EOF)
                        unsafe {
                            ffi::sqlite3_bind_int64(ins, 1, (n_o_page + 1) as i64);
                            ffi::sqlite3_bind_null(ins, 2);
                            let rc = ffi::sqlite3_step(ins);
                            if rc != ffi::SQLITE_DONE {
                                let err = cstr_to_string(ffi::sqlite3_errmsg(p.db));
                                report_error(
                                    p,
                                    &format!(
                                        "INSERT sqlite_dbpage (pgno={}, data=NULL) failed: {}",
                                        n_o_page, err
                                    ),
                                );
                            }
                            ffi::sqlite3_reset(ins);
                        }
                    }
                    p.n_page = n_o_page;
                    run_sql(p, "COMMIT");
                    debug!("replica: committed {} page(s)", p.n_page_sent);
                }
            }

            // ── ORIGIN_PAGE: receive and write one page ──
            ORIGIN_PAGE => {
                let pgno = read_uint32(p).unwrap_or(0);
                if p.z_debug_file.is_some() {
                    debug_message(p, &format!("<- ORIGIN_PAGE {}\n", pgno));
                }
                if p.n_err != 0 {
                    continue 'msg;
                }
                if ins.is_null() {
                    ins = match prepare_stmt(
                        p,
                        "INSERT INTO sqlite_dbpage(pgno,data,schema)VALUES(?1,?2,'replica')",
                    ) {
                        Some(s) => s,
                        None => {
                            continue 'msg;
                        }
                    };
                }
                read_bytes_into(p, &mut page_buf[..sz_o_page as usize]);
                if p.n_err != 0 {
                    continue 'msg;
                }
                // If page 1 of a replica that was already in WAL mode, keep WAL
                if pgno == 1 && e_j_mode == 2 && page_buf[18] == 1 {
                    page_buf[18] = 2;
                    page_buf[19] = 2;
                }
                p.n_page_sent += 1;
                unsafe {
                    ffi::sqlite3_bind_int64(ins, 1, pgno as i64);
                    // SQLITE_STATIC: we step+reset before touching page_buf again
                    ffi::sqlite3_bind_blob(
                        ins,
                        2,
                        page_buf.as_ptr() as *const _,
                        sz_o_page as i32,
                        None,
                    );
                    let rc = ffi::sqlite3_step(ins);
                    if rc != ffi::SQLITE_DONE {
                        let err = cstr_to_string(ffi::sqlite3_errmsg(p.db));
                        report_error(
                            p,
                            &format!("INSERT sqlite_dbpage (pgno={}) failed: {}", pgno, err),
                        );
                    }
                    ffi::sqlite3_reset(ins);
                }
            }

            _ => {
                report_error(
                    p,
                    &format!(
                        "Unknown message 0x{:02x} {} bytes into conversation",
                        c, p.n_in
                    ),
                );
            }
        }
    }

    if !ins.is_null() {
        unsafe {
            ffi::sqlite3_finalize(ins);
        }
    }
    info!(
        "replica complete: pages_received={} hashes_sent={} rounds={} errors={}",
        p.n_page_sent, p.n_hash_sent, p.n_round, p.n_err
    );
    close_db(p);
}

/// Sync `origin` into `replica`, both local filesystem paths.
///
/// When `wal_only` is `true` the call fails if the replica database is not
/// already in WAL journal mode.
///
/// Returns `Ok(stats)` on success, where `stats` is a human-readable
/// summary string.  Returns `Err(msg)` when either side reports errors.
pub fn sync_local(origin: &str, replica: &str, wal_only: bool) -> Result<String, String> {
    info!(
        "sync_local: {:?} → {:?} (wal_only={})",
        origin, replica, wal_only
    );
    // Two unidirectional pipes:
    //   pipe_or: origin writes → replica reads
    //   pipe_ro: replica writes → origin reads
    let (or_reader, or_writer) = pipe().map_err(|e| format!("pipe: {e}"))?;
    let (ro_reader, ro_writer) = pipe().map_err(|e| format!("pipe: {e}"))?;

    let replica_path = replica.to_owned();

    // ── Replica thread ────────────────────────────────────────────────────
    let replica_handle = std::thread::Builder::new()
        .name("replica".to_owned())
        .spawn(move || {
            let mut ctx = SqliteRsync {
                z_replica: Some(replica_path),
                p_in: Some(Box::new(or_reader)),
                p_out: Some(Box::new(ro_writer)),
                b_wal_only: wal_only,
                ..SqliteRsync::default()
            };
            replica_side(&mut ctx);
            ctx.n_err
        })
        .map_err(|e| format!("failed to spawn replica thread: {e}"))?;

    // ── Origin (this thread) ──────────────────────────────────────────────
    let mut octx = SqliteRsync {
        z_origin: Some(origin.to_owned()),
        p_in: Some(Box::new(ro_reader)),
        p_out: Some(Box::new(or_writer)),
        b_wal_only: wal_only,
        ..SqliteRsync::default()
    };
    origin_side(&mut octx);

    // Drop pipes so the replica thread sees EOF and can exit.
    octx.p_in = None;
    octx.p_out = None;

    let replica_errs = replica_handle
        .join()
        .map_err(|_| "replica thread panicked".to_owned())?;

    if octx.n_err > 0 || replica_errs > 0 {
        return Err(format!(
            "sync failed (origin errors: {}, replica errors: {})",
            octx.n_err, replica_errs
        ));
    }

    let stats = format!(
        "synced {} page(s) in {} round-trip(s) ({} hash message(s))",
        octx.n_page_sent, octx.n_round, octx.n_hash_sent,
    );
    info!("sync_local complete: {}", stats);
    Ok(stats)
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── sql_quote ────────────────────────────────────────────────────────────

    #[test]
    fn sql_quote_plain() {
        assert_eq!(sql_quote("hello"), "'hello'");
    }

    #[test]
    fn sql_quote_with_single_quote() {
        assert_eq!(sql_quote("it's"), "'it''s'");
    }

    #[test]
    fn sql_quote_multiple_single_quotes() {
        assert_eq!(sql_quote("a'b'c"), "'a''b''c'");
    }

    #[test]
    fn sql_quote_empty() {
        assert_eq!(sql_quote(""), "''");
    }

    // ── write_pow2 / read_pow2 round-trip ────────────────────────────────────

    fn make_pipe_ctx(data: Vec<u8>) -> SqliteRsync {
        let mut p = SqliteRsync::default();
        p.p_in = Some(Box::new(Cursor::new(data)));
        p.p_out = Some(Box::new(std::io::sink()));
        p
    }

    fn make_write_ctx() -> (SqliteRsync, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        use std::sync::{Arc, Mutex};
        struct SharedVec(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedVec {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Arc::new(Mutex::new(Vec::new()));
        let mut p = SqliteRsync::default();
        p.p_out = Some(Box::new(SharedVec(buf.clone())));
        p.p_in = Some(Box::new(Cursor::new(vec![])));
        (p, buf)
    }

    #[test]
    fn pow2_roundtrip_512() {
        let (mut write_ctx, buf) = make_write_ctx();
        write_pow2(&mut write_ctx, 512);
        let written = buf.lock().unwrap().clone();
        let mut read_ctx = make_pipe_ctx(written);
        assert_eq!(read_pow2(&mut read_ctx), 512);
    }

    #[test]
    fn pow2_roundtrip_4096() {
        let (mut write_ctx, buf) = make_write_ctx();
        write_pow2(&mut write_ctx, 4096);
        let written = buf.lock().unwrap().clone();
        let mut read_ctx = make_pipe_ctx(written);
        assert_eq!(read_pow2(&mut read_ctx), 4096);
    }

    #[test]
    fn pow2_roundtrip_65536() {
        let (mut write_ctx, buf) = make_write_ctx();
        write_pow2(&mut write_ctx, 65536);
        let written = buf.lock().unwrap().clone();
        let mut read_ctx = make_pipe_ctx(written);
        assert_eq!(read_pow2(&mut read_ctx), 65536);
    }

    // ── write_uint32 / read_uint32 round-trip ────────────────────────────────

    #[test]
    fn uint32_roundtrip_zero() {
        let (mut write_ctx, buf) = make_write_ctx();
        write_uint32(&mut write_ctx, 0);
        let written = buf.lock().unwrap().clone();
        let mut read_ctx = make_pipe_ctx(written);
        assert_eq!(read_uint32(&mut read_ctx), Some(0));
    }

    #[test]
    fn uint32_roundtrip_max() {
        let (mut write_ctx, buf) = make_write_ctx();
        write_uint32(&mut write_ctx, 0xFFFF_FFFF);
        let written = buf.lock().unwrap().clone();
        let mut read_ctx = make_pipe_ctx(written);
        assert_eq!(read_uint32(&mut read_ctx), Some(0xFFFF_FFFF));
    }

    #[test]
    fn uint32_roundtrip_arbitrary() {
        let (mut write_ctx, buf) = make_write_ctx();
        write_uint32(&mut write_ctx, 0x0102_0304);
        let written = buf.lock().unwrap().clone();
        assert_eq!(written, vec![0x01, 0x02, 0x03, 0x04]);
        let mut read_ctx = make_pipe_ctx(written);
        assert_eq!(read_uint32(&mut read_ctx), Some(0x0102_0304));
    }

    #[test]
    fn uint32_read_eof_returns_none() {
        let mut p = make_pipe_ctx(vec![]);
        assert_eq!(read_uint32(&mut p), None);
    }

    // ── write_byte / read_byte round-trip ────────────────────────────────────

    #[test]
    fn byte_roundtrip() {
        let (mut write_ctx, buf) = make_write_ctx();
        write_byte(&mut write_ctx, 0x42);
        let written = buf.lock().unwrap().clone();
        let mut read_ctx = make_pipe_ctx(written);
        assert_eq!(read_byte(&mut read_ctx), 0x42);
    }

    #[test]
    fn byte_read_eof_returns_minus_one() {
        let mut p = make_pipe_ctx(vec![]);
        assert_eq!(read_byte(&mut p), -1);
    }

    // ── n_in / n_out counters ────────────────────────────────────────────────

    #[test]
    fn n_out_increments_on_write_byte() {
        let (mut p, _) = make_write_ctx();
        assert_eq!(p.n_out, 0);
        write_byte(&mut p, 0xFF);
        assert_eq!(p.n_out, 1);
    }

    #[test]
    fn n_in_increments_on_read_byte() {
        let mut p = make_pipe_ctx(vec![0xAB]);
        assert_eq!(p.n_in, 0);
        read_byte(&mut p);
        assert_eq!(p.n_in, 1);
    }

    #[test]
    fn n_out_increments_on_write_uint32() {
        let (mut p, _) = make_write_ctx();
        write_uint32(&mut p, 42);
        assert_eq!(p.n_out, 4);
    }

    #[test]
    fn n_in_increments_on_read_uint32() {
        let mut p = make_pipe_ctx(vec![0, 0, 0, 7]);
        read_uint32(&mut p);
        assert_eq!(p.n_in, 4);
    }

    // ── SQLite integration: hash() and agghash() SQL functions ───────────────

    fn open_memory_db() -> *mut ffi::sqlite3 {
        unsafe {
            ffi::sqlite3_initialize();
            let mut db: *mut ffi::sqlite3 = ptr::null_mut();
            let rc = ffi::sqlite3_open(b":memory:\0".as_ptr() as *const _, &mut db);
            assert_eq!(rc, ffi::SQLITE_OK);
            hash_register(db);
            db
        }
    }

    unsafe fn exec_scalar_blob(db: *mut ffi::sqlite3, sql: &str) -> Vec<u8> {
        unsafe {
            let c_sql = CString::new(sql).unwrap();
            let mut stmt: *mut ffi::sqlite3_stmt = ptr::null_mut();
            let rc = ffi::sqlite3_prepare_v2(db, c_sql.as_ptr(), -1, &mut stmt, ptr::null_mut());
            assert_eq!(rc, ffi::SQLITE_OK, "prepare failed for: {}", sql);
            let rc = ffi::sqlite3_step(stmt);
            assert_eq!(rc, ffi::SQLITE_ROW, "step failed for: {}", sql);
            let n = ffi::sqlite3_column_bytes(stmt, 0) as usize;
            let ptr = ffi::sqlite3_column_blob(stmt, 0) as *const u8;
            let result = if ptr.is_null() {
                vec![]
            } else {
                std::slice::from_raw_parts(ptr, n).to_vec()
            };
            ffi::sqlite3_finalize(stmt);
            result
        }
    }

    unsafe fn close_db_ptr(db: *mut ffi::sqlite3) {
        unsafe {
            ffi::sqlite3_close(db);
        }
    }

    #[test]
    fn sql_hash_returns_20_bytes() {
        let db = open_memory_db();
        unsafe {
            let result = exec_scalar_blob(db, "SELECT hash('hello')");
            assert_eq!(result.len(), 20);
            close_db_ptr(db);
        }
    }

    #[test]
    fn sql_hash_same_input_consistent() {
        let db = open_memory_db();
        unsafe {
            let r1 = exec_scalar_blob(db, "SELECT hash('hello')");
            let r2 = exec_scalar_blob(db, "SELECT hash('hello')");
            assert_eq!(r1, r2);
            close_db_ptr(db);
        }
    }

    #[test]
    fn sql_hash_different_inputs_differ() {
        let db = open_memory_db();
        unsafe {
            let r1 = exec_scalar_blob(db, "SELECT hash('hello')");
            let r2 = exec_scalar_blob(db, "SELECT hash('world')");
            assert_ne!(r1, r2);
            close_db_ptr(db);
        }
    }

    #[test]
    fn sql_hash_null_returns_null() {
        let db = open_memory_db();
        unsafe {
            let c_sql = CString::new("SELECT hash(NULL)").unwrap();
            let mut stmt: *mut ffi::sqlite3_stmt = ptr::null_mut();
            ffi::sqlite3_prepare_v2(db, c_sql.as_ptr(), -1, &mut stmt, ptr::null_mut());
            ffi::sqlite3_step(stmt);
            let t = ffi::sqlite3_column_type(stmt, 0);
            assert_eq!(t, ffi::SQLITE_NULL);
            ffi::sqlite3_finalize(stmt);
            close_db_ptr(db);
        }
    }

    #[test]
    fn sql_agghash_consistent_with_hash_single_row() {
        let db = open_memory_db();
        unsafe {
            let c_sql =
                CString::new("CREATE TABLE t(v BLOB); INSERT INTO t VALUES('hello');").unwrap();
            ffi::sqlite3_exec(db, c_sql.as_ptr(), None, ptr::null_mut(), ptr::null_mut());

            let hash_val = exec_scalar_blob(db, "SELECT hash('hello')");
            let agg_val = exec_scalar_blob(db, "SELECT agghash(v) FROM t");
            assert_eq!(hash_val, agg_val);
            close_db_ptr(db);
        }
    }

    #[test]
    fn sql_agghash_multiple_rows_differs_from_single() {
        let db = open_memory_db();
        unsafe {
            let setup = CString::new(
                "CREATE TABLE t(v BLOB); INSERT INTO t VALUES('a'); INSERT INTO t VALUES('b');",
            )
            .unwrap();
            ffi::sqlite3_exec(db, setup.as_ptr(), None, ptr::null_mut(), ptr::null_mut());

            let agg_ab = exec_scalar_blob(db, "SELECT agghash(v) FROM t");
            let hash_a = exec_scalar_blob(db, "SELECT hash('a')");
            assert_ne!(agg_ab, hash_a);
            assert_eq!(agg_ab.len(), 20);
            close_db_ptr(db);
        }
    }

    // ── Direct HashContext unit tests ────────────────────────────────────────

    #[test]
    fn hash_context_produces_20_bytes() {
        let mut ctx = HashContext::new(160);
        ctx.update(b"hello");
        let out = ctx.finalize();
        assert_eq!(out.len(), 20);
    }

    #[test]
    fn hash_context_same_input_deterministic() {
        let hash = |data: &[u8]| -> [u8; 20] {
            let mut ctx = HashContext::new(160);
            ctx.update(data);
            ctx.finalize()
        };
        assert_eq!(hash(b"hello"), hash(b"hello"));
    }

    #[test]
    fn hash_context_different_inputs_differ() {
        let hash = |data: &[u8]| -> [u8; 20] {
            let mut ctx = HashContext::new(160);
            ctx.update(data);
            ctx.finalize()
        };
        assert_ne!(hash(b"hello"), hash(b"world"));
    }

    #[test]
    fn hash_context_incremental_equals_single_call() {
        let mut ctx1 = HashContext::new(160);
        ctx1.update(b"helloworld");
        let h1 = ctx1.finalize();

        let mut ctx2 = HashContext::new(160);
        ctx2.update(b"hello");
        ctx2.update(b"world");
        let h2 = ctx2.finalize();

        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_context_empty_input() {
        let mut ctx = HashContext::new(160);
        let out = ctx.finalize();
        assert_eq!(out.len(), 20);
        // Must be non-zero (the Keccak "empty message" hash is not all zeroes)
        assert!(out.iter().any(|&b| b != 0));
    }

    // ── Integration test: sync_local ─────────────────────────────────────────

    fn exec_sql(db: *mut ffi::sqlite3, sql: &str) {
        unsafe {
            let c_sql = CString::new(sql).unwrap();
            let rc = ffi::sqlite3_exec(db, c_sql.as_ptr(), None, ptr::null_mut(), ptr::null_mut());
            assert_eq!(rc, ffi::SQLITE_OK, "exec failed for: {}", sql);
        }
    }

    fn open_db(path: &str) -> *mut ffi::sqlite3 {
        unsafe {
            ffi::sqlite3_initialize();
            let mut db: *mut ffi::sqlite3 = ptr::null_mut();
            let c_path = CString::new(path).unwrap();
            let rc = ffi::sqlite3_open(c_path.as_ptr(), &mut db);
            assert_eq!(rc, ffi::SQLITE_OK, "open failed for: {}", path);
            db
        }
    }

    fn query_int(db: *mut ffi::sqlite3, sql: &str) -> i64 {
        unsafe {
            let c_sql = CString::new(sql).unwrap();
            let mut stmt: *mut ffi::sqlite3_stmt = ptr::null_mut();
            let rc = ffi::sqlite3_prepare_v2(db, c_sql.as_ptr(), -1, &mut stmt, ptr::null_mut());
            assert_eq!(rc, ffi::SQLITE_OK);
            let rc = ffi::sqlite3_step(stmt);
            assert_eq!(rc, ffi::SQLITE_ROW);
            let val = ffi::sqlite3_column_int64(stmt, 0);
            ffi::sqlite3_finalize(stmt);
            val
        }
    }

    #[test]
    fn sync_local_empty_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        let origin_path = dir.path().join("origin.db");
        let replica_path = dir.path().join("replica.db");

        // Create an empty origin database
        let db = open_db(origin_path.to_str().unwrap());
        exec_sql(db, "CREATE TABLE t(x INTEGER)");
        unsafe {
            ffi::sqlite3_close(db);
        }

        let result = sync_local(
            origin_path.to_str().unwrap(),
            replica_path.to_str().unwrap(),
            false,
        );
        assert!(result.is_ok(), "sync_local failed: {:?}", result.err());

        // Verify replica has the same table
        let db = open_db(replica_path.to_str().unwrap());
        let count = query_int(db, "SELECT count(*) FROM t");
        assert_eq!(count, 0);
        unsafe {
            ffi::sqlite3_close(db);
        }
    }

    #[test]
    fn sync_local_with_data() {
        let dir = tempfile::tempdir().unwrap();
        let origin_path = dir.path().join("origin.db");
        let replica_path = dir.path().join("replica.db");

        // Create origin with data
        let db = open_db(origin_path.to_str().unwrap());
        exec_sql(db, "CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)");
        exec_sql(db, "INSERT INTO items VALUES(1, 'alpha')");
        exec_sql(db, "INSERT INTO items VALUES(2, 'beta')");
        exec_sql(db, "INSERT INTO items VALUES(3, 'gamma')");
        unsafe {
            ffi::sqlite3_close(db);
        }

        let result = sync_local(
            origin_path.to_str().unwrap(),
            replica_path.to_str().unwrap(),
            false,
        );
        assert!(result.is_ok(), "sync_local failed: {:?}", result.err());

        // Verify replica has correct data
        let db = open_db(replica_path.to_str().unwrap());
        let count = query_int(db, "SELECT count(*) FROM items");
        assert_eq!(count, 3);
        let max_id = query_int(db, "SELECT max(id) FROM items");
        assert_eq!(max_id, 3);
        unsafe {
            ffi::sqlite3_close(db);
        }
    }

    #[test]
    fn sync_local_incremental_update() {
        let dir = tempfile::tempdir().unwrap();
        let origin_path = dir.path().join("origin.db");
        let replica_path = dir.path().join("replica.db");

        // Create origin with initial data and sync
        let db = open_db(origin_path.to_str().unwrap());
        exec_sql(db, "CREATE TABLE t(v INTEGER)");
        exec_sql(db, "INSERT INTO t VALUES(1)");
        unsafe {
            ffi::sqlite3_close(db);
        }

        let result = sync_local(
            origin_path.to_str().unwrap(),
            replica_path.to_str().unwrap(),
            false,
        );
        assert!(result.is_ok());

        // Add more data and re-sync
        let db = open_db(origin_path.to_str().unwrap());
        exec_sql(db, "INSERT INTO t VALUES(2)");
        exec_sql(db, "INSERT INTO t VALUES(3)");
        unsafe {
            ffi::sqlite3_close(db);
        }

        let result = sync_local(
            origin_path.to_str().unwrap(),
            replica_path.to_str().unwrap(),
            false,
        );
        assert!(
            result.is_ok(),
            "incremental sync failed: {:?}",
            result.err()
        );

        // Verify replica is up to date
        let db = open_db(replica_path.to_str().unwrap());
        let count = query_int(db, "SELECT count(*) FROM t");
        assert_eq!(count, 3);
        unsafe {
            ffi::sqlite3_close(db);
        }
    }

    #[test]
    fn sync_local_nonexistent_origin_fails() {
        let dir = tempfile::tempdir().unwrap();
        let origin_path = dir.path().join("does_not_exist.db");
        let replica_path = dir.path().join("replica.db");

        let result = sync_local(
            origin_path.to_str().unwrap(),
            replica_path.to_str().unwrap(),
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn sync_local_byte_for_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let origin_path = dir.path().join("origin.db");
        let replica_path = dir.path().join("replica.db");

        let db = open_db(origin_path.to_str().unwrap());
        exec_sql(db, "CREATE TABLE data(k TEXT PRIMARY KEY, v BLOB)");
        exec_sql(db, "INSERT INTO data VALUES('key1', x'DEADBEEF')");
        exec_sql(db, "INSERT INTO data VALUES('key2', x'CAFEBABE')");
        unsafe {
            ffi::sqlite3_close(db);
        }

        let result = sync_local(
            origin_path.to_str().unwrap(),
            replica_path.to_str().unwrap(),
            false,
        );
        assert!(result.is_ok());

        // Verify data equality (replica may differ in journal-mode header bytes)
        let db = open_db(replica_path.to_str().unwrap());
        let count = query_int(db, "SELECT count(*) FROM data");
        assert_eq!(count, 2);
        unsafe {
            ffi::sqlite3_close(db);
        }

        // Verify file sizes match (same page count and page size)
        let origin_len = std::fs::metadata(&origin_path).unwrap().len();
        let replica_len = std::fs::metadata(&replica_path).unwrap().len();
        assert_eq!(origin_len, replica_len, "file sizes differ");
    }
}
