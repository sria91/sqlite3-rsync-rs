# sqlite3-rsync-rs

Bandwidth-efficient SQLite database replication, written in Rust.

`sqlite3-rsync-rs` synchronises a *replica* database so that it becomes an
exact byte-for-byte copy of an *origin* database, transferring only the pages
that differ — much like `rsync` does for ordinary files.  It is a Rust port of
the [`sqlite3_rsync`](https://sqlite.org/rsync.html) utility by
D. Richard Hipp, preserving the wire protocol and semantics.

---

## How it works

Both the origin and replica sides compute a Keccak-based hash of each database
page.  Those hashes are exchanged over a byte-stream (typically a subprocess's
`stdin`/`stdout`).  Only the pages whose hashes disagree are sent in full,
minimising the data transferred.  The protocol is versioned; version 2 (the
default) further reduces round-trips for large databases by using aggregate
hashes over ranges of pages.

```
origin machine                      replica machine
──────────────────────────────────  ──────────────────────────────────
sqlite3-rsync-rs origin.db …  ────SSH──►  sqlite3-rsync-rs --replica replica.db
  │ sends page hashes                       │ compares hashes
  │◄──── mismatched page numbers ───────────┤
  │ sends only changed pages ──────────────►│
  │                                         │ applies pages, commits
```

---

## Installation

### From source

```sh
git clone https://github.com/your-org/sqlite3-rsync-rs
cd sqlite3-rsync-rs
cargo install --path .
```

SQLite is compiled from source automatically via the `bundled` feature of
[`libsqlite3-sys`](https://crates.io/crates/libsqlite3-sys).  No system
SQLite installation is required.

To link against the system `libsqlite3` instead, remove the `bundled` feature
in `Cargo.toml`:

```toml
libsqlite3-sys = { version = "0.37" }
```

---

## CLI usage

```
sqlite3_rsync ORIGIN REPLICA [OPTIONS]
```

One of `ORIGIN` or `REPLICA` is a local path; the other may be a remote path
in `user@host:/path/to/db` form.

```sh
# Sync a local database to a remote replica
sqlite3-rsync-rs /data/prod.db deploy@db2.example.com:/data/prod.db

# Sync a remote origin down to a local replica
sqlite3-rsync-rs ops@db1.example.com:/data/prod.db /backup/prod.db

# Sync two local databases (useful for testing)
sqlite3-rsync-rs origin.db replica.db --origin

# Show transferred-page statistics
sqlite3-rsync-rs origin.db user@host:replica.db -v

# Use a non-standard SSH port
sqlite3-rsync-rs origin.db user@host:replica.db --port 2222
```

### Options

| Flag | Description |
|------|-------------|
| `--exe PATH` | Name of the `sqlite3-rsync-rs` binary on the remote side |
| `--help` | Show usage screen |
| `-p`, `--port PORT` | SSH TCP port (default: 22) |
| `--protocol N` | Force wire-protocol version (1 or 2) |
| `--ssh PATH` | SSH binary to use (default: `ssh`) |
| `-v` | Verbose output; repeat for more detail (`-vv`, `-vvv`) |
| `--version` | Show SQLite version information |
| `--wal-only` | Refuse to sync unless both databases are in WAL mode |

---

## Library usage

The sync engine is exposed as a library crate.  Embed it directly when you
need programmatic control over the I/O streams (e.g. in-process pipes,
encrypted transports, or tests).

```rust
use sqlite3_rsync_rs::{origin_side, SqliteRsync};
use std::process::{Command, Stdio};

let mut child = Command::new("ssh")
    .args(["user@host", "sqlite3-rsync-rs", "--replica", "/data/replica.db"])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .spawn()?;

let mut ctx = SqliteRsync {
    z_origin:  Some("/data/origin.db".into()),
    z_replica: Some("/data/replica.db".into()),
    p_out: Some(Box::new(child.stdin.take().unwrap())),
    p_in:  Some(Box::new(child.stdout.take().unwrap())),
    ..SqliteRsync::default()
};

origin_side(&mut ctx);
assert_eq!(ctx.n_err, 0, "sync failed — check stderr for details");

println!(
    "transferred {} page(s) in {} round-trip(s)",
    ctx.n_page_sent, ctx.n_round
);
```

Full API documentation is available via:

```sh
cargo doc --open
```

---

## Development

```sh
# Build
cargo build

# Run all tests (44 tests across lib and binary targets)
cargo test

# Build API docs
cargo doc --no-deps --open
```

### Project layout

```
src/
  lib.rs    — sync engine (hash functions, wire protocol, origin_side, replica_side)
  main.rs   — CLI front-end (argument parsing, SSH subprocess management)
```

---

## Provenance & licence

Original C implementation by D. Richard Hipp, dedicated to the public domain.
This Rust port is also released into the public domain.
