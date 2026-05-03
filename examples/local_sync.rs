//! Example: sync two local SQLite databases without spawning a subprocess.
//!
//! ```
//! cargo run --example local_sync -- origin.db replica.db [--wal-only]
//! ```
//!
//! Both paths must be on the local filesystem.  The function `sync_local`
//! wires up a pair of OS pipes and runs [`origin_side`] and [`replica_side`]
//! on separate threads so that they can exchange data concurrently.

use sqlite3_rsync::sync_local;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut wal_only = false;
    let positional: Vec<&str> = args[1..]
        .iter()
        .filter(|a| {
            if a.as_str() == "--wal-only" {
                wal_only = true;
                false
            } else {
                true
            }
        })
        .map(String::as_str)
        .collect();

    minimal_logger::init(minimal_logger::config_from_env()).expect("failed to initialise logger");

    if positional.len() != 2 {
        eprintln!("Usage: local_sync ORIGIN REPLICA [--wal-only]");
        std::process::exit(1);
    }

    let origin = positional[0];
    let replica = positional[1];

    match sync_local(origin, replica, wal_only) {
        Ok(_) => (),
        Err(msg) => {
            log::error!("{msg}");
            std::process::exit(1);
        }
    }

    minimal_logger::shutdown();
}
