fn main() {
    println!("cargo:rerun-if-env-changed=LIBSQLITE3_FLAGS");

    let flags = std::env::var("LIBSQLITE3_FLAGS").unwrap_or_default();
    if !flags.contains("SQLITE_ENABLE_DBPAGE_VTAB") {
        panic!(
            "\n\nsqlite3_rsync requires SQLite to be compiled with SQLITE_ENABLE_DBPAGE_VTAB.\n\
             Add the following to your project's .cargo/config.toml:\n\n\
             \t[env]\n\
             \tLIBSQLITE3_FLAGS = \"-DSQLITE_ENABLE_DBPAGE_VTAB\"\n\n"
        );
    }
}
