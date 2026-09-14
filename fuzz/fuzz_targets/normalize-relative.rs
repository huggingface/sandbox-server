//! Fuzzes the host-mode path resolver.
//!
//! `normalize_relative` is the lexical half of the two defences that keep a
//! client's `?path=` inside its own sandbox home; the `openat`/`O_NOFOLLOW`
//! walk is the other half. Its whole contract is a shape: whatever bytes go
//! in, what comes out must be a relative path made only of plain components,
//! so that `home.join(result)` cannot name anything above `home`. That is an
//! invariant a fuzzer can check on every input, which makes this a much better
//! target than "does it panic".
//!
//! Input is decoded lossily, exactly as the query-string decoder in
//! `src/http.rs` does before the resolver ever sees it, so every generated
//! input corresponds to a request a client could actually send.
//!
//!   cargo +nightly fuzz run normalize-relative -- -max_total_time=60

#![no_main]

use std::path::{Component, Path, PathBuf};

use libfuzzer_sys::fuzz_target;

#[path = "../../src/fsutil.rs"]
#[allow(dead_code)]
mod fsutil;

fuzz_target!(|data: &[u8]| {
    let raw = String::from_utf8_lossy(data);
    let out = fsutil::normalize_relative(&raw);

    // The escape property, stated as the walk consumes it: every component the
    // walk will `openat` is a plain name, so no step can be `..`, a second
    // root, or an empty name that silently resolves to the parent.
    for component in out.components() {
        match component {
            Component::Normal(name) => {
                assert!(!name.is_empty(), "empty component from {raw:?}");
                assert_ne!(name.as_encoded_bytes(), b"..", "a literal .. survived from {raw:?}");
                assert!(
                    !name.as_encoded_bytes().contains(&b'/'),
                    "component {name:?} still holds a separator, from {raw:?}"
                );
            }
            other => panic!("non-normal component {other:?} from {raw:?} -> {out:?}"),
        }
    }
    assert!(out.is_relative(), "absolute result {out:?} from {raw:?}");
    assert!(!out.starts_with(".."), "result escapes upward: {out:?} from {raw:?}");

    // Joining onto a home must stay under that home. Purely lexical, but that
    // is the level this function is responsible for.
    let home = Path::new("/home/sbx-1");
    let joined = home.join(&out);
    assert!(joined.starts_with(home), "{joined:?} left the home, from {raw:?}");
    // Component count, not string prefix: `/home/sbx-10` must not count as
    // being under `/home/sbx-1`.
    assert_eq!(
        joined.components().count(),
        home.components().count() + out.components().count(),
        "join changed the component count: {joined:?} from {raw:?}"
    );

    // Normalizing an already-normal path must be a no-op, or the resolver and
    // anything that re-derives a path from a stored one would disagree.
    if let Some(text) = out.to_str() {
        assert_eq!(fsutil::normalize_relative(text), out, "not idempotent on {text:?}");
    }

    // What the walk actually iterates over must match what we just checked.
    let walked: PathBuf = out.components().collect();
    assert_eq!(walked, out);
});
