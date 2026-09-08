//! Fuzzes the HTTP request-head parser.
//!
//! `parse_head` is the first code in the process to touch bytes from an
//! unauthenticated peer, and it is hand-written, so it is the likeliest place
//! for a surprise. Crashing on hostile input is only half of what we care
//! about: the parser's job is to refuse anything whose framing two parsers
//! could read differently, so this target also asserts the framing invariants
//! on every head it *accepts*. A head that parses two ways, or parses into a
//! state the router did not expect, is a smuggling bug even though nothing
//! panicked.
//!
//!   cargo +nightly fuzz run request-head -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../src/http.rs"]
#[allow(dead_code)]
mod http;

/// Reshape arbitrary bytes into a head `read_request` could actually have
/// delivered: it reads one byte at a time and stops at the *first* CRLFCRLF, so
/// `parse_head` only ever sees a head that ends with one, contains no other,
/// and is within the 64 KiB cap. Feeding it anything else manufactures findings
/// no client can reach.
fn as_head(data: &[u8]) -> Vec<u8> {
    let mut head = match data.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(at) => data[..at + 4].to_vec(),
        None => {
            let mut head = data.to_vec();
            head.extend_from_slice(b"\r\n\r\n");
            head
        }
    };
    head.truncate(64 * 1024);
    head
}

fuzz_target!(|data: &[u8]| {
    let data = &as_head(data)[..];
    let Ok(request) = http::parse_head(data) else {
        // A rejection is a correct outcome for almost all of the input space;
        // there is nothing to check about it beyond "it did not panic".
        return;
    };

    // Same bytes, same framing. If this ever differs, something in the parser
    // depends on iteration order (HashMap) and two runs could disagree about
    // where the body ends -- which is request smuggling against ourselves.
    let again = http::parse_head(data).expect("a head that parsed once must parse again");
    assert_eq!(request.method, again.method);
    assert_eq!(request.path, again.path);
    assert_eq!(request.raw_query, again.raw_query);
    assert_eq!(request.content_length, again.content_length);
    assert_eq!(request.keep_alive, again.keep_alive);

    // The router matches on `method` after normalization, so it must be the
    // uppercase alphabetic token the route table is written against.
    assert!(!request.method.is_empty());
    assert!(
        request.method.bytes().all(|b| b.is_ascii_uppercase()),
        "method {:?} would not match any route literal",
        request.method
    );

    // The route table and the auth check both look up lowercase header names,
    // so a name that survived in any other case would be invisible to them --
    // that is how an `X-Sandbox-Token` gets smuggled past authentication.
    for (name, value) in &request.headers {
        assert_eq!(*name, name.to_ascii_lowercase(), "header name not lowercased: {name:?}");
        assert!(!name.is_empty());
        assert!(
            name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)),
            "non-token byte survived in header name {name:?}"
        );
        // The head was split on CRLF, so no value can carry a full CRLF and
        // thereby become two header lines when the proxy replays the head to a
        // backend.
        //
        // Note what is deliberately NOT asserted: a *bare* CR or LF does
        // survive in a value, e.g. "X-A: a\nX-B: b" parses as one header whose
        // value is "a\nX-B: b". A backend that accepts bare LF as a line
        // terminator would read that as two headers. It is not asserted here
        // because the parser does not promise it today, and the only reachable
        // target is the caller's own sandbox backend, which the same token can
        // already address directly. Tightening it is a change to the parser,
        // which belongs in its own PR -- not smuggled in behind a CI change.
        assert!(!value.contains("\r\n"), "CRLF in header value {value:?}");
    }

    // The single most important framing rule: never both.
    assert!(
        !(request.headers.contains_key("content-length") && request.headers.contains_key("transfer-encoding")),
        "accepted a head with both framing headers"
    );

    // A non-zero body length must come from a header that is a plain decimal
    // integer -- never from a guess, and never from a value we would re-read
    // differently than the proxy in front of us.
    match request.headers.get("content-length") {
        None => assert_eq!(request.content_length, 0, "invented a body length with no header"),
        Some(raw) => {
            assert_eq!(
                raw.parse::<u64>().ok(),
                Some(request.content_length),
                "Content-Length {raw:?} does not round-trip to {}",
                request.content_length
            );
        }
    }

    // The query string is split off, so a `?` left in `path` would let a
    // request reach a route whose literal it does not equal.
    assert!(!request.path.contains('?'), "query left in path: {:?}", request.path);
});
