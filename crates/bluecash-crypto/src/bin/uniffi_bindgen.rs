//! Entry point for UniFFI's bindings generator.
//!
//! Kept inside this crate rather than installed separately so the generator and
//! the scaffolding compiled into the library are always the same version. A
//! mismatch between the two produces bindings that compile and then fail at the
//! FFI boundary at runtime, which is a bad way to find out.
//!
//! ```text
//! cargo run --features uniffi-bindings --bin uniffi-bindgen -- \
//!     generate --library <path to the built cdylib> --language kotlin --out-dir <dir>
//! ```

fn main() {
    uniffi::uniffi_bindgen_main()
}
