//! Public-only reference CLI using the exact standalone checker source.
#[path = "../../public_crypto/src/lib.rs"]
mod client_public_crypto;

fn main() {
    std::process::exit(client_public_crypto::run_cli());
}
