//! Public mathematics only. No secret input, filesystem selection or network.
fn main() {
    std::process::exit(ptlc_nom_public_crypto::run_cli());
}
