fn main() {
    println!("cargo:rerun-if-changed=src/net_utils.c");
    let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    if target_family == "unix" {
        cc::Build::new().file("src/net_utils.c").compile("net_utils");
    }
}
