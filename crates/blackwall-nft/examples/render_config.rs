//! Dev helper: parse a Blackwall config file and print its nftables JSON.
//! `cargo run -p blackwall-nft --example render_config -- <config-path>`

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: render_config <config>");
    let text = std::fs::read_to_string(&path).expect("read config");
    let policy = blackwall_config::parse_str(&text).expect("parse config");
    let json = blackwall_nft::ruleset_json(&policy).expect("render");
    println!("{json}");
}
