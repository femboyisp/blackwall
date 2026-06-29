//! The shipped proof-slice scenario must parse, validate, compile, and render.

use blackwall_lab::addr::allocate;
use blackwall_lab::plan::compile;
use blackwall_lab::render::render_bird;
use blackwall_lab::topology::{parse_manifest, validate};

const SCENARIO: &str = include_str!("../scenarios/bgp-bird.kdl");

#[test]
fn proof_slice_is_well_formed() {
    let manifest = parse_manifest(SCENARIO).expect("parse");
    validate(&manifest.topology).expect("validate");

    let map = allocate(&manifest.topology).expect("allocate");
    let plan = compile(&manifest.topology, &map, "test00").expect("compile");
    assert_eq!(plan.netns, vec!["bw-test00-peer".to_owned(), "bw-test00-speaker".to_owned()]);

    let peer = &manifest.topology.nodes[0];
    let bird = render_bird(peer, &manifest.topology, &map).expect("render");
    assert!(bird.contains("neighbor 10.0.0.2 as 214806;"));
    assert!(bird.contains("router id 10.0.0.1;"));
}
