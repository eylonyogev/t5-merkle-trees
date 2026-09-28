//! Bounded correctness/timing smoke check; use Criterion for performance claims.

use std::{env, hint::black_box, time::Instant};

use binary_merkle_tree::{Blake3, HashFunction, MerkleTree, Sha3_256, Sha256};

fn run<H: HashFunction>(name: &str, data: &[u32], width: usize) {
    let start = Instant::now();
    let tree = MerkleTree::<H>::commit_u32(data, width).unwrap();
    let commit = start.elapsed();
    let commitment = tree.commitment();
    let index = data.len() / width / 2;
    let leaf = &data[index * width..(index + 1) * width];
    let mut siblings = Vec::new();
    tree.open_into(index, &mut siblings).unwrap();
    commitment.verify_u32(index, leaf, &siblings).unwrap();
    let mut wrong_leaf = leaf.to_vec();
    wrong_leaf[0] ^= 1;
    assert!(
        commitment
            .verify_u32(index, &wrong_leaf, &siblings)
            .is_err()
    );

    let repetitions = 1_000_u32;
    let start = Instant::now();
    for _ in 0..repetitions {
        black_box(&commitment)
            .verify_u32(black_box(index), black_box(leaf), black_box(&siblings))
            .unwrap();
    }
    let verify = start.elapsed() / repetitions;
    println!(
        "{name:8} commit={commit:?} verify={verify:?} siblings={}",
        siblings.len()
    );
}

fn main() {
    let mut args = env::args().skip(1);
    let total_log: u32 = args
        .next()
        .map_or(20, |arg| arg.parse().expect("total_log must be an integer"));
    let width_log: u32 = args
        .next()
        .map_or(8, |arg| arg.parse().expect("width_log must be an integer"));
    assert!(
        args.next().is_none(),
        "usage: cargo run --release --example smoke -- [total_log] [width_log]"
    );
    assert!(total_log <= 26, "total_log must be at most 26");
    assert!(
        width_log <= 14 && width_log <= total_log,
        "width_log must be at most 14 and at most total_log"
    );
    let total = 1_usize << total_log;
    let width = 1_usize << width_log;
    let data: Vec<u32> = (0..total)
        .map(|index| (index as u32).wrapping_mul(0x9e37_79b9))
        .collect();
    println!(
        "{} u32 elements, {} elements/leaf, {} leaves",
        total,
        width,
        total / width
    );
    run::<Sha256>("sha256", &data, width);
    run::<Sha3_256>("sha3_256", &data, width);
    run::<Blake3>("blake3", &data, width);
}
