//! Frozen outputs from the pre-optimization release library at commit
//! cfd93bdf643e64674c460bace0553516e95848c4. Generated before replacing any
//! compression kernel, using input byte i = (73*i + floor(i/7)) mod 256.
//! Unlike a reference that calls the current primitive, these fixtures also
//! detect accidental changes to role encoding, padding, and chaining domains.

use binary_merkle_tree::{Blake3, LeafMode, LeafPlan, ResearchHash, Sha3_256, Sha256};

fn check<H: ResearchHash>() {
    let mut checked = 0;
    for row in include_str!("fixtures/experimental-leaves-v1.csv")
        .lines()
        .skip(1)
    {
        let fields: Vec<_> = row.split(',').collect();
        assert_eq!(fields.len(), 4);
        if fields[0] != H::NAME {
            continue;
        }
        let mode = LeafMode::ALL
            .into_iter()
            .find(|mode| mode.name() == fields[1])
            .unwrap();
        let width: usize = fields[2].parse().unwrap();
        let input: Vec<u8> = (0..width)
            .map(|i| i.wrapping_mul(73).wrapping_add(i / 7) as u8)
            .collect();
        let expected: [u8; 32] =
            core::array::from_fn(|i| u8::from_str_radix(&fields[3][2 * i..2 * i + 2], 16).unwrap());
        let plan = LeafPlan::new::<H>(mode, width).unwrap();
        assert_eq!(
            plan.hash::<H>(&input),
            expected,
            "{} {mode:?} {width} single",
            H::NAME
        );
        // Include full four-lane batches plus a partial tail in the same call.
        let batch = input.repeat(5);
        let mut digests = [[0; 32]; 5];
        plan.hash_many::<H>(&batch, &mut digests);
        assert!(
            digests.iter().all(|digest| *digest == expected),
            "{} {mode:?} {width} batch",
            H::NAME
        );
        checked += 1;
    }
    assert_eq!(checked, if H::supports_t253() { 240 } else { 200 });
}

#[test]
fn sha256_preserves_preoptimization_outputs() {
    check::<Sha256>();
}

#[test]
fn sha3_preserves_preoptimization_outputs() {
    check::<Sha3_256>();
}

#[test]
fn blake3_preserves_preoptimization_outputs() {
    check::<Blake3>();
}
