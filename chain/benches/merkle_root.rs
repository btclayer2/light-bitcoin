use criterion::{black_box, criterion_group, criterion_main, Criterion};

use light_bitcoin_chain::merkle_root;
use light_bitcoin_primitives::{h256_conv_endian_from_str, H256};

fn prepare_hashes(num: u32) -> Vec<H256> {
    let mut vec = Vec::new();
    let h1 = h256_conv_endian_from_str(
        "1da63abbc8cc611334a753c4c31de14d19839c65b2b284202eaf3165861fb58d",
    );
    let h2 = h256_conv_endian_from_str(
        "26c6a6f18d13d2f0787c1c0f3c5e23cf5bc8b3de685dd1923ae99f44c5341c0c",
    );
    let h3 = h256_conv_endian_from_str(
        "d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1",
    );
    for v in 0..num {
        match v % 3 {
            0 => vec.push(h1),
            1 => vec.push(h2),
            2 => vec.push(h3),
            _ => (),
        }
    }
    vec
}

fn bench_merkle_root_with_hashes(c: &mut Criterion) {
    let _5_hashes = prepare_hashes(5);
    c.bench_function("merkle_root_with_5_hashes", |b| {
        b.iter(|| {
            let _ = black_box(merkle_root(&_5_hashes));
        })
    });

    let _1000_hashes = prepare_hashes(1000);
    c.bench_function("merkle_root_with_1000_hashes", |b| {
        b.iter(|| {
            let _ = black_box(merkle_root(&_1000_hashes));
        })
    });
}

criterion_group!(benches, bench_merkle_root_with_hashes);
criterion_main!(benches);
