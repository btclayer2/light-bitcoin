use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use light_bitcoin_mast::{
    convert_hex_to_pubkey, generate_combine_index, generate_combine_pubkey, Mast,
};
use musig2::{PrivateKey, PublicKey};

fn bench_generate_combine_index(b: &mut Bencher) {
    let n = 20;
    let m = 10;
    // println!("combine:{}", compute_combine(n, m));
    b.iter(|| generate_combine_index(n, m));
}

fn bench_generate_combine_pubkey(b: &mut Bencher) {
    let n = 100;
    let m = 99;
    // println!("combine:{}", compute_combine(n, m));
    let pubkey = convert_hex_to_pubkey("04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
    let pks = vec![pubkey; n];
    b.iter(|| {
        generate_combine_pubkey(pks.clone(), m)
            .unwrap()
            .iter()
            .map(|p| hex::encode(&p.serialize()))
            .collect::<Vec<_>>()
    });
}

fn bench_generate_root(b: &mut Bencher) {
    let n = 10;
    let m = 5;
    // println!("combine:{}", compute_combine(n, m));
    let pks = (1..n)
        .map(|i| PublicKey::create_from_private_key(&PrivateKey::from_int(i as u32)))
        .collect::<Vec<_>>();
    b.iter(|| {
        let mast = Mast::new(pks.clone(), m).unwrap();
        let _root = mast.calc_root().unwrap();
    });
}

fn bench_generate_address(c: &mut Criterion) {
    c.bench_function("bench_generate_combine_index", bench_generate_combine_index);

    c.bench_function(
        "bench_generate_combine_pubkey",
        bench_generate_combine_pubkey,
    );

    c.bench_function("bench_generate_root", bench_generate_root);
}

criterion_group!(benches, bench_generate_address);
criterion_main!(benches);
