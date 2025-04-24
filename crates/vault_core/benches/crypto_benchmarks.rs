use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{thread_rng, RngCore};
use std::time::Duration;
use vault_core::{decrypt_data, encrypt_data, VaultEncryptionParams};

fn generate_random_data(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    thread_rng().fill_bytes(&mut data);
    data
}

fn benchmark_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption");
    group.sample_size(10); // Reduce sample size due to high security parameters
    group.measurement_time(Duration::from_secs(30)); // Longer measurement time

    // Test different data sizes
    for size in [1024, 10 * 1024, 100 * 1024, 1024 * 1024].iter() {
        let data = generate_random_data(*size);
        let password = "benchmark_password_with_high_entropy_1234567890!@#$";

        group.bench_with_input(
            BenchmarkId::new("fort_knox_encrypt", size),
            &data,
            |b, data| {
                b.iter(|| encrypt_data(black_box(data), black_box(password)));
            },
        );
    }

    group.finish();
}

fn benchmark_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("decryption");
    group.sample_size(10); // Reduce sample size due to high security parameters
    group.measurement_time(Duration::from_secs(30)); // Longer measurement time

    // Test different data sizes
    for size in [1024, 10 * 1024, 100 * 1024].iter() {
        let data = generate_random_data(*size);
        let password = "benchmark_password_with_high_entropy_1234567890!@#$";

        // Pre-encrypt with maximum security
        let encrypted = encrypt_data(&data, password).expect("Encryption failed");

        // Benchmark decryption
        group.bench_with_input(
            BenchmarkId::new("fort_knox_decrypt", size),
            &encrypted,
            |b, encrypted| {
                b.iter(|| decrypt_data(black_box(encrypted), black_box(password)));
            },
        );
    }

    group.finish();
}

fn benchmark_high_volume(c: &mut Criterion) {
    // This benchmark tests encryption/decryption of multiple small files in sequence
    // to simulate batch processing operations

    let mut group = c.benchmark_group("high_volume");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    // Generate 100 small files
    let file_count = 100;
    let file_size = 4 * 1024; // 4KB each
    let mut files = Vec::with_capacity(file_count);

    for _ in 0..file_count {
        files.push(generate_random_data(file_size));
    }

    let password = "batch_processing_password_with_high_entropy_1234567890!@#$";

    // Benchmark encrypting all files in sequence
    group.bench_function("encrypt_100_files", |b| {
        b.iter(|| {
            for file in &files {
                let _ =
                    encrypt_data(black_box(file), black_box(password)).expect("Encryption failed");
            }
        });
    });

    // Pre-encrypt all files for decryption benchmark
    let encrypted_files: Vec<_> = files
        .iter()
        .map(|file| encrypt_data(file, password).expect("Encryption failed"))
        .collect();

    // Benchmark decrypting all files in sequence
    group.bench_function("decrypt_100_files", |b| {
        b.iter(|| {
            for encrypted in &encrypted_files {
                let _ = decrypt_data(black_box(encrypted), black_box(password))
                    .expect("Decryption failed");
            }
        });
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().significance_level(0.01).sample_size(10);
    targets = benchmark_encryption, benchmark_decryption, benchmark_high_volume
);
criterion_main!(benches);
