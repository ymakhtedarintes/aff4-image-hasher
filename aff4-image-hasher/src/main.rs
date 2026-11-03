use aff4::Aff4Reader;
use aff4_forensic::audit_image;
use sha2::{Digest, Sha256};
use std::env;
use std::io::Read;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: aff4-image-hasher <image.aff4>");
        std::process::exit(1);
    }

    let image = Path::new(&args[1]);

    if !image.exists() {
        eprintln!("Error: file not found: {}", image.display());
        std::process::exit(1);
    }

    println!("AFF4 Image Hasher");
    println!("=================");
    println!("Image: {}", image.display());
    println!();

    // Verify the AFF4's declared internal integrity hashes.
    match audit_image(image) {
        Ok(findings) => {
            if findings.is_empty() {
                println!("AFF4 integrity: PASS");
            } else {
                println!("AFF4 integrity: FINDINGS");

                for finding in findings {
                    println!("{}: {}", finding.code, finding.note);
                }

                std::process::exit(2);
            }
        }
        Err(error) => {
            eprintln!("Error verifying AFF4: {}", error);
            std::process::exit(1);
        }
    }

    println!();
    println!("Hashing reconstructed image...");

    let mut reader = match Aff4Reader::open(image) {
        Ok(reader) => reader,
        Err(error) => {
            eprintln!("Error opening AFF4 image: {}", error);
            std::process::exit(1);
        }
    };

    let virtual_size = reader.virtual_disk_size();

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut total: u64 = 0;

    loop {
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(error) => {
                eprintln!("Error reading AFF4 image: {}", error);
                std::process::exit(1);
            }
        };

        if count == 0 {
            break;
        }

        hasher.update(&buffer[..count]);
        total += count as u64;
    }

    let digest = hasher.finalize();

    let hex_digest: String = digest
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();

    println!();
    println!("Reconstructed image size: {} bytes", virtual_size);
    println!("Bytes hashed: {}", total);
    println!();
    println!("SHA-256:");
    println!("{}", hex_digest);
}