# AFF4 Image Hasher

AFF4 Image Hasher is a small Rust command-line utility that calculates the SHA-256 hash of the reconstructed forensic image represented by an AFF4 container.

Unlike standard file-hashing utilities, which hash the outer .aff4 file itself, this tool reads the AFF4 through an AFF4-aware reader and hashes the reconstructed image stream presented as the virtual disk.

## Features

- Reads AFF4 forensic images
- Verifies declared AFF4 integrity information
- Reconstructs the virtual disk represented by the AFF4
- Calculates SHA-256 over the reconstructed image
- Reports the exact number of bytes hashed
- Does not modify the source AFF4

## Usage

cargo build --release

./target/release/aff4-image-hasher /path/to/image.aff4

## Example

AFF4 Image Hasher
=================

AFF4 integrity: PASS

Hashing reconstructed image...

Reconstructed image size: 268435456 bytes
Bytes hashed: 268435456

SHA-256:
[SHA-256 output]

## Validation

The tool was tested using the canonical Base-Linear-AllHashes.aff4 AFF4 reference image.

The reconstructed image SHA-256 produced by this utility was independently compared against results from established forensic software.

## Dependencies

This project uses the open-source `aff4` and `aff4-forensic` Rust crates for AFF4 parsing and integrity verification.

The AFF4 parsing implementation is provided by those upstream projects. This repository provides a focused command-line utility for reconstructed image hashing.

## Important distinction

Running a standard command such as:

shasum -a 256 evidence.aff4

calculates the SHA-256 of the AFF4 container file.

AFF4 Image Hasher instead calculates SHA-256 over the reconstructed forensic image exposed by the AFF4 reader.