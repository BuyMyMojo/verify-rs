use clap::Parser;
use hex::ToHex;
use std::io::prelude::*;
use std::{
    fs::File,
    path::{Path, PathBuf},
    process::exit,
};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input file to hash
    #[arg()]
    input: PathBuf,

    /// Display cryptographically broken hashes
    #[arg(short, long)]
    cryptographically_broken: bool,

    /// Display extra hashes
    #[arg(short, long)]
    extras: bool,
}

fn main() {
    let args = Args::parse();

    // Make sure input is a file
    if !args.input.is_file() {
        eprintln!("Input must be a file!");
        exit(1);
    }

    let file_name = args
        .input
        .file_name()
        .expect("Unable to get file name")
        .to_str()
        .expect("Unable to read file name");

    let sha256 = sha256(&args.input);
    let sha512 = sha512(&args.input);
    let blake3 = blake3(&args.input);
    let blake2s256 = blake2s_256(&args.input);
    let blake2b512 = blake2b_512(&args.input);
    let sha3_256 = sha3_256(&args.input);
    let sha3_512 = sha3_512(&args.input);

    let mut output = format!(
        "Sha256:
{sha256} {file_name}

Sha3 256:
{sha3_256} {file_name}

Blake2s:
{blake2s256} {file_name}

Blake3:
{blake3} {file_name}

Sha512:
{sha512} {file_name}

Sha3 512:
{sha3_512} {file_name}

Blake2b:
{blake2b512} {file_name}"
    );

    if args.extras {
        let sha3_224 = sha3_224(&args.input);
        let sha3_384 = sha3_384(&args.input);
        output.push_str(
            format!("\n\nExtra Hashes:

Sha3 224:
{sha3_224} {file_name}

Sha3 384:
{sha3_384} {file_name}
").as_str(),
        );
    }

    if args.cryptographically_broken {
        let sha1 = sha1(&args.input);
        let md5 = md5(&args.input);
        output.push_str(
            format!("\n\nCryptographically Broken Hashes:

Md5:
{md5} {file_name}

Sha1:
{sha1} {file_name}").as_str(),
        );
    }

    println!("{output}");
}

fn sha256(file_path: &Path) -> String {
    use sha2::{Sha256, Digest};
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("Unable to read file contents");

    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let res = hasher.finalize();

    res.encode_hex::<String>()
}

fn sha512(file_path: &Path) -> String {
    use sha2::{Sha512, Digest};
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("Unable to read file contents");

    let mut hasher = Sha512::new();
    hasher.update(&buffer);
    let res = hasher.finalize();

    res.encode_hex::<String>()
}

fn sha3_256(file_path: &Path) -> String {
    use sha3::{Sha3_256, Digest};
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("Unable to read file contents");

    let mut hasher = Sha3_256::new();
    hasher.update(&buffer);
    let res = hasher.finalize();

    res.encode_hex::<String>()
}

fn sha3_224(file_path: &Path) -> String {
    use sha3::{Sha3_224, Digest};
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("Unable to read file contents");

    let mut hasher = Sha3_224::new();
    hasher.update(&buffer);
    let res = hasher.finalize();

    res.encode_hex::<String>()
}

fn sha3_384(file_path: &Path) -> String {
    use sha3::{Sha3_384, Digest};
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("Unable to read file contents");

    let mut hasher = Sha3_384::new();
    hasher.update(&buffer);
    let res = hasher.finalize();

    res.encode_hex::<String>()
}

fn sha3_512(file_path: &Path) -> String {
    use sha3::{Sha3_512, Digest};
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("Unable to read file contents");

    let mut hasher = Sha3_512::new();
    hasher.update(&buffer);
    let res = hasher.finalize();

    res.encode_hex::<String>()
}

fn sha1(file_path: &Path) -> String {
    use sha1::{Sha1, Digest};
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("Unable to read file contents");

    let mut hasher = Sha1::new();
    hasher.update(&buffer);
    let res = hasher.finalize();

    res.encode_hex::<String>()
}

fn md5(file_path: &Path) -> String {
    use md5::{Md5, Digest};
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("Unable to read file contents");

    let mut hasher = Md5::new();
    hasher.update(&buffer);
    let res = hasher.finalize();

    res.encode_hex::<String>()
}

fn blake3(file_path: &Path) -> String {
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("Unable to read file contents");

    let hash1 = blake3::hash(&buffer);
    hash1.to_string()
}

fn blake2b_512(file_path: &Path) -> String {
    use blake2::{Blake2b512, Digest};
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("Unable to read file contents");

    let mut hasher = Blake2b512::new();

    hasher.update(&buffer);

    let res = hasher.finalize();

    res.encode_hex::<String>()
}

fn blake2s_256(file_path: &Path) -> String {
    use blake2::{Blake2s256, Digest};
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("Unable to read file contents");

    let mut hasher = Blake2s256::new();

    hasher.update(&buffer);

    let res = hasher.finalize();

    res.encode_hex::<String>()
}
