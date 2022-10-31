use hex;
use sha1::{self, Digest};
use std::{
    env,
    error::Error,
    fs,
    io::{self, BufRead},
};

const SHA1_HEX_STRING_LENGTH: usize = 40;

// sha1(general) = dfe2db74975e0aa9f6fdd4d61dedcb7328502456
// sha1(hello) = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d

fn main() -> Result<(), Box<dyn Error>> {
    // reading cli args
    let cli_args: Vec<String> = env::args().collect();

    // validate args length
    if cli_args.len() != 3 {
        println!("Usage:");
        println!("sha1_cracker: <WORDS_LIST.TXT> <SHA1_HASH>");
        return Ok(());
    }

    // validate sha1 hash len
    let hash_to_crack = cli_args[2].trim();
    if hash_to_crack.len() != SHA1_HEX_STRING_LENGTH {
        return Err("sha1 hash is not valid".into());
    }

    // read wordslist dictionary
    let words = fs::File::open(&cli_args[1])?;
    let reader = io::BufReader::new(&words);

    for line in reader.lines() {
        let line = line?;
        let common_pass = line.trim().to_string();
        // sha1 hash of common pass
        if hash_to_crack == &hex::encode(sha1::Sha1::digest(common_pass.as_bytes())) {
            println!("Password count: {}", common_pass);
            return Ok(());
        }
    }

    println!("password not found in wordlist :(");
    Ok(())
}
