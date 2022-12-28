#[macro_use]
extern crate rocket;
extern crate openssl;
use std::{env, fs, io::Write};

use openssl::rsa::{Padding, Rsa};
use openssl::symm::Cipher;
use passwords::PasswordGenerator;
use rocket::serde::{json::Json, Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Res {
    pub password: String,
}

/// This struct can help you generate passwords.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ReqData {
    pub length: usize,
    pub numbers: bool,
    pub lowercase_letters: bool,
    pub uppercase_letters: bool,
    pub symbols: bool,
    pub spaces: bool,
    pub exclude_similar_characters: bool,
    pub strict: bool,
}

#[post("/generate-password", format = "application/json", data = "<req_data>")]
fn index(req_data: String) -> Json<Res> {
    let parsed_data: ReqData = serde_json::from_str(&req_data[..]).unwrap();
    let pg = PasswordGenerator {
        length: parsed_data.length,
        numbers: parsed_data.numbers,
        lowercase_letters: parsed_data.lowercase_letters,
        uppercase_letters: parsed_data.uppercase_letters,
        symbols: parsed_data.symbols,
        spaces: parsed_data.spaces,
        exclude_similar_characters: parsed_data.exclude_similar_characters,
        strict: parsed_data.strict,
    };

    // println!("{}", pg.generate_one().unwrap());
    Json(Res {
        password: pg.generate_one().unwrap(),
    })
}

#[launch]
fn rocket() -> _ {
    // let passphrase = "rust_by_example";

    // let rsa = Rsa::generate(1024).unwrap();
    // let private_key: Vec<u8> = rsa
    //     .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), passphrase.as_bytes())
    //     .unwrap();
    // let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();

    // let public_key_pem = String::from_utf8(public_key).unwrap();

    // let private_key_pem = String::from_utf8(private_key).unwrap();

    // let data = "A quick brown fox jumps over the lazy dog.";

    // // Encrypt with public key
    // let rsa = Rsa::public_key_from_pem(public_key_pem.as_bytes()).unwrap();
    // let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    // let _ = rsa
    //     .public_encrypt(data.as_bytes(), &mut buf, Padding::PKCS1)
    //     .unwrap();
    // println!("Encrypted: {:?}", buf);

    // let data = buf;

    // // Decrypt with private key
    // let rsa =
    //     Rsa::private_key_from_pem_passphrase(private_key_pem.as_bytes(), passphrase.as_bytes())
    //         .unwrap();
    // let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    // let _ = rsa
    //     .private_decrypt(&data, &mut buf, Padding::PKCS1)
    //     .unwrap();
    // println!("Decrypted: {}", String::from_utf8(buf).unwrap());

    match fs::read("my_important_text.txt") {
        Ok(contents) => {
            // The `2` here is arbitrary, you can put any number

            let passphrase = "rust_by_example";

            let rsa = Rsa::generate(1024).unwrap();
            let private_key: Vec<u8> = rsa
                .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), passphrase.as_bytes())
                .unwrap();
            let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();

            let public_key_pem = String::from_utf8(public_key).unwrap();

            let private_key_pem = String::from_utf8(private_key).unwrap();

            let data = contents;

            // Encrypt with public key
            let rsa = Rsa::public_key_from_pem(public_key_pem.as_bytes()).unwrap();
            let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
            let _ = rsa.public_encrypt(&data, &mut buf, Padding::PKCS1).unwrap();
            println!("Encrypted: {:?}", buf);

            let mut file = fs::File::create("my_important_text_1.txt").unwrap();

            // let c = &buf.into_iter().filter(|&x| x == 0).collect();

            if let Err(e) = file.write(&buf) {
                println!("Error: {:?}", e);
            }

            let data = buf;

            // Decrypt with private key
            let rsa = Rsa::private_key_from_pem_passphrase(
                private_key_pem.as_bytes(),
                passphrase.as_bytes(),
            )
            .unwrap();
            let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
            let _ = rsa
                .private_decrypt(&data, &mut buf, Padding::PKCS1)
                .unwrap();
            println!("Decrypted: {}", String::from_utf8(buf.clone()).unwrap());

            let mut file = fs::File::create("my_important_text_2.txt").unwrap();

            println!("data: {:?} {}", &buf, &rsa.size());

            let (left, right) = buf.split_at(buf.iter().position(|&x| x == 0).unwrap_or_default());

            println!("right: {:?}", right);

            if let Err(e) = file.write(left) {
                println!("Error: {:?}", e);
            }
        }

        Err(e) => {
            println!("Could not open file `{}`: {}", "my_important_text.txt", e);
        }
    } // File encode and decode
    
    gen_password();

    rocket::build().mount("/", routes![index])
}

fn gen_password() -> () {
    let pg = PasswordGenerator {
        length: 8,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        spaces: false,
        exclude_similar_characters: false,
        strict: true,
    }; // generate password

    println!("{}", pg.generate_one().unwrap());
    println!("{:?}", pg.generate(5).unwrap());
}

// fn main() {
//     let pg = PasswordGenerator {
//         length: 8,
//         numbers: true,
//         lowercase_letters: true,
//         uppercase_letters: true,
//         symbols: true,
//         spaces: false,
//         exclude_similar_characters: false,
//         strict: true,
//     };

//     println!("{}", pg.generate_one().unwrap());
//     println!("{:?}", pg.generate(5).unwrap());
// }
