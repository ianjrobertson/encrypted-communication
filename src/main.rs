use std::{io::{Read, Write}, net::TcpStream};
mod messages;
use aes_gcm::{
    Aes256Gcm, Nonce, aead::{Aead, AeadCore, KeyInit, OsRng}
};
use messages::{EncryptedMessage, HelloMessage, ServerResponse};
use rand::{RngCore, thread_rng};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey, pkcs8::DecodePublicKey, sha2::Sha256};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use colored::Colorize;
use std::io::{self};

fn main() -> Result<(), String> {
    // sends a Hello Message
    // parses the server response
    let (mut stream, public_key) = match connect().and_then(handshake) {
        Ok(result) => result,
        Err(e) => return Err(format!("An error occured connecting to the server {e}"))
    };

    println!("{} connected and {} connection", "Successfully".green(), "verified".green());
    println!("Type a question or {} to exit\n", "exit".yellow());

    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("could not read line");
        let input = input.trim();
        if input.is_empty() {
            continue;
        }
        match input {
            "exit" => {
                return Ok(());
            }
            message => {
                let server_response = send_encrypted_message(&mut stream, &public_key, &message)?;
                println!("{}", server_response.green());
            }
        }
    }
}

fn connect() -> Result<TcpStream, String> {
    let stream = TcpStream::connect("127.0.0.1:2222").map_err(|e| format!("Could not connect to server: {e}"))?;
    Ok(stream)
}

fn handshake(mut stream: TcpStream) -> Result<(TcpStream, RsaPublicKey), String> {
    let mut nonce = [0u8; 32];
    thread_rng().fill_bytes(&mut nonce);

    let hello = HelloMessage {
        signed_message: vec![],
        pub_key: "".to_string(),
        nonce,
    };
    let json: String = hello.to_json().map_err(|e: serde_json::Error| format!("Could not create hello message payload: {e}"))?;
    stream.write_all(json.as_bytes()).map_err(|e: std::io::Error| format!("Could not send message: {e}"))?;

    let mut buffer: [u8; 4096] = [0; 4096];
    let bytes_read: usize = stream.read(&mut buffer).map_err(|e: std::io::Error| format!("Could not read message: {e}"))?;

    let server_hello_json: &str = str::from_utf8(&buffer[..bytes_read]).expect("Server hello not in UTF8");
    let server_hello = HelloMessage::from_json(server_hello_json.to_string()).map_err(|e| format!("Could not parse hello message{e}"))?;

    let pub_key = match RsaPublicKey::from_public_key_pem(&server_hello.pub_key) {
        Ok(key) => key,
        Err(error) => return Err(format!("Could not convert public key from PEM {}", error))
    };

    let verifying_key: VerifyingKey<Sha256> = VerifyingKey::<Sha256>::new(pub_key.clone());
    let signature: Signature = Signature::try_from(server_hello.signed_message.as_ref()).expect("Could not convert signature");

    match verifying_key.verify(&nonce, &signature) {
        Ok(_) => (),
        Err(_e) => {
            return Err("Could not verify signature!".to_string());
        }
    };

    Ok((stream, pub_key))
}

fn send_encrypted_message(stream: &mut TcpStream, pub_key: &RsaPublicKey, message: &str) -> Result<String, String> {
    let key = Aes256Gcm::generate_key(OsRng);
    let encrypted_key = pub_key.encrypt(&mut OsRng, Pkcs1v15Encrypt, &key).map_err(|e| format!("Could not encrypy symetric key {e}"))?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, message.as_ref()).map_err(|e| format!("An error occured encrypting the text {e}"))?;
    let encrypted_message = EncryptedMessage {
        ciphertext,
        encrypted_key,
        nonce_bytes: nonce.to_vec()
    };

    let json: String = encrypted_message.to_json().map_err(|e: serde_json::Error| format!("Could not create message payload: {e}"))?;
    stream.write_all(json.as_bytes()).map_err(|e: std::io::Error| format!("Could not send message: {e}"))?;

    let mut buffer: [u8; 4096] = [0; 4096];
    let bytes_read: usize = stream.read(&mut buffer).map_err(|e: std::io::Error| format!("Could not read message: {e}"))?;

    let server_response_json: &str = str::from_utf8(&buffer[..bytes_read]).expect("Server hello not in UTF8");
    let server_response = ServerResponse::from_json(server_response_json.to_string()).map_err(|e| format!("Could not parse hello message{e}"))?;

    let plain_message = decrypt_message(&key, &server_response)?;
    Ok(plain_message)

}

fn decrypt_message(key: &[u8], server_response: &ServerResponse) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid Key: {e}"))?;
    let nonce = Nonce::from_slice(&server_response.nonce_bytes);
    let plaintext = cipher.decrypt(nonce, server_response.encrypted_message.as_ref()).map_err(|e| format!("Error decrypting message: {e}"))?;
    String::from_utf8(plaintext).map_err(|e| format!("Decrypted message not utf8 {e}"))
}

