use std::{default, fmt::format, io::{Read, Write}, net::TcpStream};
mod messages;
use messages::{EncryptedMessage, HelloMessage, ServerResponse};
use rand::{RngCore, thread_rng};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, sha2::Sha256};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use colored::Colorize;
use std::io::{self, BufRead};

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
        //     reads some text from the terminal
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("could not read line");
        let input = input.trim();
        if input.is_empty() {
            continue;
        }
        match input {
            //     if the text is “exit”, break from the loop
            "exit" => {
                return Ok(());
            }
            //     otherwise, send an Encrypted Message
            message => {
                println!("{}", message);
                let response = send_encrypted_message(&mut stream, &public_key, &input)?;

                // For every message the client sends to the server it:
                //     Creates a new symmetric key K and a nonce
                //     Encrypts the key K with the server’s public key
                //     Encrypts the message with K
                //     Sends the server an Encrypted Message message that includes the encrypted key, the nonce, and the encrypted message

            }
        }
        
        

        //     parse the Server Response
        // The server responds to an Encrypted Message with a Server Response that includes:

        //     a new nonce
        //     the message, encrypted with the same key but the new nonce
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
        Err(error) => panic!("Could not convert public key from PEM {}", error),
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

fn send_encrypted_message(stream: &mut TcpStream, pub_key: &RsaPublicKey, message: &str) -> Result<ServerResponse, String> {
    todo!()
}

