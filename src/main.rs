use std::{io::{Read, Write}, net::TcpStream};

mod messages;
use messages::{EncryptedMessage, HelloMessage, ServerResponse};
use rand::{RngCore, thread_rng};

fn main() {
    let mut stream = match TcpStream::connect("127.0.0.1:2222") {
        Ok(stream) => stream,
        Err(_e) => {
            println!("Could not connect to server. Check that it is running");
            return ();
        }
    };
    println!("Connected to server");
    
    // sends a Hello Message
    let mut nonce = [0u8; 32];
    thread_rng().fill_bytes(&mut nonce);

    let hello = HelloMessage {
        signed_message: vec![],
        pub_key: "".to_string(),
        nonce,
    };
    let json = match hello.to_json() {
        Ok(json) => json,
        Err(e) => {
            println!("Could not convert message to json {e}");
            return();
        }
    };

    // TODO items: refactor this code into a function that returns a success or fail for the connect case
    // If the conncect is succussful, keep looping and sending messages to the server
    // If the connect is unsuccseful return

    match stream.write_all(json.as_bytes()) {
        Ok(_value) => {
            println!("Sent hello message to server");

            // parses the server response

            // we assume that all messages are shorter than 4096 bytes and
            // will be read in one call to read()
            let mut buffer = [0; 4096];
            let bytes_read = match stream.read(&mut buffer) {
                Ok(bytes_read) => bytes_read,
                Err(e) => {
                    println!("An error occured reading from the server");
                    return();
                }
            };
            // an example of how to convert the buffer to a JSON string
            // you can do something similar for other message types
            let server_hello_json = str::from_utf8(&buffer[..bytes_read]).expect("Server hello not in UTF8");
            println!("{server_hello_json}");

            // The client sends the server a Hello Message containing a nonce
            // The server responds with a Hello Message that includes its RSA public key (in PEM format), the nonce, and a signed version of the nonce
            // The client verifies the signature and, if it is valid, accepts the server’s public key

            // loops
            //     reads some text from the terminal
            //     if the text is “exit”, break from the loop
            //     otherwise, send an Encrypted Message
            //     parse the Server Response
        }
        Err(e) => {
            println!("Could not send hello message to server, {e}");
            return();
        }
    }
}
// For every message the client sends to the server it:

//     Creates a new symmetric key K and a nonce
//     Encrypts the key K with the server’s public key
//     Encrypts the message with K
//     Sends the server an Encrypted Message message that includes the encrypted key, the nonce, and the encrypted message

// The server responds to an Encrypted Message with a Server Response that includes:

//     a new nonce
//     the message, encrypted with the same key but the new nonce

// The client decrypts and prints each Encrypted Message the server sends it

// sends a Hello Message
// parses the server response
// loops

//     reads some text from the terminal
//     if the text is “exit”, break from the loop
//     otherwise, send an Encrypted Message
//     parse the Server Response


