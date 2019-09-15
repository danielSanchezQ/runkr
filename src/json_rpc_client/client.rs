use std::io::prelude::*;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

pub struct JSONRPCClient {
    address: String,
    stream: Option<UnixStream>,
}

impl JSONRPCClient {
    pub fn new(address: &str) -> JSONRPCClient {
        JSONRPCClient {
            address: address.to_string(),
            stream: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        match self.stream {
            Some(_) => true,
            None => false,
        }
    }

    pub fn connect(&mut self) -> Result<(), String> {
        match UnixStream::connect(&self.address) {
            Ok(stream) => {
                self.stream = Some(stream);
                return Ok(());
            }
            Err(e) => {
                return Err(format!(
                    "Could not connect to {} due to {}",
                    self.address, e
                ))
            }
        }
    }

    pub fn disconnect(&mut self) -> Result<(), String> {
        match &self.stream {
            Some(stream) => match stream.shutdown(Shutdown::Both) {
                Ok(_) => {
                    self.stream = None;
                    return Ok(());
                }
                Err(e) => {
                    return Err(format!(
                        "Error disconnecting from {} due to {}",
                        self.address, e
                    ))
                }
            },
            None => return Err("Error, trying to disconnect from empty stream".to_string()),
        }
    }

    pub fn send(&mut self, message: String) -> Result<String, String> {
        if self.is_connected() {
            match &mut self.stream {
                Some(stream) => {
                    match stream.write_all(message.as_bytes()) {
                        Ok(_) => {}
                        Err(e) => return Err(format!("Error writing message: {}", e)),
                    }
                    let mut buff = [0 as u8; 1024];
                    let mut handle = stream.take(1024);
                    handle.read(&mut buff);
                    match String::from_utf8(buff.to_vec()) {
                        Ok(result) => {
                            return Ok(result.trim_end_matches(char::from(0)).to_string())
                        }
                        Err(e) => {
                            return Err(format!("Error: couldn't read properly from stream: {}", e))
                        }
                    }
                }
                None => return Err("Error: couldn't find available socket stream".to_string()),
            }
        }
        Err(format!(
            "Client bound to address `{}` is disconnected",
            self.address
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::json_rpc_client::client::JSONRPCClient;
    use crate::json_rpc_client::protocol::build_rpcjson_message;
    use std::io::prelude::*;
    use std::io::{BufRead, BufReader};
    use std::net::Shutdown;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;

    fn ping() {
        let listener = UnixListener::bind("/tmp/rust-uds.sock").unwrap();
        match listener.accept() {
            Ok((mut stream, socket_addr)) => loop {
                let mut buff = [0 as u8; 1024];
                println!("Reading");
                let mut handle = stream.try_clone().unwrap().take(1024);
                handle.read(&mut buff).unwrap();
                let message = String::from_utf8(buff.to_vec())
                    .unwrap()
                    .trim_end_matches(char::from(0))
                    .to_string();
                println!("Got message: {}", message.clone());
                println!("Writing");
                stream.write_all(message.as_bytes()).unwrap();
            },
            Err(e) => println!("accept function failed: {:?}", e),
        }
    }

    #[test]
    fn test_client() {
        let sock = "/tmp/rust-uds.sock";
        println!("Launching ping");
        let t = thread::spawn(|| ping());
        let content = "{\"Line\": \"access foo\"}";
        let message = build_rpcjson_message(
            "1.0".to_string(),
            "CommandProxy.HandleCommand".to_string(),
            vec![content.to_string()],
        );
        println!("Creating client");
        let mut client = JSONRPCClient::new(sock);
        println!("Connecting to {}", sock);
        client.connect().unwrap();
        assert!(client.is_connected());
        println!("Sending message {}", message);
        let result = client.send(message.clone()).unwrap();
        assert_eq!(result, message);
        assert!(client.is_connected());
        let result2 = client.send("foo".to_string()).unwrap();
        assert_eq!(result2, "foo".to_string());
        println!("Disconnecting");
        client.disconnect().unwrap();
    }

    #[test]
    fn streams() {
        use std::io::prelude::*;
        use std::net::Shutdown;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let (mut s1, mut s2) = UnixStream::pair().unwrap();
        s1.write_all(b"hello world").unwrap();
        let mut buff = [0; 1024];
        let mut h = s2.take(1024);
        h.read(&mut buff);
        let mut response = String::from_utf8(buff.to_vec()).unwrap();
        let res = response.trim_end_matches(char::from(0));
        assert_eq!("hello world".to_string(), res);
    }
}
