pub mod json_rpc_client;

#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;

use json_rpc_client::client::JSONRPCClient;
use json_rpc_client::protocol::{
    build_rpcjson_message, parse_rpcjson_response, JsonProtocolResponse,
};
use regex::Regex;
use serde::{Deserialize, Serialize};

// Supported Bunkr JSON RPC protocol version
const BUNKR_JSON_PROTOCOL_VERSION: &str = "1.0";
// Main Bunkr RPC method
const BUNKR_RPC_METHOD: &str = "CommandProxy.HandleCommand";

// Hashmap to reference the results parsing method
// Bunkr operations return strings containing different results, in order to use them
// usually is better to parse those results into proper objects
lazy_static! {
    static ref FMT_COMMANDS: HashMap<&'static str, Regex> = {
        let m: HashMap<&'static str, Regex> = HashMap::new();
        m
    };
}

// Bunkr result object that comes embedded in the response JSON RPC messages
#[derive(Serialize, Deserialize, Debug)]
struct BunkrResult {
    #[serde(rename = "Result")]
    result: String,
    #[serde(rename = "Error")]
    error: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct OperationArgs {
    #[serde(rename = "Line")]
    line: String,
}

// Main Bunkr client
pub struct Runkr {
    client: JSONRPCClient,
}

impl Runkr {
    pub fn new(address: &str) -> Runkr {
        Runkr {
            client: JSONRPCClient::new(address),
        }
    }

    // Get stream response message and parse the result of the operation if it was successful
    fn handle_response(&mut self, command_name: &str, response: String) -> Result<String, String> {
        match parse_rpcjson_response::<JsonProtocolResponse<BunkrResult>>(response.as_str()) {
            Ok(bunkr_result) => match bunkr_result.error {
                Some(err) => return Err(err),
                None => {
                    let res = bunkr_result.result.result;
                    match FMT_COMMANDS.get(command_name) {
                        Some(fmt_result) => match fmt_result.captures(res.as_str()) {
                            Some(cap) => return Ok(String::from(cap.get(0).unwrap().as_str())),
                            None => return Ok(res),
                        },
                        _ => return Ok(res),
                    }
                }
            },
            Err(e) => Err(format!("Error parsing response: {}", e)),
        }
    }

    // Send a command to the Bunkr JSON RPC server
    fn exec_command(
        &mut self,
        command_name: &'static str,
        command: &str,
    ) -> Result<String, String> {
        // Build the message to be sent
        let message = build_rpcjson_message(
            BUNKR_JSON_PROTOCOL_VERSION.to_string(),
            BUNKR_RPC_METHOD.to_string(),
            vec![OperationArgs {
                line: command.to_string(),
            }],
        );
        if !self.client.is_connected() {
            self.client.connect()?;
        }
        match self.client.send(message) {
            Ok(response) => {
                match self.client.disconnect() {
                    _ => {}
                }
                return self.handle_response(command_name, response);
            }
            Err(err) => {
                match self.client.disconnect() {
                    _ => {}
                }
                return Err(err);
            }
        };
    }

    pub fn new_text_secret(&mut self, secret_name: &str, content: &str) -> Result<String, String> {
        let command = format!(r#"new-text-secret {} "{}""#, secret_name, content);
        self.exec_command("new-text-secret", &command)
    }

    pub fn create(&mut self, secret_name: &str, secret_type: &str) -> Result<String, String> {
        let command = format!("create {} {}", secret_name, secret_type);
        self.exec_command("create", &command)
    }

    pub fn write(&mut self, secret_name: &str, content: &str) -> Result<String, String> {
        let command = format!(r#"write {} "{}""#, secret_name, content);
        self.exec_command("write", &command)
    }

    pub fn access(&mut self, secret_name: &str) -> Result<String, String> {
        let command = format!("access {}", secret_name);
        self.exec_command("access", &command)
    }

    pub fn delete(&mut self, secret_name: &str) -> Result<String, String> {
        let command = format!("delete {}", secret_name);
        self.exec_command("delete", &command)
    }

    pub fn sign_ecdsa(&mut self, secret_name: &str, hash_content: &str) -> Result<String, String> {
        let command = format!("sign-ecdsa {} {}", secret_name, hash_content);
        self.exec_command("sign-ecdsa", &command)
    }

    pub fn new_group(&mut self, group_name: &str) -> Result<String, String> {
        let command = format!("new-group {}", group_name);
        self.exec_command("new-group", &command)
    }

    pub fn grant(&mut self, device_name: &str, group_name: &str) -> Result<String, String> {
        let command = format!("grant {} {}", device_name, group_name);
        self.exec_command("grant", &command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_rpc_client::protocol::JsonProtocolMessage;
    use std::fs::remove_file;
    use std::io::prelude::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;
    use std::time;

    const TMP_SOCK: &str = "/tmp/punkr.sock";

    fn mock_server(response: String) {
        let listener = UnixListener::bind(TMP_SOCK).unwrap();
        match listener.accept() {
            Ok((mut stream, _)) => loop {
                let mut buff = [0 as u8; 1024];
                let mut handle = stream.try_clone().unwrap().take(1024);
                handle.read(&mut buff).unwrap();
                let message = String::from_utf8(buff.to_vec())
                    .unwrap()
                    .trim_end_matches(char::from(0))
                    .to_string();
                println!("Received message: {}", message);
                let message: JsonProtocolMessage<OperationArgs> =
                    serde_json::from_str(message.as_str()).unwrap();
                if message.params[0].line == "end" {
                    break;
                }
                stream.write_all(response.as_bytes()).unwrap();
            },
            Err(e) => println!("accept function failed: {:?}", e),
        }
    }

    #[test]
    fn test_punkr_client() {
        let response_message: JsonProtocolResponse<BunkrResult> = JsonProtocolResponse {
            id: uuid::Uuid::new_v4().to_string(),
            result: BunkrResult {
                result: "Foo".to_string(),
                error: "".to_string(),
            },
            error: None,
        };
        let response = serde_json::to_string(&response_message).unwrap();
        let t = thread::spawn(move || mock_server(response));
        let milis = time::Duration::from_millis(500);
        thread::sleep(milis);
        let mut runkr = Runkr::new(TMP_SOCK);
        let res = runkr
            .exec_command("create", "create foo foocontent")
            .unwrap();
        assert_eq!(res, "Foo".to_string());
        runkr.exec_command("", "end");
        t.join();
        remove_file(TMP_SOCK).unwrap();
    }
}
