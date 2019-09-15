pub mod json_rpc_client;

#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;

use json_rpc_client::client::JSONRPCClient;
use json_rpc_client::protocol::{
    build_rpcjson_message, parse_rpcjson_response, JsonProtocolResponse,
};
use regex::Regex;
use serde::Deserialize;

const BUNKR_JSON_PROTOCOL_VERSION: &str = "1.0";
const BUNKR_RPC_METHOD: &str = "CommandProxy.HandleCommand";

lazy_static! {
    static ref FMT_COMMANDS: HashMap<&'static str, Regex> = {
        let mut m: HashMap<&'static str, Regex> = HashMap::new();
        m.insert("access", Regex::new(r"Secret content: ([^\n]*)\n").unwrap());
        m
    };
}

#[derive(Deserialize, Debug)]
struct BunkrResult {
    result: String,
    error: String,
}

pub struct Runkr {
    client: JSONRPCClient,
}

impl Runkr {
    pub fn new(address: &str) -> Runkr {
        Runkr {
            client: JSONRPCClient::new(address),
        }
    }

    pub fn handle_response(self, command_name: &str, response: String) -> Result<String, String> {
        match parse_rpcjson_response::<JsonProtocolResponse<BunkrResult>>(response.as_str()) {
            Ok(bunkr_result) => {
                if bunkr_result.error != "" {
                    if bunkr_result.result.error != "" {
                        return Err(bunkr_result.result.error);
                    }
                    let res = bunkr_result.result.result;
                    match FMT_COMMANDS.get(command_name) {
                        Some(fmt_result) => match fmt_result.captures(res.as_str()) {
                            Some(cap) => return Ok(String::from(cap.get(0).unwrap().as_str())),
                            None => return Ok(res),
                        },
                        _ => return Ok(res),
                    }
                }
                return Err(bunkr_result.error);
            }
            Err(_) => Err("Error parsing response".to_string()),
        }
    }

    pub fn exec_command(
        self,
        client: &mut JSONRPCClient,
        command_name: &'static str,
        command: String,
    ) -> Result<String, String> {
        let message = build_rpcjson_message(
            BUNKR_JSON_PROTOCOL_VERSION.to_string(),
            BUNKR_RPC_METHOD.to_string(),
            vec![format!("\"Line\": \"{command}\"", command = command)],
        );
        if !client.is_connected() {
            client.connect()?;
        }
        match client.send(message) {
            Ok(response) => self.handle_response(command_name, response),
            Err(err) => Err(err),
        }
    }
}
