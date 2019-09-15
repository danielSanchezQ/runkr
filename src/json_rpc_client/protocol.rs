use serde::{Deserialize, Serialize};
use serde_json;
use std::vec;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonProtocolMessage {
    version: String,
    method: String,
    params: vec::Vec<String>,
    id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonProtocolResponse<T> {
    pub result: T,
    pub error: String,
    id: String,
}

pub fn build_rpcjson_message(version: String, method: String, params: vec::Vec<String>) -> String {
    serde_json::to_string(&JsonProtocolMessage {
        version,
        method,
        params,
        id: Uuid::new_v4().to_string(),
    })
    .unwrap()
}

pub fn parse_rpcjson_response<'a, T>(response: &'a str) -> Result<T, ()>
where
    T: Deserialize<'a>,
{
    match serde_json::from_str(response) {
        Ok(res) => return Ok(res),
        Err(_) => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use crate::json_rpc_client::protocol::build_rpcjson_message;

    #[test]
    fn test_build_message() {
        let message = build_rpcjson_message(
            "1.0".to_string(),
            "CommandProxy.HandleCommand".to_string(),
            vec!["\"Line\": \"access foo\"".to_string()],
        );
        println!("{}", message);
        assert!(message.len() != 0);
    }
}
