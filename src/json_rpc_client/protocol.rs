// JSON RPC protocol messages
use serde::{Deserialize, Serialize};
use serde_json;
use std::vec;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonProtocolMessage<T> {
    pub version: String,
    pub method: String,
    pub params: vec::Vec<T>,
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonProtocolResponse<T> {
    pub result: T,
    pub error: Option<String>,
    pub id: String,
}

pub fn build_rpcjson_message<T>(version: String, method: String, params: vec::Vec<T>) -> String
where
    T: Serialize,
{
    serde_json::to_string(&JsonProtocolMessage::<T> {
        version,
        method,
        params,
        id: Uuid::new_v4().to_string(),
    })
    .unwrap()
}

pub fn parse_rpcjson_response<'a, T>(response: &'a str) -> Result<T, String>
where
    T: Deserialize<'a>,
{
    match serde_json::from_str(response) {
        Ok(res) => return Ok(res),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_rpc_client::protocol::build_rpcjson_message;

    #[test]
    fn test_build_message() {
        let message = build_rpcjson_message(
            "1.0".to_string(),
            "CommandProxy.HandleCommand".to_string(),
            vec![r#""Line": "access foo""#.to_string()],
        );
        println!("{}", message);
        assert_ne!(message.len(), 0);
        let protocol_message: JsonProtocolMessage<String> =
            serde_json::from_str(message.as_str()).unwrap();
        assert_eq!(protocol_message.version, "1.0");
        assert_eq!(protocol_message.method, "CommandProxy.HandleCommand");
        assert_eq!(protocol_message.params[0], r#""Line": "access foo""#);
        assert!(protocol_message.id != "");
    }

    #[test]
    fn test_parse_response() {
        let id = Uuid::new_v4();
        let response: JsonProtocolResponse<String> = JsonProtocolResponse {
            id: id.to_string(),
            result: "Foo".to_string(),
            error: None,
        };
        let str_response = serde_json::to_string(&response).unwrap();
        println!("{}", str_response);
        assert_ne!(str_response.len(), 0);
        let parse_response: JsonProtocolResponse<String> =
            parse_rpcjson_response(&str_response).unwrap();
        assert_eq!(response.id, parse_response.id);
        assert_eq!(response.result, parse_response.result);
        assert_eq!(response.error, parse_response.error);
    }
}
