///! Runkr is a lightweight library that enable communication with a running [Bunkr](bunkr.app)
/// daemon through unix sockets. It is intended to use as a single object that abstract the
/// available Bunkr operations.
///
///
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
use std::str::FromStr;

// Supported Bunkr JSON RPC protocol version
const BUNKR_JSON_PROTOCOL_VERSION: &str = "1.0";
// Main Bunkr RPC method
const BUNKR_RPC_METHOD: &str = "CommandProxy.HandleCommand";

// Bunkr supported commands
pub enum Command {
    NEW_TEXT_SECRET,
    NEW_SSH_KEY,
    NEW_FILE_SECRET,
    NEW_GROUP,
    IMPORT_SSH_KEY,
    LIST_SECRETS,
    LIST_DEVICES,
    LIST_GROUPS,
    SEND_DEVICE,
    RECEIVE_DEVICE,
    REMOVE_DEVICE,
    REMOVE_LOCAL,
    RENAME,
    CREATE,
    WRITE,
    ACCESS,
    GRANT,
    REVOKE,
    DELETE,
    RECEIVE_CAPABILITY,
    RESET_TRIPLES,
    NOOP,
    SECRET_INFO,
    SIGN_ECDSA,
    SSH_PUBLIC_DATA,
    SIGNIN,
    CONFIRM_SIGNIN,
}

impl Command {
    pub fn to_string(&self) -> String {
        let res = match self {
            Command::NEW_TEXT_SECRET => "new-text-secret",
            Command::NEW_SSH_KEY => "new-ssh-key",
            Command::NEW_FILE_SECRET => "new-file-secret",
            Command::NEW_GROUP => "new-group",
            Command::IMPORT_SSH_KEY => "import-ssh-key",
            Command::LIST_SECRETS => "list-secrets",
            Command::LIST_DEVICES => "list-devices",
            Command::LIST_GROUPS => "list-groups",
            Command::SEND_DEVICE => "send-device",
            Command::RECEIVE_DEVICE => "receive-device",
            Command::REMOVE_DEVICE => "remove-device",
            Command::REMOVE_LOCAL => "remove-local",
            Command::RENAME => "rename",
            Command::CREATE => "create",
            Command::WRITE => "write",
            Command::ACCESS => "access",
            Command::GRANT => "grant",
            Command::REVOKE => "revoke",
            Command::DELETE => "delete",
            Command::RECEIVE_CAPABILITY => "receive-capability",
            Command::RESET_TRIPLES => "reset-triples",
            Command::NOOP => "noop-test",
            Command::SECRET_INFO => "secret-info",
            Command::SIGN_ECDSA => "sign-ecdsa",
            Command::SSH_PUBLIC_DATA => "ssh-public-data",
            Command::SIGNIN => "sigin",
            Command::CONFIRM_SIGNIN => "confirm-signin",
        };
        res.to_string()
    }
}

impl FromStr for Command {
    type Err = &'static str;
    fn from_str(command: &str) -> Result<Self, Self::Err> {
        match command {
            "new-text-secret" => Ok(Command::NEW_TEXT_SECRET),
            "new-ssh-key" => Ok(Command::NEW_SSH_KEY),
            "new-file-secret" => Ok(Command::NEW_FILE_SECRET),
            "new-group" => Ok(Command::NEW_GROUP),
            "import-ssh-key" => Ok(Command::IMPORT_SSH_KEY),
            "list-secrets" => Ok(Command::LIST_SECRETS),
            "list-devices" => Ok(Command::LIST_DEVICES),
            "list-groups" => Ok(Command::LIST_GROUPS),
            "send-device" => Ok(Command::SEND_DEVICE),
            "receive-device" => Ok(Command::RECEIVE_DEVICE),
            "remove-device" => Ok(Command::REMOVE_DEVICE),
            "remove-local" => Ok(Command::REMOVE_LOCAL),
            "rename" => Ok(Command::RENAME),
            "create" => Ok(Command::CREATE),
            "write" => Ok(Command::WRITE),
            "access" => Ok(Command::ACCESS),
            "grant" => Ok(Command::GRANT),
            "revoke" => Ok(Command::REVOKE),
            "delete" => Ok(Command::DELETE),
            "receive-capability" => Ok(Command::RECEIVE_CAPABILITY),
            "reset-triples" => Ok(Command::RESET_TRIPLES),
            "noop-test" => Ok(Command::NOOP),
            "secret-info" => Ok(Command::SECRET_INFO),
            "sign-ecdsa" => Ok(Command::SIGN_ECDSA),
            "ssh-public-data" => Ok(Command::SSH_PUBLIC_DATA),
            "sigin" => Ok(Command::SIGNIN),
            "confirm-signin" => Ok(Command::CONFIRM_SIGNIN),
            _ => Err("Command not supported"),
        }
    }
}

// Bunkr supported secret types
pub enum SecretType {
    ECDSASECP256k1Key,
    ECDSAP256Key,
    HMACKey,
    GenericGF256,
    GenericPF,
}

impl SecretType {
    pub fn to_string(&self) -> String {
        let res = match self {
            SecretType::ECDSASECP256k1Key => "ECDSA-SECP256k1",
            SecretType::ECDSAP256Key => "ECDSA-P256",
            SecretType::HMACKey => "HMAC",
            SecretType::GenericGF256 => "GENERIC-GF256",
            SecretType::GenericPF => "GENERIC-PF",
        };
        res.to_string()
    }
}

impl FromStr for SecretType {
    type Err = &'static str;
    fn from_str(secret_type: &str) -> Result<Self, Self::Err> {
        match secret_type {
            "ECDSA-SECP256k1" => Ok(SecretType::ECDSASECP256k1Key),
            "ECDSA-P256" => Ok(SecretType::ECDSAP256Key),
            "HMAC" => Ok(SecretType::HMACKey),
            "GENERIC-GF256" => Ok(SecretType::GenericGF256),
            "GENERIC-PF" => Ok(SecretType::GenericPF),
            _ => Err("Secret type not supported"),
        }
    }
}

// Secret content type
// Used in some of the operations to specify the sent content format
pub enum ContentType {
    B64,
    Text,
}

impl ContentType {
    pub fn to_string(&self) -> String {
        let res = match self {
            ContentType::B64 => "b64",
            ContentType::Text => "text",
        };
        res.to_string()
    }
}

impl FromStr for ContentType {
    type Err = &'static str;
    fn from_str(content_type: &str) -> Result<Self, Self::Err> {
        match content_type.to_lowercase().as_str() {
            "b64" => Ok(ContentType::B64),
            "text" => Ok(ContentType::Text),
            _ => Err("Content type not supported"),
        }
    }
}

// Access operation mode
// `B64` to retrieve the contenty bytes in b64 format
// `Text` for plain string representation
// `File` to dump content into a file
pub enum AccessMode {
    B64,
    Text,
    File,
}

impl AccessMode {
    pub fn to_string(&self) -> String {
        let res = match self {
            AccessMode::B64 => "b64",
            AccessMode::Text => "text",
            AccessMode::File => "file",
        };
        res.to_string()
    }
}

impl FromStr for AccessMode {
    type Err = &'static str;
    fn from_str(mode: &str) -> Result<Self, Self::Err> {
        match mode.to_lowercase().as_str() {
            "b64" => Ok(AccessMode::B64),
            "text" => Ok(AccessMode::Text),
            "file" => Ok(AccessMode::File),
            _ => Err("Content type not supported"),
        }
    }
}

// Bunkr replies with a generic json, we can use serde Value for it
type Response = serde_json::Value;

// Bunkr result object that comes embedded in the response JSON RPC messages
#[derive(Serialize, Deserialize, Debug)]
struct BunkrResult {
    #[serde(rename = "Result")]
    result: Response,
    #[serde(rename = "Error")]
    error: String,
}

// Bunkr RPC object holding the command to be executed and a list with the needed command arguments
#[derive(Serialize, Deserialize, Debug)]
struct OperationArgs {
    #[serde(rename = "Command")]
    command: String,
    #[serde(rename = "Args")]
    args: Vec<String>,
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
    fn handle_response(
        &mut self,
        command_name: Command,
        response: String,
    ) -> Result<Response, String> {
        match parse_rpcjson_response::<JsonProtocolResponse<BunkrResult>>(response.as_str()) {
            Ok(bunkr_result) => match bunkr_result.error {
                Some(err) => return Err(err),
                None => {
                    let res = bunkr_result.result.result;
                    return Ok(res);
                }
            },
            Err(e) => Err(format!("Error parsing response: {}", e)),
        }
    }

    // Send a command to the Bunkr JSON RPC server
    fn exec_command(
        &mut self,
        command_name: Command,
        args: Vec<String>,
    ) -> Result<Response, String> {
        // Build the message to be sent
        let message = build_rpcjson_message(
            BUNKR_JSON_PROTOCOL_VERSION.to_string(),
            BUNKR_RPC_METHOD.to_string(),
            vec![OperationArgs {
                command: command_name.to_string(),
                args,
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

    /// new_text_secret creates and writes a secret
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn new_text_secret(
        &mut self,
        secret_name: &str,
        content: &str,
    ) -> Result<Response, String> {
        self.exec_command(
            Command::NEW_TEXT_SECRET,
            vec![secret_name.to_string(), content.to_string()],
        )
    }

    /// new_ssh_key creates a new ecdsa key and stores it as a secret
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn new_ssh_key(&mut self, secret_name: &str) -> Result<Response, String> {
        self.exec_command(Command::NEW_SSH_KEY, vec![secret_name.to_string()])
    }

    /// new_file_secret creates a secret with the content of an specified file
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn new_file_secret(
        &mut self,
        secret_name: &str,
        file_path: &str,
    ) -> Result<Response, String> {
        self.exec_command(
            Command::NEW_FILE_SECRET,
            vec![secret_name.to_string(), file_path.to_string()],
        )
    }

    /// new_group creates a new group
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn new_group(&mut self, group_name: &str) -> Result<Response, String> {
        self.exec_command(Command::NEW_GROUP, vec![group_name.to_string()])
    }

    /// import_ssh_key uploads an ecdsa key to Bunkr
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn import_ssh_key(
        &mut self,
        secret_name: &str,
        file_path: &str,
    ) -> Result<Response, String> {
        self.exec_command(
            Command::IMPORT_SSH_KEY,
            vec![secret_name.to_string(), file_path.to_string()],
        )
    }

    /// list_secrets retrieves Bunkr stored secret names and hierarchy
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg"     : "",
    ///     "content" : {
    ///         "secrets" : [string], # secrets names
    ///         "devices" : {
    ///             "<device name>" : [string], # secrets names
    ///             ...
    ///         },
    ///         "groups" : {
    ///             "<group name>" : [string], # secrets names
    ///             ...
    ///         },
    ///     }
    /// }
    /// ```
    pub fn list_secrets(&mut self) -> Result<Response, String> {
        self.exec_command(Command::LIST_SECRETS, vec![])
    }

    /// list_devices retrieves Bunkr attached devices
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///      "msg"     : "",
    ///      "devices" : [string] # devices names
    /// }
    /// ```
    pub fn list_devices(&mut self) -> Result<Response, String> {
        self.exec_command(Command::LIST_DEVICES, vec![])
    }

    /// list_groups retrieves Bunkr attached devices
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///      "msg"     : "",
    ///      "groups"  : [string] # group names
    /// }
    /// ```
    pub fn list_groups(&mut self) -> Result<Response, String> {
        self.exec_command(Command::LIST_GROUPS, vec![])
    }

    /// send_device generates a device sharing link/s
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg"       : "<feedback message>",
    ///     "url_raw"   : "<shared static url>",
    ///     "url_short" : "<shared short url>",
    /// }
    /// ```
    pub fn send_device(&mut self, device_name: Option<&str>) -> Result<Response, String> {
        match device_name {
            Some(name) => self.exec_command(Command::SEND_DEVICE, vec![name.to_string()]),
            None => self.exec_command(Command::SEND_DEVICE, vec![]),
        }
    }

    /// receive_device links a links a new device to Bunkr
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn receive_device(&mut self, url: &str) -> Result<Response, String> {
        self.exec_command(Command::RECEIVE_DEVICE, vec![url.to_string()])
    }

    /// remove_device removes a device link from Bunkr
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn remove_device(&mut self, device_name: &str) -> Result<Response, String> {
        self.exec_command(Command::REMOVE_DEVICE, vec![device_name.to_string()])
    }

    /// remove_local removes a secret reference from Bunkr (it does not delete the secret)
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn remove_local(&mut self, secret_name: &str) -> Result<Response, String> {
        self.exec_command(Command::REMOVE_LOCAL, vec![secret_name.to_string()])
    }

    /// rename a secret, group or device
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn rename(&mut self, old_name: &str, new_name: &str) -> Result<Response, String> {
        self.exec_command(
            Command::RENAME,
            vec![old_name.to_string(), new_name.to_string()],
        )
    }

    /// create a new secret
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn create(
        &mut self,
        secret_name: &str,
        secret_type: SecretType,
    ) -> Result<Response, String> {
        self.exec_command(Command::CREATE, vec![secret_type.to_string()])
    }

    /// write dumps content into the specified secret
    /// If content_type is None, b64 mode is use by default
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn write(
        &mut self,
        secret_name: &str,
        content: &str,
        content_type: Option<ContentType>,
    ) -> Result<Response, String> {
        match content_type {
            Some(t) => self.exec_command(Command::WRITE, vec![t.to_string()]),
            None => self.exec_command(Command::WRITE, vec![ContentType::B64.to_string()]),
        }
    }

    /// access the content of a secret
    /// It can retrieve the content in plain text, b64 or dump it into a file
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///      "msg"       : "<feedback message>",
    ///      "mode"      : "<access mode>"
    ///      "content"   : "<secret content just for (b64 and text)>",
    /// }
    /// ```
    pub fn access(
        &mut self,
        secret_name: &str,
        mode: AccessMode,
        fpath: Option<&str>,
    ) -> Result<Response, String> {
        match mode {
            AccessMode::File => match fpath {
                Some(path) => self.exec_command(
                    Command::ACCESS,
                    vec![AccessMode::File.to_string(), path.to_string()],
                ),
                None => Err("A file path must be specified for File mode".to_string()),
            },
            _ => self.exec_command(Command::ACCESS, vec![mode.to_string()]),
        }
    }

    /// grant command shares a secret to a device or group
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg"       : "<feedback message>",
    ///     "url_raw"   : "<shared static url>",
    ///     "url_short" : "<shared short url>",
    /// }
    /// ```
    pub fn grant(
        &mut self,
        target: &str,
        secret_name: &str,
        admin: bool,
    ) -> Result<Response, String> {
        match admin {
            true => self.exec_command(
                Command::GRANT,
                vec![
                    target.to_string(),
                    secret_name.to_string(),
                    "admin".to_string(),
                ],
            ),
            false => self.exec_command(
                Command::GRANT,
                vec![target.to_string(), secret_name.to_string()],
            ),
        }
    }

    /// revoke command removes a capability from a secret to the specified device or group
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn revoke(&mut self, target: &str, secret_name: &str) -> Result<Response, String> {
        self.exec_command(
            Command::REVOKE,
            vec![target.to_string(), secret_name.to_string()],
        )
    }

    /// delete specified secret
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn delete(&mut self, secret_name: &str) -> Result<Response, String> {
        self.exec_command(Command::DELETE, vec![secret_name.to_string()])
    }

    /// receive_capability, load a capability into your Bunkr
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn receive_capability(&mut self, url: &str) -> Result<Response, String> {
        self.exec_command(Command::RECEIVE_CAPABILITY, vec![url.to_string()])
    }

    /// reset_triples launches a reseting operation to synchronize the triples in a secret coalition
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn reset_triples(&mut self, secret_name: &str) -> Result<Response, String> {
        self.exec_command(Command::RESET_TRIPLES, vec![secret_name.to_string()])
    }

    /// noop performs a health status operation
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn noop(&mut self, secret_name: &str) -> Result<Response, String> {
        self.exec_command(Command::NOOP, vec![secret_name.to_string()])
    }

    /// secret_info return public secret info for the specified secret
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn secret_info(&mut self, secret_name: &str) -> Result<Response, String> {
        self.exec_command(Command::SECRET_INFO, vec![secret_name.to_string()])
    }

    /// sign_ecdsa requests a signing with the specified secret content
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///      "msg" : "<feedback message>",
    ///      "r"   : "<R component of the signature>",
    ///      "s"   : "<S component of the signature>",
    /// }
    /// ```
    pub fn sign_ecdsa(
        &mut self,
        secret_name: &str,
        hash_content: &str,
    ) -> Result<Response, String> {
        self.exec_command(
            Command::SIGN_ECDSA,
            vec![secret_name.to_string(), hash_content.to_string()],
        )
    }

    /// ssh_public_data requests a signing with the specified secret content
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///    "msg"            : "<feedback message>",
    ///    "public_data"    : {
    ///        "name"       : "<secret name>",
    ///        "public_key" : "<b64 encoded public key>",
    ///    }
    /// }
    /// ```
    pub fn ssh_public_data(&mut self, secret_name: &str) -> Result<Response, String> {
        self.exec_command(Command::SSH_PUBLIC_DATA, vec![secret_name.to_string()])
    }

    /// sigin performs a Bunkr signin process
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn signin(&mut self, email: &str, device_name: &str) -> Result<Response, String> {
        self.exec_command(
            Command::SIGNIN,
            vec![email.to_string(), device_name.to_string()],
        )
    }

    /// confirm_signin verifies the sigin verification code to access the Bunkr
    /// ### Returns
    /// json like object decoded into a Response object
    /// ```json
    /// {
    ///     "msg" : "<feedback message>",
    /// }
    /// ```
    pub fn confirm_signin(&mut self, email: &str, code: &str) -> Result<Response, String> {
        self.exec_command(
            Command::CONFIRM_SIGNIN,
            vec![email.to_string(), code.to_string()],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_rpc_client::protocol::JsonProtocolMessage;
    use serde_json::Value;
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
                if &message.params[0].args[0] == "end" {
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
                result: Value::String("Foo".to_string()),
                error: "".to_string(),
            },
            error: None,
        };
        let response = serde_json::to_string(&response_message).unwrap();
        let t = thread::spawn(move || mock_server(response));
        // Wait a bit for server to start
        let milis = time::Duration::from_millis(500);
        thread::sleep(milis);
        let mut runkr = Runkr::new(TMP_SOCK);
        let res = runkr
            .exec_command(
                Command::CREATE,
                vec!["foo".to_string(), "foo_content".to_string()],
            )
            .unwrap();
        assert_eq!(res, "Foo".to_string());
        runkr.exec_command(Command::NOOP, vec!["end".to_string()]);
        t.join();
        remove_file(TMP_SOCK).unwrap();
    }
}
