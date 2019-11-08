# Runkr

[![Build Status](https://travis-ci.org/danielSanchezQ/runkr.svg?branch=master)](https://travis-ci.org/danielSanchezQ/runkr)
[![Docs](https://docs.rs/runkr/badge.svg)](https://docs.rs/runkr)

Runkr is a Rust [Bunkr](https://bunkr.app) client. You can find all the Bunkr related information [here](https://github.com/off-the-grid-inc/bunkr)

Notice that you need to have a Bunkr daemon running:
* [Install Bunkr](https://github.com/off-the-grid-inc/bunkr#Bunkr-Install)
* [Singin](https://github.com/off-the-grid-inc/bunkr#sign-in)

Run your bunkr as a daemon with :
```shell script
bunkr -D
```
 
## Installation

Add the dependency to your `Cargo.toml`
```toml
[dependencies]
runkr = { version = "0.1.*"}
```

## Usage

The Runkr object API is really simple, you need to provide the socket address where the Bunkr daemon is listening, and then use each of the available methods to communicate with your Bunkr:

```rust
extern crate runkr;

use runkr::{Runkr, AccessMode};

fn main() {
    let mut runkr = Runkr::new("/tmp/bunkr_daemon.sock");
    // Test basic creat/access/delete operation
    runkr.new_text_secret("mySecret", "My secret content");
    let secret_content = runkr.access("mySecret", AccessMode::Text, None).unwrap();
    println!("{:?}", secret_content["content"].as_str());
    let del_res = runkr.delete("mySecret");
    match del_res {
        Ok(_)  => println!("Operation success"),
        Err(e) => println!("Error executing operation {}", e)
    };

    // Test groups and granting
    runkr.new_group("ga").unwrap();
    runkr.new_group("gb").unwrap();
    runkr.new_group("gc").unwrap();
    runkr.grant("ga", "gb", false).unwrap();
    runkr.grant("gb", "gc", false).unwrap();

    // Test rename and revoke
    runkr.rename("ga", "gA").unwrap();
    runkr.rename("gA", "ga").unwrap();
    runkr.revoke("ga", "gb").unwrap();
    runkr.revoke("gb", "gc").unwrap();
    for &n in ["ga", "gb", "gc"].iter() {
        runkr.delete(n).unwrap();
    }

    // Test ssh
    runkr.new_ssh_key("test_ssh_key").unwrap();
    let sign_res = runkr.sign_ecdsa("test_ssh_key", "Zm9v").unwrap();
    println!("Signature, R: {}, S: {}", sign_res["r"], sign_res["s"]);

    let ssh_public = runkr.ssh_public_data("test_ssh_key").unwrap();
    println!("b64 public key: {}", ssh_public["public_data"]["public_key"]);
    runkr.delete("test_ssh_key");

    // Test send device
    let device_result = runkr.send_device(None).unwrap();
    println!("My device link: {}", device_result["url_raw"]);

}
```

## Available operations
The [Bunkr operations](https://github.com/off-the-grid-inc/bunkr#Docs) currently supported by this client:
* new-text-secret
* new-ssh-key
* new-file-secret
* new-group
* import-ssh-key
* list-secrets
* list-devices
* list-groups
* send-device
* receive-device
* remove-device
* remove-local
* rename
* create
* write
* access
* grant
* revoke
* delete
* receive-capability
* reset-triples
* noop-test
* secret-info
* sign-ecdsa
* ssh-public-data
* signin
* confirm-signin

