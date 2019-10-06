# Runkr

[![Build Status](https://travis-ci.org/danielSanchezQ/runkr.svg?branch=master)](https://travis-ci.org/danielSanchezQ/runkr)


Runkr is a Rust [Bunkr](https://bunkr.app) client. You can find all the Bunkr related information [here](https://github.com/off-the-grid-inc/bunkr)

## Installation

Add the dependency to your `Cargo.toml`
```toml
[dependencies]
runkr = { version = "0.1.*"}
```

## Usage

The Runkr object API is really simple, you need to provide the socket address where the Bunkr daemon is listening, and then use each of the available methods to communicate with your Bunkr:

```rust
fn main() {
    let mut runkr = Runkr::new("/tmp/bunkr-daemon.sock");
    runker.new_text_secret("mySecret", "My secret content");
    let secret_content = runkr.access("mySecret").unwrap();
    println!("{}", secret_content);
    let del_res = runkr.delete("mySecret");
    match del_res {
        Ok(_)  => println!("Operation success"),
        Err(e) => println!("Error executing operation {}", e)
    };
}
```

## Available operations
The [Bunkr operations](https://github.com/off-the-grid-inc/bunkr#Docs) currently supported by this client:

* new-text-secret
* create
* write
* access
* delete
* sign-ecdsa
* new-group
* grant

