## substrate-c-tool

A tool that generates Substrate addresses and signed Extrinsics, written in the C language.

## Getting started

Most of the dependencies of the project are not specified with the purpose of facilitating its integration.

### Configuration

First step is to run the installation script:
```
./install.sh
```

Before using the project, edit the header `src/config.h` to "link" the host libraries.
You should also edit the `Makefile` to include your custom dependencies.

If you don't want to customize the project and just want to see it building, have a look at the following example of configuration. Otherwise, jump to the "Testing" section.

### Example configuration

Requires the package `libsodium-devel`.
The following packages are compatible with this project:
```
git clone https://github.com/bitcoin/libbase58.git ./lib/libbase58
git clone https://github.com/BLAKE2/BLAKE2.git ./lib/BLAKE2
```
This example configuration is build with:
```
export DEFAULT_CONFIG=1
```

Now you can try the examples.

Encode and decode a Substrate address with:
```
make example_address
./bin/generate_address
```

Encode and sign a balance transfer with:
```
make example_transaction
./bin/transfer_balance
```

## Testing

Requires that configuration is completed.

### Unit test
The test framework is `munit` and the test suite is run with:
```
make test
./bin/test
```
### Fuzz test
Requires the package `afl` (`american-fuzz-lop`).
Instructions are in `tests/fuzz/README.md`.

## Supported Features

* Address
    * Generates a Substrate address (only Ed25519 is supported).
    * Verifies a Substrate address.

* SCALE codec
    * Encoded/Decodes data to/from SCALE format.

* Extrinsic
    * Signs an Extrinsic containing a balance transfer.
