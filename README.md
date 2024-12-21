# dirk-tools
A command-line collection of utilities to use with [Dirk](https://github.com/attestantio/dirk/).

## Usage

### Signing an arbitrary message

`dirk-tools --config config.yml sign-arbitrary-message [ARGS]`

```
Options:
  --message TEXT          The message you want to sign with the validator
                          keys.
  --domain TEXT           32-byte hex string domain in which to sign the
                          message
  --output-dir DIRECTORY  The folder where signed messages will be saved.
```

Ethereum 2.0 uses BLS signatures with the BLS12-381 curve, primarily to:

- Sign beacon chain objects (blocks, attestations, etc.).
- Enable aggregation of many signatures into a single, compact multi-signature.

SSZ (Simple Serialize) is the canonical way of encoding structured data prior to hashing and signing. For example:

- A BeaconBlock is an SSZ container with fields: slot, proposer_index, parent_root, state_root, and body_root.
- An Attestation is an SSZ container with fields: slot, index, beacon_block_root, source, target.

These containers are then serialized via SSZ, hashed, domain-separated, and signed using the BLS curve. Existing containers are Ethereum-specific and not intended for arbitrary messages.

Ethereum 2.0 also includes domain separation in the hashing process. This ensures that signatures cannot be replayed across different message types (e.g., confusing a block signature with an attestation signature). This is done by mixing in a 4-byte domain type, plus a version or fork identifier, before hashing.

In order to be able to sign an arbitrary message, we defined the following container:

```python
class ArbitraryMessage(Container):
    message: Bytes32
```

This provides the flexibility to handle messages of any length by following these steps:

- Hash the message using SHA-256 to produce a 32-byte digest.
- Wrap the digest in the ArbitraryMessage container.
- Compute the SSZ hash tree root.
- Sign the root using Dirk.

### Verify a message signature

`dirk-tools verify-signature [OPTIONS]`

```
Options:
  --message TEXT         The original message that was signed.
  --hash-tree-root TEXT  If the original message is not passed, pass the hash tree root of the message.
  --domain TEXT          32-byte hex string domain in which the message was signed.
  --public-key TEXT      The public key.
  --signature TEXT       The signature.
```

Alternatively, the signature can also be verified with ethdo:

`ethdo signature verify --data="0xMESSAGE_HASH_TREE_ROOT" --signature="0xSIGNATURE" --public-key="0xPUBLIC_KEY" --domain="0xDOMAIN" --verbose`

## Configuration

By default, `dirk-tools` loads the `config.yml` in the current folder in the current folder.

Otherwise it can be with the `--config` option, e.g:

`dirk-tools --config /path/to/config.yml [COMMAND] [ARGS]`

```yaml
dirk:
  # Hostname and port of the Dirk instance.
  endpoint: dirk.example.com:13141

  # Path to the client certificate to authenticate with Dirk.
  client_cert: /path/to/certs/client.crt

  # Path to the key to authenticate with Dirk.
  client_key: /path/to/certs/client.key

  # Path to the Certificate Authority certificate.
  ca_cert: /path/to/certs/dirk_authority.crt

  # Name of the Wallet
  wallet: Wallet
```

## Development

### Requirements

- python ^3.9.10 built with a shared Python Library

Linux:
```shell
sudo apt-get install python3-dev
```

MacOS with pyenv:
```shell
env PYTHON_CONFIGURE_OPTS="--enable-shared" pyenv install 3.9.10
```

- [Poetry](https://python-poetry.org/)

```shell
curl -sSL https://install.python-poetry.org | python -
```

### Install Dependencies

```shell
poetry install
```

### Running locally

```shell
poetry run python dirk_tools/main.py --config /path/to/config [COMMAND] [ARGS] --config /path/to/config.yml
```

### Building Executable

```shell
./build.sh
```

## License

[Apache License v2](LICENSE)
