import os
import sys
import logging
import binascii
import concurrent.futures

import click
import grpc
import yaml
from hashlib import sha256

from eth_jit_exiter import signer_pb2
from eth_jit_exiter import lister_pb2
from eth_jit_exiter import signer_pb2_grpc
from eth_jit_exiter import lister_pb2_grpc
from eth2spec.phase0.mainnet import BLSPubkey, BLSSignature, bls, compute_signing_root
from eth2spec.utils.ssz.ssz_typing import Container, Bytes32
from eth_jit_exiter.signer_server import bls_signature_recover

logging.basicConfig()

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

class ArbitraryMessage(Container):
    message: Bytes32  # Arbitrary data

def get_grpc_credentials(config):
    """Generate the gRPC SSL channel credentials"""
    root_certs = open(config['dirk']['ca_cert'], 'rb').read()
    client_key = open(config['dirk']['client_key'], 'rb').read()
    client_cert = open(config['dirk']['client_cert'], 'rb').read()

    credentials = grpc.ssl_channel_credentials(
        private_key=client_key,
        root_certificates=root_certs,
        certificate_chain=client_cert,
    )

    return credentials

def get_accounts(config):
    endpoint = config['dirk']['endpoint']

    LOGGER.debug(f"Getting accounts list from endpoint {endpoint}")

    credentials = get_grpc_credentials(config)

    channel = grpc.secure_channel(endpoint, credentials)
    LOGGER.debug("Waiting for List Accounts channel...")

    grpc.channel_ready_future(channel).result()
    LOGGER.debug("Channel connected!")

    account_stub = lister_pb2_grpc.ListerStub(channel)
    accounts = account_stub.ListAccounts(lister_pb2.ListAccountsRequest(paths=[config['dirk']['wallet']]))

    channel.close()
    LOGGER.debug("Channel closed.")

    accounts_by_pub = {binascii.b2a_hex(account.composite_public_key).decode():account for account in accounts.DistributedAccounts}

    return accounts_by_pub

def parallel_sign_requests(credentials, account, data, domain):
    """
    Dispatch Sign requests to each endpoint in parallel using a ThreadPoolExecutor.
    Returns a dictionary mapping endpoint -> BLSSignature (for successful calls).
    """
    LOGGER.debug("Getting threshold signatures...")
    signatures = {}

    endpoints = {x.id: f"{x.name}:{x.port}" for x in account.participants}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(endpoints)) as executor:
        # Schedule a sign_request task for each endpoint ID
        future_to_id = {
            executor.submit(request_signature, endpoints[id_], credentials, account, data, domain): id_
            for id_ in endpoints
        }

        # As each future completes, retrieve its result
        for future in concurrent.futures.as_completed(future_to_id):
            id_ = future_to_id[future]
            try:
                signature = future.result()
                if signature:
                    signatures[id_] = signature
            except Exception as ex:
                LOGGER.error(f"Exception for endpoint with id {id_}: {ex}")

    valid_signatures = {key: value for key, value in signatures.items() if value is not None}

    if len(valid_signatures.items()) < account.signing_threshold:
        raise Exception(f"Not enough signatures obtained to reach threshold.")

    # Recover composite signature.
    recovered_signature = bls_signature_recover(valid_signatures)

    return BLSSignature.from_obj(recovered_signature)

def request_signature(endpoint, credentials, account, data, domain):
    try:
        LOGGER.debug(f"Waiting for Sign channel on endpoint {endpoint}...")
        channel = grpc.secure_channel(endpoint, credentials)
        grpc.channel_ready_future(channel).result()
        LOGGER.debug("Channel connected!")

        signer_stub = signer_pb2_grpc.SignerStub(channel)

        sign_response = signer_stub.Sign(signer_pb2.SignRequest(
            account=account.name,
            data=data,
            domain=domain
        ))

        channel.close()
        LOGGER.debug("Sign Channel closed.")

        if sign_response.state == 1:
            LOGGER.debug(f"Received signature from {endpoint}")
            return BLSSignature.from_obj(sign_response.signature)
    except Exception as e:
        LOGGER.error(f"Error while signing with endpoint {endpoint}: {e}")

    return None

def strip_prefix(value: str) -> str:
    return value[2:] if value.startswith("0x") else value

@click.command(help="Signs an arbitrary message with all accounts in Dirk.")
@click.option(
    "--message",
    help="The message you want to sign with the validator keys.",
    prompt="Enter the message you want to sign",
)
@click.option(
    "--domain",
    help="32-byte hex string domain in which to sign the message",
    prompt="Enter the domain in which to sign the message",
    default="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)
@click.option(
    "--output-dir",
    help="The folder where signed messages will be saved.",
    prompt="Enter output directory to collect signed files",
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.pass_context
def sign_arbitrary_message(
    ctx,
    message: str,
    domain: str,
    output_dir: str,
) -> None:
    config = ctx.obj.get('config', {})

    if not config:
        click.secho(
            f"Missing config!",
            bold=True,
            fg="red",
        )

        return

    domain = strip_prefix(domain)

    accounts = get_accounts(config)
    credentials = get_grpc_credentials(config)
    domain = bytes.fromhex(domain)
    domain_hex = domain.hex()

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    for public_key in accounts:
        LOGGER.info(f"Signing with key 0x{public_key}")

        data = ArbitraryMessage(
            message=sha256(message.encode("utf-8")).digest(),
        )

        signing_root = compute_signing_root(data, domain)

        signature = parallel_sign_requests(
            credentials=credentials,
            account=accounts[public_key],
            data=data.hash_tree_root(),
            domain=domain
        )

        LOGGER.info(f"Domain: 0x{domain_hex}")
        LOGGER.info(f"hash tree root: {data.hash_tree_root()}")
        LOGGER.info(f"Signing root: {signing_root}")
        LOGGER.info(f"Signature: {signature}")

        valid = bls.Verify(BLSPubkey.fromhex(public_key), signing_root, signature)

        LOGGER.info(f"Valid: {valid}")

        filename = f"pubkey_{public_key}.yaml"

        with open(os.path.join(output_dir, filename), "w") as f:
            f.write(yaml.dump({
                "pubkey": f"0x{public_key}",
                "message_body": message,
                "hash_tree_root": str(data.hash_tree_root()),
                "domain": f"0x{domain.hex()}",
                "signature": str(signature)
            }))

    click.secho(
        f"Signed {len(accounts)} messages.\n",
        bold=True,
        fg="green",
    )

@click.command(help="Verifies that a message signature matches the Public Key.")
@click.option(
    "--message",
    help="The original message that was signed.",
    prompt=False,
    default="",
)
@click.option(
    "--hash-tree-root",
    help="The hash tree root from the message.",
    prompt=False,
    default="",
)
@click.option(
    "--domain",
    help="32-byte hex string domain in which the message was signed",
    prompt="Enter the domain in which the message was signed",
    default="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)
@click.option(
    "--public-key",
    help="The public key.",
    prompt="Enter the public key",
)
@click.option(
    "--signature",
    help="The signature.",
    prompt="Enter the signature",
)
def verify_signature(
    message: str,
    hash_tree_root: str,
    domain: str,
    public_key: str,
    signature: str
) -> None:
    domain = strip_prefix(domain)
    public_key = strip_prefix(public_key)
    signature = strip_prefix(signature)

    if not message and not hash_tree_root:
        raise click.UsageError("You must provide either --message or --hash-tree-root.")

    if message:
        # We put the message in an container so we can compute the signing root.
        data = ArbitraryMessage(
            message=sha256(message.encode("utf-8")).digest(),
        )

        hash_tree_root = str(data.hash_tree_root())
        signing_root = compute_signing_root(data, bytes.fromhex(domain))
    else:
        signing_root = bytes.fromhex(strip_prefix(signing_root))

    valid = bls.Verify(
        bytes.fromhex(public_key),
        signing_root,
        bytes.fromhex(signature)
    )

    if valid:
        click.secho(
            f"Signature valid.\n",
            bold=True,
            fg="green",
        )

        click.secho(
            f"Can also be verified with ethdo:\n"
            f'ethdo signature verify --data="{hash_tree_root}" --signature="{signature}" --public-key="0x{public_key}" --domain="{domain}" --verbose',
            bold=False,
            fg="blue",
        )

        sys.exit(0)
    else:
        click.secho(
            f"Signature invalid!\n",
            bold=True,
            fg="red",
        )

        click.secho(
            f"Can also be verified with ethdo:\n"
            f'ethdo signature verify --data="{hash_tree_root}" --signature="{signature}" --public-key="0x{public_key}" --domain="{domain}" --verbose',
            bold=False,
            fg="blue",
        )

        sys.exit(1)
