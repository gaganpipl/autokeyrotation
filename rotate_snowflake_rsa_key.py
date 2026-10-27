"""Rotate a Snowflake service user's RSA key using Azure Key Vault."""

from __future__ import annotations

import base64
import logging
import os

import snowflake.connector
from azure.identity import AzureCliCredential
from azure.keyvault.secrets import SecretClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

LOGGER = logging.getLogger("snowflake-rsa-key-rotation")


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"Required environment variable {name} is not set.")
    return value


def quote_identifier(identifier: str) -> str:
    if not identifier:
        raise ValueError("Snowflake user name cannot be empty.")
    return '"' + identifier.replace('"', '""') + '"'


def quote_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def generate_key_pair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, base64.b64encode(public_der).decode("ascii")


def load_private_key(pem: str, passphrase: str | None = None) -> bytes:
    password = passphrase.encode("utf-8") if passphrase else None
    private_key = serialization.load_pem_private_key(
        pem.encode("utf-8"),
        password=password,
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def connect_to_snowflake(
    account: str,
    user: str,
    private_key: bytes,
    role: str | None = None,
) -> snowflake.connector.SnowflakeConnection:
    connection_options: dict[str, object] = {
        "account": account,
        "user": user,
        "private_key": private_key,
        "authenticator": "SNOWFLAKE_JWT",
        "login_timeout": 60,
    }
    if role:
        connection_options["role"] = role
    return snowflake.connector.connect(**connection_options)


def execute_snowflake(cursor: snowflake.connector.cursor.SnowflakeCursor, sql: str, operation: str) -> None:
    try:
        cursor.execute(sql)
    except snowflake.connector.errors.Error:
        raise RuntimeError(f"Snowflake {operation} failed; SQL text was suppressed.") from None


def get_current_public_key(
    cursor: snowflake.connector.cursor.SnowflakeCursor,
    user: str,
) -> str | None:
    execute_snowflake(cursor, f"DESC USER {quote_identifier(user)}", "user description")
    for row in cursor.fetchall():
        if str(row[0]).upper() == "RSA_PUBLIC_KEY":
            value = row[2] if len(row) > 2 else None
            return str(value) if value else None
    raise RuntimeError("RSA_PUBLIC_KEY was not present in the Snowflake user description.")


def verify_service_login(
    account: str,
    user: str,
    private_key: bytes,
) -> None:
    connection = connect_to_snowflake(account, user, private_key)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT CURRENT_USER()")
            row = cursor.fetchone()
            if not row or str(row[0]).casefold() != user.casefold():
                raise RuntimeError("Snowflake authentication returned an unexpected user.")
    finally:
        connection.close()


def rotate() -> None:
    vault_url = required_env("AZURE_KEY_VAULT_URL")
    account = required_env("SNOWFLAKE_ACCOUNT")
    admin_user = required_env("SNOWFLAKE_ADMIN_USER")
    service_user = required_env("SNOWFLAKE_SERVICE_USER")
    admin_key_secret = required_env("SNOWFLAKE_ADMIN_PRIVATE_KEY_SECRET")
    service_key_secret = required_env("SNOWFLAKE_SERVICE_PRIVATE_KEY_SECRET")
    if admin_user.casefold() == service_user.casefold():
        raise ValueError("The Snowflake rotation identity must differ from the target service user.")

    admin_role = os.environ.get("SNOWFLAKE_ADMIN_ROLE")
    admin_passphrase_secret = os.environ.get("SNOWFLAKE_ADMIN_PRIVATE_KEY_PASSPHRASE_SECRET")
    credential = AzureCliCredential()
    secret_client = SecretClient(vault_url=vault_url, credential=credential)
    admin_connection: snowflake.connector.SnowflakeConnection | None = None

    try:
        admin_pem = secret_client.get_secret(admin_key_secret).value
        if not admin_pem:
            raise RuntimeError("The Snowflake admin private-key secret is empty.")
        admin_passphrase = None
        if admin_passphrase_secret:
            secret_value = secret_client.get_secret(admin_passphrase_secret).value
            if secret_value is None:
                raise RuntimeError("The Snowflake admin private-key passphrase secret is empty.")
            admin_passphrase = secret_value
        admin_private_key = load_private_key(admin_pem, admin_passphrase)

        new_private_pem, new_public_key = generate_key_pair()
        new_private_key = load_private_key(new_private_pem)

        admin_connection = connect_to_snowflake(
            account,
            admin_user,
            admin_private_key,
            admin_role,
        )
        with admin_connection.cursor() as cursor:
            previous_public_key = get_current_public_key(cursor, service_user)
            target_identifier = quote_identifier(service_user)
            execute_snowflake(
                cursor,
                f"ALTER USER {target_identifier} SET RSA_PUBLIC_KEY_2 = {quote_literal(new_public_key)}",
                "staging the secondary public key",
            )

        LOGGER.info("Testing the staged key with the Snowflake service user.")
        verify_service_login(account, service_user, new_private_key)

        secret_version = secret_client.set_secret(service_key_secret, new_private_pem).properties.version
        if not secret_version:
            raise RuntimeError("Azure Key Vault did not return a version for the private-key secret.")
        LOGGER.info("Stored the new private key as Key Vault secret version %s.", secret_version)

        with admin_connection.cursor() as cursor:
            if previous_public_key:
                execute_snowflake(
                    cursor,
                    f"ALTER USER {target_identifier} SET RSA_PUBLIC_KEY = {quote_literal(new_public_key)}, "
                    f"RSA_PUBLIC_KEY_2 = {quote_literal(previous_public_key)}",
                    "promoting the public key",
                )
            else:
                execute_snowflake(
                    cursor,
                    f"ALTER USER {target_identifier} SET RSA_PUBLIC_KEY = {quote_literal(new_public_key)}",
                    "promoting the public key",
                )
                execute_snowflake(
                    cursor,
                    f"ALTER USER {target_identifier} UNSET RSA_PUBLIC_KEY_2",
                    "clearing the secondary public key",
                )

        verify_service_login(account, service_user, new_private_key)
        LOGGER.info("RSA key rotation completed and verified for Snowflake user %s.", service_user)
    finally:
        if admin_connection is not None:
            admin_connection.close()
        secret_client.close()
        credential.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    rotate()
