import base64
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rotate_snowflake_rsa_key import (
    generate_key_pair,
    load_private_key,
    quote_identifier,
    quote_literal,
    connect_to_snowflake,
)


class KeyRotationHelperTests(unittest.TestCase):
    def test_quote_identifier_escapes_embedded_quotes(self) -> None:
        self.assertEqual(quote_identifier('svc"user'), '"svc""user"')

    def test_quote_literal_escapes_embedded_quotes(self) -> None:
        self.assertEqual(quote_literal("key'value"), "'key''value'")

    def test_generated_key_pair_matches_snowflake_public_key_encoding(self) -> None:
        private_pem, public_key_value = generate_key_pair()
        private_key_der = load_private_key(private_pem)
        private_key = serialization.load_der_private_key(private_key_der, password=None)
        expected_public_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        self.assertEqual(base64.b64decode(public_key_value), expected_public_der)
        self.assertTrue(private_pem.startswith("-----BEGIN PRIVATE KEY-----"))

    @patch("rotate_snowflake_rsa_key.snowflake.connector.connect")
    def test_admin_connection_uses_rsa_authentication(self, connect) -> None:
        connect_to_snowflake("account", "rotation_user", b"private-key", "ROTATION_ROLE")

        connect.assert_called_once_with(
            account="account",
            user="rotation_user",
            private_key=b"private-key",
            authenticator="SNOWFLAKE_JWT",
            login_timeout=60,
            role="ROTATION_ROLE",
        )


if __name__ == "__main__":
    unittest.main()
