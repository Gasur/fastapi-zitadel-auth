"""
Test suite for introspection authentication methods.
"""

import time

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from fastapi_zitadel_auth.introspection import BasicAuth, JwtProfileAuth, CLIENT_ASSERTION_TYPE
from tests.utils import ZITADEL_CLIENT_ID, ZITADEL_API_CLIENT_SECRET, ZITADEL_ISSUER, jwt_profile_key_file


class TestBasicAuth:
    """Test suite for BasicAuth introspection method."""

    def test_valid_initialization(self):
        """Test that BasicAuth initializes with valid credentials."""
        auth = BasicAuth(client_id=ZITADEL_CLIENT_ID, client_secret=ZITADEL_API_CLIENT_SECRET)
        assert auth._client_id == ZITADEL_CLIENT_ID
        assert auth._client_secret == ZITADEL_API_CLIENT_SECRET

    @pytest.mark.parametrize(
        "client_id,client_secret",
        [
            ("", "secret"),
            ("client", ""),
            ("", ""),
        ],
        ids=["empty_client_id", "empty_client_secret", "both_empty"],
    )
    def test_invalid_initialization(self, client_id, client_secret):
        """Test that BasicAuth rejects empty credentials."""
        with pytest.raises(ValueError, match="client_id and client_secret must be non-empty strings"):
            BasicAuth(client_id=client_id, client_secret=client_secret)

    def test_build_request_params(self):
        """Test that BasicAuth builds correct request params."""
        auth = BasicAuth(client_id="my-client", client_secret="my-secret")
        params = auth.build_request_params("opaque-test-token")

        assert params["data"] == {"token": "opaque-test-token"}
        assert params["auth"] == ("my-client", "my-secret")


class TestJwtProfileAuth:
    """Test suite for JwtProfileAuth introspection method."""

    def test_valid_initialization(self):
        """Test that JwtProfileAuth initializes with valid key file."""
        auth = JwtProfileAuth(key_file=jwt_profile_key_file)
        assert auth._key_id == jwt_profile_key_file["keyId"]
        assert auth._client_id == jwt_profile_key_file["clientId"]
        assert auth._private_key == jwt_profile_key_file["key"]

    @pytest.mark.parametrize(
        "missing_field",
        ["keyId", "key", "clientId"],
    )
    def test_missing_required_field(self, missing_field):
        """Test that JwtProfileAuth rejects key files missing required fields."""
        incomplete = {k: v for k, v in jwt_profile_key_file.items() if k != missing_field}
        with pytest.raises(ValueError, match="key_file is missing required fields"):
            JwtProfileAuth(key_file=incomplete)

    def test_build_request_params(self):
        """Test that JwtProfileAuth builds correct request params with a signed JWT assertion."""
        auth = JwtProfileAuth(key_file=jwt_profile_key_file)
        now = int(time.time())
        params = auth.build_request_params("opaque-test-token", issuer_url=ZITADEL_ISSUER)

        assert params["data"]["token"] == "opaque-test-token"
        assert params["data"]["client_assertion_type"] == CLIENT_ASSERTION_TYPE

        assertion = params["data"]["client_assertion"]
        assert isinstance(assertion, str)

        public_key = rsa.generate_private_key(
            backend=default_backend(), public_exponent=65537, key_size=2048
        ).public_key()

        unverified_header = jwt.get_unverified_header(assertion)
        assert unverified_header["alg"] == "RS256"
        assert unverified_header["kid"] == jwt_profile_key_file["keyId"]

        claims = jwt.decode(assertion, options={"verify_signature": False})
        assert claims["iss"] == jwt_profile_key_file["clientId"]
        assert claims["sub"] == jwt_profile_key_file["clientId"]
        assert claims["aud"] == ZITADEL_ISSUER
        assert claims["iat"] >= now - 2
        assert claims["exp"] >= now + 3500

    def test_build_request_params_default_issuer(self):
        """Test that JwtProfileAuth defaults to empty issuer URL."""
        auth = JwtProfileAuth(key_file=jwt_profile_key_file)
        params = auth.build_request_params("token")
        claims = jwt.decode(params["data"]["client_assertion"], options={"verify_signature": False})
        assert claims["aud"] == ""
