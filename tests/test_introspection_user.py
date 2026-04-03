"""
Test suite for introspection user models.
"""

import time

import pytest
from pydantic import ValidationError

from fastapi_zitadel_auth.user import (
    IntrospectionClaims,
    DefaultZitadelIntrospectionClaims,
    DefaultZitadelIntrospectionUser,
)
from tests.utils import ZITADEL_ISSUER, ZITADEL_PRIMARY_DOMAIN, ZITADEL_CLIENT_ID, ZITADEL_PROJECT_ID

role_key = "role1"
role_id = "295621089671959405"
sub = "22222222222222222222"


@pytest.fixture
def valid_introspection_data() -> dict:
    """Fixture providing valid introspection response data."""
    now = int(time.time())
    return {
        "aud": [ZITADEL_PROJECT_ID],
        "client_id": ZITADEL_CLIENT_ID,
        "exp": now + 3600,
        "iat": now,
        "iss": ZITADEL_ISSUER,
        "sub": sub,
        "nbf": now,
        "jti": "unique-token-id",
        "scope": "openid profile email",
        "token_type": "Bearer",
        "username": f"user@{ZITADEL_PRIMARY_DOMAIN}",
    }


@pytest.fixture
def introspection_data_with_roles(valid_introspection_data):
    """Fixture providing introspection data with project roles."""
    data = valid_introspection_data.copy()
    data[f"urn:zitadel:iam:org:project:{ZITADEL_PROJECT_ID}:roles"] = {role_key: {role_id: ZITADEL_PRIMARY_DOMAIN}}
    return data


class TestIntrospectionClaims:
    """Test suite for IntrospectionClaims model."""

    def test_valid_claims(self, valid_introspection_data):
        """Test creation with all fields."""
        claims = IntrospectionClaims(**valid_introspection_data)
        assert claims.scope == "openid profile email"
        assert claims.token_type == "Bearer"
        assert claims.username == f"user@{ZITADEL_PRIMARY_DOMAIN}"
        assert claims.sub == sub

    def test_optional_introspection_fields(self):
        """Test that introspection-specific fields are optional."""
        now = int(time.time())
        minimal = {
            "aud": [ZITADEL_PROJECT_ID],
            "client_id": ZITADEL_CLIENT_ID,
            "exp": now + 3600,
            "iat": now,
            "iss": ZITADEL_ISSUER,
            "sub": sub,
        }
        claims = IntrospectionClaims(**minimal)
        assert claims.scope is None
        assert claims.token_type is None
        assert claims.username is None

    def test_required_fields(self, valid_introspection_data):
        """Test that base required fields must be present."""
        required_fields = ["aud", "client_id", "exp", "iat", "iss", "sub"]
        for field in required_fields:
            invalid = valid_introspection_data.copy()
            del invalid[field]
            with pytest.raises(ValidationError, match=f"1 validation error for IntrospectionClaims\n{field}\n  Field required"):
                IntrospectionClaims(**invalid)


class TestDefaultZitadelIntrospectionClaims:
    """Test suite for DefaultZitadelIntrospectionClaims model."""

    def test_project_roles_extraction(self, introspection_data_with_roles):
        """Test extraction of project roles from Zitadel-specific claim."""
        claims = DefaultZitadelIntrospectionClaims(**introspection_data_with_roles)
        assert claims.project_roles == {role_key: {role_id: ZITADEL_PRIMARY_DOMAIN}}
        assert claims.scope == "openid profile email"

    def test_missing_project_roles(self, valid_introspection_data):
        """Test handling of missing project roles."""
        claims = DefaultZitadelIntrospectionClaims(**valid_introspection_data)
        assert claims.project_roles == {}


class TestDefaultZitadelIntrospectionUser:
    """Test suite for DefaultZitadelIntrospectionUser model."""

    def test_valid_user_creation(self, introspection_data_with_roles):
        """Test creation of valid introspection user."""
        claims = DefaultZitadelIntrospectionClaims(**introspection_data_with_roles)
        user = DefaultZitadelIntrospectionUser(claims=claims, access_token="opaque-token")
        assert isinstance(user.claims, DefaultZitadelIntrospectionClaims)
        assert user.access_token == "opaque-token"
        assert user.claims.username == f"user@{ZITADEL_PRIMARY_DOMAIN}"
        assert user.claims.project_roles == {role_key: {role_id: ZITADEL_PRIMARY_DOMAIN}}
