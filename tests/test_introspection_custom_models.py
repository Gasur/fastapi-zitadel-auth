"""
Test suite for ZitadelIntrospectionAuth initialization and custom model validation.
"""

import pytest
from pydantic import BaseModel

from fastapi_zitadel_auth import ZitadelIntrospectionAuth
from fastapi_zitadel_auth.introspection import BasicAuth
from fastapi_zitadel_auth.user import (
    BaseZitadelUser,
    IntrospectionClaims,
    DefaultZitadelIntrospectionClaims,
    DefaultZitadelIntrospectionUser,
)
from tests.utils import ZITADEL_ISSUER, ZITADEL_CLIENT_ID, ZITADEL_API_CLIENT_SECRET

DEFAULT_AUTH_METHOD = BasicAuth(client_id=ZITADEL_CLIENT_ID, client_secret=ZITADEL_API_CLIENT_SECRET)


class CustomIntrospectionClaims(IntrospectionClaims):
    """Custom claims with additional fields."""

    custom_field: str
    role: str


class CustomIntrospectionUser(BaseZitadelUser):
    """Custom user type."""

    username: str


class InvalidClaims(BaseModel):
    """Claims that don't extend IntrospectionClaims."""

    some_field: str


class InvalidUser(BaseModel):
    """User that doesn't extend BaseZitadelUser."""

    some_field: str


class TestZitadelIntrospectionAuthInit:
    """Test initialization and validation of ZitadelIntrospectionAuth."""

    def test_default_initialization(self):
        """Test initialization with default models."""
        auth = ZitadelIntrospectionAuth(
            issuer_url=ZITADEL_ISSUER,
            project_id="project_id",
            app_client_id=ZITADEL_CLIENT_ID,
            allowed_scopes={"openid": "OpenID Connect"},
            auth_method=DEFAULT_AUTH_METHOD,
        )
        assert auth.claims_model == DefaultZitadelIntrospectionClaims
        assert auth.user_model == DefaultZitadelIntrospectionUser
        assert auth.client_id == ZITADEL_CLIENT_ID
        assert auth.project_id == "project_id"

    def test_custom_models(self):
        """Test initialization with custom claims and user models."""
        auth = ZitadelIntrospectionAuth(
            issuer_url=ZITADEL_ISSUER,
            project_id="project_id",
            app_client_id=ZITADEL_CLIENT_ID,
            allowed_scopes={"openid": "OpenID Connect"},
            auth_method=DEFAULT_AUTH_METHOD,
            claims_model=CustomIntrospectionClaims,
            user_model=CustomIntrospectionUser,
        )
        assert auth.claims_model == CustomIntrospectionClaims
        assert auth.user_model == CustomIntrospectionUser

    def test_invalid_claims_model(self):
        """Test that non-IntrospectionClaims subclass is rejected."""
        with pytest.raises(ValueError, match="claims_model must be a subclass of IntrospectionClaims"):
            ZitadelIntrospectionAuth(
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id=ZITADEL_CLIENT_ID,
                allowed_scopes={"openid": "OpenID Connect"},
                auth_method=DEFAULT_AUTH_METHOD,
                claims_model=InvalidClaims,  # type: ignore
            )

    def test_invalid_user_model(self):
        """Test that non-BaseZitadelUser subclass is rejected."""
        with pytest.raises(ValueError, match="user_model must be a subclass of BaseZitadelUser"):
            ZitadelIntrospectionAuth(
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id=ZITADEL_CLIENT_ID,
                allowed_scopes={"openid": "OpenID Connect"},
                auth_method=DEFAULT_AUTH_METHOD,
                user_model=InvalidUser,  # type: ignore
            )

    def test_invalid_auth_method(self):
        """Test that non-IntrospectionAuthMethod is rejected."""
        with pytest.raises(ValueError, match="auth_method must be an instance of IntrospectionAuthMethod"):
            ZitadelIntrospectionAuth(
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id=ZITADEL_CLIENT_ID,
                allowed_scopes={"openid": "OpenID Connect"},
                auth_method="not-a-method",  # type: ignore
            )

    def test_empty_scheme_name(self):
        """Test that empty scheme_name is rejected."""
        with pytest.raises(ValueError, match="scheme_name must be a non-empty string"):
            ZitadelIntrospectionAuth(
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id=ZITADEL_CLIENT_ID,
                allowed_scopes={"openid": "OpenID Connect"},
                auth_method=DEFAULT_AUTH_METHOD,
                scheme_name="",
            )

    def test_whitespace_scheme_name(self):
        """Test that whitespace-only scheme_name is rejected."""
        with pytest.raises(ValueError, match="scheme_name must be a non-empty string"):
            ZitadelIntrospectionAuth(
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id=ZITADEL_CLIENT_ID,
                allowed_scopes={"openid": "OpenID Connect"},
                auth_method=DEFAULT_AUTH_METHOD,
                scheme_name="   ",
            )

    def test_empty_description(self):
        """Test that empty description is rejected."""
        with pytest.raises(ValueError, match="description must be a non-empty string"):
            ZitadelIntrospectionAuth(
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id=ZITADEL_CLIENT_ID,
                allowed_scopes={"openid": "OpenID Connect"},
                auth_method=DEFAULT_AUTH_METHOD,
                description="",
            )

    def test_whitespace_description(self):
        """Test that whitespace-only description is rejected."""
        with pytest.raises(ValueError, match="description must be a non-empty string"):
            ZitadelIntrospectionAuth(
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id=ZITADEL_CLIENT_ID,
                allowed_scopes={"openid": "OpenID Connect"},
                auth_method=DEFAULT_AUTH_METHOD,
                description="   ",
            )

    def test_custom_scheme_name_and_description(self):
        """Test initialization with custom scheme_name and description."""
        auth = ZitadelIntrospectionAuth(
            issuer_url=ZITADEL_ISSUER,
            project_id="project_id",
            app_client_id=ZITADEL_CLIENT_ID,
            allowed_scopes={"openid": "OpenID Connect"},
            auth_method=DEFAULT_AUTH_METHOD,
            scheme_name="CustomIntrospectionScheme",
            description="Custom introspection description",
        )
        assert auth.scheme_name == "CustomIntrospectionScheme"

    def test_openid_config_has_introspection_endpoint(self):
        """Test that the OpenID config is initialized with an introspection endpoint."""
        auth = ZitadelIntrospectionAuth(
            issuer_url=ZITADEL_ISSUER,
            project_id="project_id",
            app_client_id=ZITADEL_CLIENT_ID,
            allowed_scopes={"openid": "OpenID Connect"},
            auth_method=DEFAULT_AUTH_METHOD,
        )
        assert auth.openid_config.introspection_endpoint == f"{ZITADEL_ISSUER}/oauth/v2/introspect"

    def test_issuer_url_trailing_slash_stripped(self):
        """Test that trailing slash is stripped from issuer URL."""
        auth = ZitadelIntrospectionAuth(
            issuer_url=f"{ZITADEL_ISSUER}/",
            project_id="project_id",
            app_client_id=ZITADEL_CLIENT_ID,
            allowed_scopes={"openid": "OpenID Connect"},
            auth_method=DEFAULT_AUTH_METHOD,
        )
        assert auth.issuer_url == ZITADEL_ISSUER
