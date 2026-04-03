"""
Token introspection module for Zitadel OAuth2 (RFC 7662)

Validates opaque (and JWT) tokens by calling Zitadel's introspection endpoint.
Supports Basic Auth and JWT Profile authentication methods.
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Type

import httpx
import jwt
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer, SecurityScopes
from fastapi.security.base import SecurityBase
from pydantic import HttpUrl
from starlette.requests import Request

from .exceptions import ForbiddenException, IntrospectionException, InvalidRequestException, UnauthorizedException
from .openid_config import OpenIdConfig
from .token import TokenValidator
from .user import (
    BaseZitadelUser,
    DefaultZitadelIntrospectionClaims,
    DefaultZitadelIntrospectionUser,
    IntrospectionClaims,
    IntrospectionClaimsT,
    UserT,
)

log = logging.getLogger("fastapi_zitadel_auth")

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class IntrospectionAuthMethod(ABC):
    """Abstract base for introspection endpoint authentication strategies."""

    @abstractmethod
    def build_request_params(self, token: str) -> dict[str, Any]:
        """Build keyword arguments for the httpx introspection POST request.

        :param token: The access token to introspect
        :returns: dict of kwargs to pass to httpx.AsyncClient.post()
        """


class BasicAuth(IntrospectionAuthMethod):
    """Authenticate to the introspection endpoint using HTTP Basic (client_secret_basic)."""

    def __init__(self, client_id: str, client_secret: str) -> None:
        if not client_id or not client_secret:
            raise ValueError("client_id and client_secret must be non-empty strings")
        self._client_id = client_id
        self._client_secret = client_secret

    def build_request_params(self, token: str) -> dict[str, Any]:
        return {"data": {"token": token}, "auth": (self._client_id, self._client_secret)}


class JwtProfileAuth(IntrospectionAuthMethod):
    """Authenticate to the introspection endpoint using Private Key JWT (jwt-bearer)."""

    def __init__(self, key_file: dict[str, str]) -> None:
        """
        :param key_file: Zitadel JSON key file contents with keys: keyId, key, clientId, appId, type
        """
        required_fields = {"keyId", "key", "clientId"}
        missing = required_fields - key_file.keys()
        if missing:
            raise ValueError(f"key_file is missing required fields: {', '.join(sorted(missing))}")
        self._key_id: str = key_file["keyId"]
        self._private_key: str = key_file["key"]
        self._client_id: str = key_file["clientId"]

    def build_request_params(self, token: str, issuer_url: str = "") -> dict[str, Any]:
        now = int(time.time())
        payload = {"iss": self._client_id, "sub": self._client_id, "aud": issuer_url, "exp": now + 3600, "iat": now}
        headers = {"alg": "RS256", "kid": self._key_id}
        client_assertion = jwt.encode(payload, self._private_key, algorithm="RS256", headers=headers)
        return {
            "data": {
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": client_assertion,
                "token": token,
            }
        }


class ZitadelIntrospectionAuth(SecurityBase):
    """
    Zitadel OAuth2 authentication using token introspection (RFC 7662).

    Validates opaque (and JWT) tokens by calling the introspection endpoint.
    """

    def __init__(
        self,
        issuer_url: HttpUrl | str,
        project_id: str,
        app_client_id: str,
        allowed_scopes: dict[str, str],
        auth_method: IntrospectionAuthMethod,
        cache_ttl_seconds: int = 600,
        claims_model: Type[IntrospectionClaimsT] = DefaultZitadelIntrospectionClaims,  # type: ignore
        user_model: Type[UserT] = DefaultZitadelIntrospectionUser,  # type: ignore
        scheme_name: str = "ZitadelAuthorizationCodeBearer",
        description: str = "Zitadel OAuth2 authentication using token introspection",
    ) -> None:
        """
        Initialize the ZitadelIntrospectionAuth object.

        :param issuer_url: HttpUrl | str
            The Zitadel issuer URL

        :param project_id: str
            The Zitadel project ID

        :param app_client_id: str
            The Zitadel application client ID

        :param allowed_scopes: dict[str, str]
            The allowed scopes for the application. Key is the scope name and value is the description.

        :param auth_method: IntrospectionAuthMethod
            The authentication method for the introspection endpoint (BasicAuth or JwtProfileAuth).

        :param cache_ttl_seconds: int
            The time in seconds to cache the OpenID configuration

        :param claims_model: Type[IntrospectionClaimsT]
            The claims model to use, e.g. DefaultZitadelIntrospectionClaims. See user.py

        :param user_model: Type[UserT]
            The user model to use, e.g. DefaultZitadelIntrospectionUser. See user.py

        :param scheme_name: str
            The name of the security scheme for OpenAPI documentation.

        :param description: str
            The description of the security scheme for OpenAPI documentation.
        """
        self.client_id = app_client_id
        self.project_id = project_id
        self.issuer_url = str(issuer_url).rstrip("/")

        if not isinstance(auth_method, IntrospectionAuthMethod):
            raise ValueError("auth_method must be an instance of IntrospectionAuthMethod")

        if not issubclass(claims_model, IntrospectionClaims):
            raise ValueError("claims_model must be a subclass of IntrospectionClaims")

        if not issubclass(user_model, BaseZitadelUser):
            raise ValueError("user_model must be a subclass of BaseZitadelUser")

        if not isinstance(scheme_name, str) or not scheme_name.strip():
            raise ValueError("scheme_name must be a non-empty string")

        if not isinstance(description, str) or not description.strip():
            raise ValueError("description must be a non-empty string")

        self.auth_method = auth_method
        self.claims_model = claims_model
        self.user_model = user_model

        self.openid_config = OpenIdConfig(
            issuer_url=self.issuer_url,
            config_url=f"{self.issuer_url}/.well-known/openid-configuration",
            authorization_url=f"{self.issuer_url}/oauth/v2/authorize",
            token_url=f"{self.issuer_url}/oauth/v2/token",
            introspection_endpoint=f"{self.issuer_url}/oauth/v2/introspect",
            jwks_uri=f"{self.issuer_url}/oauth/v2/keys",
            cache_ttl_seconds=cache_ttl_seconds,
        )

        self.oauth = OAuth2AuthorizationCodeBearer(
            authorizationUrl=self.openid_config.authorization_url,
            tokenUrl=self.openid_config.token_url,
            scopes=allowed_scopes,
            scheme_name=scheme_name,
            description=description,
        )

        self._http_client: httpx.AsyncClient | None = None
        self.model = self.oauth.model
        self.scheme_name = self.oauth.scheme_name

    async def __call__(self, request: Request, security_scopes: SecurityScopes) -> UserT | None:
        """
        Validate the token via Zitadel's introspection endpoint.
        see also FastAPI -> "Advanced Dependency".
        """
        try:
            access_token = await self._extract_access_token(request)
            if access_token is None:
                raise UnauthorizedException("No access token provided")

            await self.openid_config.load_config()
            introspection_response = await self._introspect_token(access_token)

            if not introspection_response.get("active"):
                log.info("Token introspection returned active=false")
                raise UnauthorizedException("Token is not active")

            TokenValidator.validate_scopes(introspection_response, security_scopes.scopes)

            user: UserT = self.user_model(  # type: ignore
                claims=self.claims_model.model_validate(introspection_response),
                access_token=access_token,
            )
            request.state.user = user
            return user

        except (UnauthorizedException, InvalidRequestException, ForbiddenException, IntrospectionException, HTTPException):
            raise

        except Exception as error:
            log.warning(f"Unable to extract token from request. Error: {error}")
            raise InvalidRequestException("Unable to extract token from request") from error

    async def _introspect_token(self, token: str) -> dict[str, Any]:
        """Call the introspection endpoint to validate the token."""
        introspection_url = self.openid_config.introspection_endpoint
        if not introspection_url:
            log.error("Introspection endpoint not available in OpenID configuration")
            raise IntrospectionException("Introspection endpoint not available")

        if isinstance(self.auth_method, JwtProfileAuth):
            request_params = self.auth_method.build_request_params(token, issuer_url=self.openid_config.issuer_url)
        else:
            request_params = self.auth_method.build_request_params(token)

        try:
            client = self._get_http_client()
            response = await client.post(introspection_url, **request_params)
        except Exception as error:
            log.exception(f"Introspection request failed: {error}")
            raise IntrospectionException("Unable to reach introspection endpoint") from error

        if response.status_code == 401:
            log.error("Introspection endpoint returned 401 — API credentials are invalid")
            raise IntrospectionException("Introspection endpoint rejected API credentials")

        if response.status_code != 200:
            try:
                error_body = response.json()
            except Exception:
                error_body = response.text[:500]
            log.error("Introspection endpoint returned HTTP %s: %s", response.status_code, error_body)
            error_detail = error_body.get("error", "") if isinstance(error_body, dict) else str(error_body)
            error_desc = error_body.get("error_description", "") if isinstance(error_body, dict) else ""
            msg = f"Introspection endpoint returned HTTP {response.status_code}"
            if error_detail:
                msg += f": {error_detail}"
            if error_desc:
                msg += f" — {error_desc}"
            raise IntrospectionException(msg)

        return response.json()

    async def _extract_access_token(self, request: Request) -> str | None:
        """Extract the access token from the request."""
        return await self.oauth(request=request)

    def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create a persistent httpx client for introspection calls."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=10, http2=True)
        return self._http_client

    async def close(self) -> None:
        """Close the persistent HTTP client. Call during application shutdown."""
        if self._http_client is not None:
            if not self._http_client.is_closed:
                await self._http_client.aclose()
            self._http_client = None
