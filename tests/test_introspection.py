"""
Test the introspection module with endpoint tests.
"""

import time

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from demo_project.main import app
from fastapi_zitadel_auth import ZitadelIntrospectionAuth
from fastapi_zitadel_auth.introspection import BasicAuth
from tests.utils import (
    create_introspection_response,
    introspection_url,
    keys_url,
    openid_config_url,
    openid_configuration,
    create_openid_keys,
    ZITADEL_CLIENT_ID,
    ZITADEL_ISSUER,
    ZITADEL_PROJECT_ID,
    ZITADEL_PRIMARY_DOMAIN,
    ZITADEL_API_CLIENT_SECRET,
)

OPAQUE_TOKEN = "VjVxyCZmRmWYqd3_F5db9Pb9mHR5fqzhn_opaque_test_token"


@pytest.mark.asyncio
async def test_valid_token_with_admin_role(fastapi_app_introspection_basic, mock_openid_keys_and_introspection):
    """Test that a valid opaque token with admin role passes introspection."""
    issued_at = int(time.time())
    expires = issued_at + 3600
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["message"] == "Hello world!"
        assert data["user"]["access_token"] == OPAQUE_TOKEN
        assert data["user"]["claims"]["sub"] == "user123"
        assert data["user"]["claims"]["iss"] == ZITADEL_ISSUER
        assert data["user"]["claims"]["client_id"] == ZITADEL_CLIENT_ID
        assert data["user"]["claims"]["username"] == f"user123@{ZITADEL_PRIMARY_DOMAIN}"
        assert data["user"]["claims"]["token_type"] == "Bearer"
        assert "admin" in data["user"]["claims"]["project_roles"]


async def test_inactive_token(fastapi_app_introspection_basic, mock_openid_keys_and_inactive_introspection):
    """Test that an inactive token is rejected."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 401
        assert response.json() == {"detail": {"error": "invalid_token", "message": "Token is not active"}}
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_no_token_provided(fastapi_app_introspection_basic, mock_openid_keys_and_introspection, mocker):
    """Test that when no token is available, it is rejected."""
    mocker.patch.object(ZitadelIntrospectionAuth, "_extract_access_token", return_value=None)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 401
        assert response.json() == {"detail": {"error": "invalid_token", "message": "No access token provided"}}
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_missing_authorization_header(fastapi_app_introspection_basic, mock_openid_keys_and_introspection):
    """Test that a missing Authorization header is rejected."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 401
        assert response.json() == {"detail": "Not authenticated"}
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_normal_user_rejected_from_admin(fastapi_app_introspection_basic, respx_mock, mock_openid):
    """Test that a user without admin role is rejected from the admin endpoint."""
    respx_mock.get(keys_url()).respond(json=create_openid_keys())
    respx_mock.post(introspection_url()).respond(json=create_introspection_response(active=True, role="user"))
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 403
        assert response.json() == {
            "detail": {"error": "insufficient_scope", "message": "User does not have role assigned: admin"}
        }


async def test_missing_required_scope(fastapi_app_introspection_basic, respx_mock, mock_openid):
    """Test that a token without the required scope is rejected."""
    respx_mock.get(keys_url()).respond(json=create_openid_keys())
    respx_mock.post(introspection_url()).respond(
        json=create_introspection_response(active=True, scopes="openid email profile")
    )
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        response = await ac.get("/api/protected/scope")
        assert response.status_code == 403
        assert response.json() == {
            "detail": {"error": "insufficient_scope", "message": "Missing required scope: scope1"}
        }


async def test_introspection_endpoint_returns_401(fastapi_app_introspection_basic, respx_mock, mock_openid):
    """Test that a 401 from the introspection endpoint is handled (bad API credentials)."""
    respx_mock.get(keys_url()).respond(json=create_openid_keys())
    respx_mock.post(introspection_url()).respond(status_code=401)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 503
        assert response.json() == {
            "detail": {"error": "introspection_error", "message": "Introspection endpoint rejected API credentials"}
        }


async def test_introspection_endpoint_returns_500(fastapi_app_introspection_basic, respx_mock, mock_openid):
    """Test that a 500 from the introspection endpoint is handled."""
    respx_mock.get(keys_url()).respond(json=create_openid_keys())
    respx_mock.post(introspection_url()).respond(status_code=500)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 503
        assert response.json() == {
            "detail": {"error": "introspection_error", "message": "Introspection endpoint returned an error"}
        }


async def test_introspection_endpoint_unreachable(fastapi_app_introspection_basic, respx_mock, mock_openid):
    """Test that a connection error to the introspection endpoint is handled."""
    respx_mock.get(keys_url()).respond(json=create_openid_keys())
    respx_mock.post(introspection_url()).mock(side_effect=httpx.ConnectError("Connection refused"))
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 503
        assert response.json() == {
            "detail": {"error": "introspection_error", "message": "Unable to reach introspection endpoint"}
        }


async def test_introspection_endpoint_not_in_config(fastapi_app_introspection_basic, respx_mock):
    """Test that a missing introspection endpoint URL raises an error."""
    config_without_introspection = openid_configuration()
    del config_without_introspection["introspection_endpoint"]
    respx_mock.get(openid_config_url()).respond(json=config_without_introspection)
    respx_mock.get(keys_url()).respond(json=create_openid_keys())

    auth: ZitadelIntrospectionAuth = app.dependency_overrides[
        __import__("demo_project.dependencies", fromlist=["zitadel_auth"]).zitadel_auth
    ]
    auth.openid_config.introspection_endpoint = ""

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 503
        assert response.json() == {
            "detail": {"error": "introspection_error", "message": "Introspection endpoint not available"}
        }


async def test_token_extraction_raises(fastapi_app_introspection_basic, mock_openid_keys_and_introspection, mocker):
    """Test that an exception during token extraction is handled."""
    mocker.patch.object(ZitadelIntrospectionAuth, "_extract_access_token", side_effect=ValueError("oops"))
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 400
        assert response.json() == {
            "detail": {"error": "invalid_request", "message": "Unable to extract token from request"}
        }


async def test_valid_token_with_jwt_profile_auth(
    fastapi_app_introspection_jwt_profile, mock_openid_keys_and_introspection
):
    """Test that introspection works with JWT Profile auth method."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 200
        assert response.json()["user"]["claims"]["sub"] == "user123"


async def test_valid_scope_passes(fastapi_app_introspection_basic, respx_mock, mock_openid):
    """Test that a token with the correct scope passes scope-protected endpoint."""
    respx_mock.get(keys_url()).respond(json=create_openid_keys())
    respx_mock.post(introspection_url()).respond(json=create_introspection_response(active=True, scopes="scope1"))
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        response = await ac.get("/api/protected/scope")
        assert response.status_code == 200


async def test_close_http_client(fastapi_app_introspection_basic, mock_openid_keys_and_introspection):
    """Test that close() properly closes the HTTP client."""
    auth: ZitadelIntrospectionAuth = fastapi_app_introspection_basic
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        await ac.get("/api/protected/admin")

    assert auth._http_client is not None
    await auth.close()
    assert auth._http_client is None


async def test_close_when_no_client():
    """Test that close() is safe when no HTTP client exists."""
    auth = ZitadelIntrospectionAuth(
        issuer_url=ZITADEL_ISSUER,
        app_client_id=ZITADEL_CLIENT_ID,
        project_id=ZITADEL_PROJECT_ID,
        allowed_scopes={"scope1": "Some scope"},
        auth_method=BasicAuth(client_id=ZITADEL_CLIENT_ID, client_secret=ZITADEL_API_CLIENT_SECRET),
    )
    assert auth._http_client is None
    await auth.close()
    assert auth._http_client is None


async def test_close_already_closed_client(fastapi_app_introspection_basic, mock_openid_keys_and_introspection):
    """Test that close() is safe when the HTTP client is already closed."""
    auth: ZitadelIntrospectionAuth = fastapi_app_introspection_basic
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        await ac.get("/api/protected/admin")

    await auth._http_client.aclose()
    await auth.close()
    assert auth._http_client is None


async def test_http_client_recreated_after_close(fastapi_app_introspection_basic, mock_openid_keys_and_introspection):
    """Test that the HTTP client is recreated if it was closed."""
    auth: ZitadelIntrospectionAuth = fastapi_app_introspection_basic

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        await ac.get("/api/protected/admin")

    first_client = auth._http_client
    await first_client.aclose()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {OPAQUE_TOKEN}"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 200

    assert auth._http_client is not first_client
