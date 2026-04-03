"""
FastAPI Zitadel Auth
"""

from importlib.metadata import version

from fastapi_zitadel_auth.auth import ZitadelAuth
from fastapi_zitadel_auth.introspection import ZitadelIntrospectionAuth

__version__ = version("fastapi-zitadel-auth")

__all__ = ["ZitadelAuth", "ZitadelIntrospectionAuth", "__version__"]
