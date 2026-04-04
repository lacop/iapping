from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.requests import Request, HTTPConnection
from starlette.middleware.authentication import (
    AuthenticationMiddleware,
)
from starlette.authentication import (
    AuthenticationError,
    AuthenticationBackend,
    AuthCredentials,
    SimpleUser,
    requires,
)
import jwt
import os


class IapJwtUser(SimpleUser):
    def __init__(self, email: str):
        super().__init__(email)

    @property
    def email(self) -> str:
        return self.username


class IapJwtBackend(AuthenticationBackend):
    def __init__(self, *, jwks_url: str, audience: str):
        self.jwks_client = jwt.PyJWKClient(jwks_url)
        self.audience = audience

    async def authenticate(
        self, conn: HTTPConnection
    ) -> tuple[AuthCredentials, IapJwtUser]:
        # https://docs.cloud.google.com/iap/docs/signed-headers-howto#securing_iap_headers
        token = conn.headers.get("x-goog-iap-jwt-assertion")
        if not token:
            raise AuthenticationError("Missing JWT header")

        try:
            # https://docs.cloud.google.com/iap/docs/signed-headers-howto#verifying_the_jwt_header
            unverified_header = jwt.get_unverified_header(token)
            if unverified_header.get("alg") != "ES256":
                raise AuthenticationError("Invalid JWT algorithm")
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)

            # https://docs.cloud.google.com/iap/docs/signed-headers-howto#verifying_the_jwt_payload
            decoded = jwt.decode(
                token,
                signing_key.key,
                algorithms=["ES256"],
                options={
                    "require": ["aud", "exp", "iat", "iss"],
                    "strict_aud": True,
                    "verify_aud": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_signature": True,
                },
                audience=self.audience,
                issuer="https://cloud.google.com/iap",
                # Thirty seconds recommended by GCP docs.
                leeway=30,
            )

            email = decoded.get("email")
            if not email:
                raise AuthenticationError("JWT missing 'email' claim")
            return AuthCredentials(["authenticated"]), IapJwtUser(email)

        except jwt.exceptions.PyJWTError as e:
            raise AuthenticationError("Invalid JWT: " + str(e)) from e
        except Exception as e:
            print("Authentication error:", e)
            raise AuthenticationError("Authentication failed")
        


def on_auth_error(conn: HTTPConnection, exc: Exception) -> PlainTextResponse:
    print("Authentication error:", exc)
    return PlainTextResponse(f"Unauthorized: {exc}", status_code=401)


def required_env_var(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


IapJwtAuthMiddleware = Middleware(
    AuthenticationMiddleware,
    backend=IapJwtBackend(
        jwks_url=required_env_var("IAP_JWKS_URL"),
        audience=required_env_var("IAP_JWT_AUDIENCE"),
    ),
    on_error=on_auth_error,
)


async def health(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


@requires("authenticated")
async def auth_check(request: Request) -> PlainTextResponse:
    assert request.user.is_authenticated
    assert isinstance(request.user, IapJwtUser)

    return PlainTextResponse(f"ok: {request.user.email}")


app = Starlette(
    debug=True,
    routes=[
        Route("/health", health),
        Route("/auth", auth_check, middleware=[IapJwtAuthMiddleware]),
    ],
)
