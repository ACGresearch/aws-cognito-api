# MIT License
#
# Copyright (c) 2024 ACG Business Analytics
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import json
import re
from base64 import b64decode
from contextlib import contextmanager
from os import environ
from typing import Iterator, Self

import boto3
from botocore.exceptions import ClientError
from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from mangum import Mangum
from pydantic import BaseModel, EmailStr, model_validator
from starlette.responses import Response
from starlette.status import HTTP_403_FORBIDDEN, HTTP_422_UNPROCESSABLE_ENTITY

# Initialize Sentry
if (SENTRY_DSN := environ.get("SENTRY_DSN", None)) is not None:
    import sentry_sdk
    from sentry_sdk.integrations.aws_lambda import AwsLambdaIntegration

    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[AwsLambdaIntegration(timeout_warning=True)],
        traces_sample_rate=environ.get("SENTRY_TRACES_SAMPLE_RATE", 1.0),
        profiles_sample_rate=environ.get("SENTRY_PROFILES_SAMPLE_RATE", 1.0),
    )


# Scope required for self-management
SELF_MANAGEMENT_SCOPE = "aws.cognito.signin.user.admin"


# Cognito Identity Provider issuer URL regex
COGNITO_ISS_REGEX = re.compile(
    r"^https://cognito-idp\.(?P<region>[a-z0-9-]+)\.amazonaws\.com/(?P<user_pool_id>[a-zA-Z0-9_\-]+)$"
)


# Initialize FastAPI
app = FastAPI(title="AWS Cognito API", docs_url="/")


# Initialize Bearer token authentication scheme
http_bearer_scheme = HTTPBearer(auto_error=False)


@contextmanager
def cognito_idp_exception_handler() -> Iterator[None]:
    """Context manager to handle exceptions raised by the Cognito Identity Provider.

    This context manager catches `botocore.exceptions.ClientError` and
    translates them into appropriate HTTP exceptions.

    :raises HTTPException: If the exception is a 'NotAuthorizedException',
        it raises a 403 Forbidden error. For all other exceptions, it raises
        a 422 Unprocessable Entity error.

    Example usage:

    .. code-block:: python

        with cognito_idp_exception_handler():
            response = client.method()

    All exceptions raised by the Cognito Identity Provider client within
    the context will be caught and handled appropriately.

    Note that this context manager is specific to the Cognito Identity Provider
    and will not catch exceptions from other AWS services.

    :return: None
    """
    try:
        yield
    except ClientError as e:
        # Check the error code to determine the appropriate HTTP status code
        # and error message to raise.
        match e.response["Error"]["Code"]:
            case "NotAuthorizedException":
                status_code = HTTP_403_FORBIDDEN
            case _:
                status_code = HTTP_422_UNPROCESSABLE_ENTITY

        raise HTTPException(
            status_code=status_code,
            detail=e.response["Error"]["Message"],
        ) from None


def get_token(
    http_auth_credentials: HTTPAuthorizationCredentials | None = Depends(http_bearer_scheme),
) -> str:
    """Utility function to extract the bearer token from the HTTP Authorization
    header.

    This function is intended to be used with the `Depends` mechanism, for
    example:

    .. code-block:: python

        @app.get("/users/me")
        async def read_user_me(token: str = Depends(get_token))):
            return {"token": token}

    :param http_auth_credentials: The HTTP Authorization credentials.
    :return: The extracted bearer token.
    :raises HTTPException: If the HTTP Authorization credentials are missing.
    """
    # Check if HTTP Authorization credentials are provided
    if http_auth_credentials is None:
        # If not provided, raise an HTTPException with 403 status code
        # This means "Forbidden" - the user is not authenticated
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authenticated")

    # Using the walrus operator (:=) to both assert the type of http_auth_credentials.credentials
    # and assign it to the variable 'credentials'
    assert isinstance(credentials := http_auth_credentials.credentials, str)

    # Return the extracted bearer token
    return credentials


def get_token_claims(access_token: str = Depends(get_token)) -> dict:
    """This function takes an access token as input and returns the claims
    (payload) of the token.

    :returns The claims (payload) of the token.
    :raises HTTPException 403: If the token is invalid.
    """
    try:
        # The access token is a JWT (JSON Web Token) which consists of three
        # parts: header, claims (payload), and signature. Here we're splitting
        # the token into its three parts.
        jwt = access_token.encode("utf-8")
        _, claims_segment, _ = jwt.split(b".", 3)

        # The claims segment may have padding at the end. Here we're adding
        # padding if necessary to ensure that the length is a multiple of 4.
        claims_segment_remainder = len(claims_segment) % 4
        if claims_segment_remainder > 0:
            claims_segment += b"=" * (4 - claims_segment_remainder)

        # The claims segment is base64url encoded. Here we're replacing the
        # characters that are different between base64 and base64url and
        # then decoding it to get the original claims.
        b64encoded_claims_segment = claims_segment.replace(b"-", b"+").replace(b"_", b"/")
        decoded_claims_segment = b64decode(b64encoded_claims_segment).decode("utf-8")

        # The decoded claims segment is a JSON string. Here we're parsing it
        # to get the actual claims (payload) of the token.
        claims = json.loads(decoded_claims_segment)

        # The claims should be a dictionary. If it's not, it means that the
        # token is not valid.
        if not isinstance(claims, dict):
            raise ValueError("claims is not a dict")
    except ValueError:
        # If an error occurs during the above process, it means that the
        # token is not valid. In this case, we're raising an HTTP exception
        # with status code 403 (Forbidden) and a detail message.
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Invalid access token")

    # If everything is successful, we're returning the claims (payload) of
    # the token.
    return claims


def get_token_region(claims: dict = Depends(get_token_claims)) -> str:
    """Returns the region name of the user pool that issued the token.

    This function takes the claims (payload) of a token as input and returns
    the region name of the user pool that issued the token.

    :returns The region name of the user pool that issued the token.
    :raises HTTPException 403: If the token is invalid or the region cannot
        be extracted.
    """
    # The iss claim of the token is the issuer URL of the user pool that
    # issued the token. The URL is in the format
    # https://cognito-idp.<region>.amazonaws.com/<user_pool_id>.
    # Here we're extracting the region name from the URL.
    match = COGNITO_ISS_REGEX.fullmatch(claims["iss"])

    # If the match is None, it means the iss claim is not in the expected format.
    # In this case, we raise an HTTPException with status code 403 (Forbidden)
    # and detail message "Invalid access token".
    if match is None:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Invalid access token")

    # If the match is successful, we return the region name. The region name
    # is captured in the "region" group of the match object.
    return match["region"]


def get_token_scope(claims: dict = Depends(get_token_claims)) -> set[str]:
    """Returns the scope of the token.

    This function takes the claims (payload) of a token as input and returns
    the scope of the token.

    :returns The scope of the token.
    :raises HTTPException 403: If the token is invalid or the scope cannot
        be extracted.
    """
    try:
        scope = claims["scope"]
    except KeyError:
        # If the scope claim is missing, it means the token is not valid.
        # In this case, we raise an HTTPException with status code 403
        # (Forbidden) and detail message "Invalid access token".
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Invalid access token")

    if not isinstance(scope, str):
        # If the scope claim is not a string, it means the token is not valid.
        # In this case, we raise an HTTPException with status code 403
        # (Forbidden) and detail message "Invalid access token".
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Invalid access token")

    # return the scope as a set.
    return set(scope.split(" "))


def has_selfmanagement_scope(scope: set[str] = Depends(get_token_scope)) -> None:
    """Checks if the token has the required self-management scope.

    This function takes the scope of a token as input and checks if the token
    has therequired self-management scope. If the token does not have the
    required self-management scope, it raises an HTTPException with status
    code 403 (Forbidden) and detail message "Not authorized".

    :raises HTTPException 403: Token does not have the self-management scope.
    """
    # Check if the user/admin scope is present in the token scope
    if SELF_MANAGEMENT_SCOPE not in scope:
        # If the user/admin scope is not present, raise an HTTPException
        # with status code 403 (Forbidden) and a detail message
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail=f'Access token is missing "{SELF_MANAGEMENT_SCOPE}" scope',
        )


class PatchUserRequestBody(BaseModel):
    """Request body for the PATCH /user endpoint."""

    previousPassword: str | None = None
    proposedPassword: str | None = None
    name: str | None = None
    email: EmailStr | None = None

    @model_validator(mode="after")
    def check_attribute_combination(self) -> Self:
        if self.proposedPassword is not None:
            if self.previousPassword is None:
                raise ValueError("previous password is required")
            if self.name is not None or self.email is not None:
                raise ValueError("cannot change name or email when changing password")
        else:
            if self.name is None and self.email is None:
                raise ValueError("at least one of name or email is required")
            if self.previousPassword is not None:
                raise ValueError(
                    "previous password should only be specified when changing password"
                )
        return self


@app.patch("/user", status_code=204, dependencies=[Depends(has_selfmanagement_scope)])
async def update_user(
    body: PatchUserRequestBody = Body(),
    access_token: str = Depends(get_token),
    region_name: str = Depends(get_token_region),
) -> Response:
    """Update user attributes.

    This end point updates the user attributes like name, email, and password.
    If the proposedPassword is provided, it will change the user's password.
    If the proposedPassword is not provided, it will update the user's name
    and/or email.
    """
    cognito_idp = boto3.client("cognito-idp", region_name=region_name)
    with cognito_idp_exception_handler():
        # Check if proposed_password is provided
        if body.proposedPassword is not None:
            # If proposed_password is provided, change the user's password
            cognito_idp.change_password(
                PreviousPassword=body.previousPassword,
                ProposedPassword=body.proposedPassword,
                AccessToken=access_token,
            )
        else:
            # If proposed_password is not provided, update user's name and/or email
            user_attributes = []
            if body.name is not None:
                # If new_name is provided, add it to the user_attributes list
                user_attributes.append({"Name": "name", "Value": body.name})
            if body.email is not None:
                # If new_email is provided, add it to the user_attributes list
                user_attributes.append({"Name": "email", "Value": body.email})
            # Update the user attributes
            cognito_idp.update_user_attributes(
                UserAttributes=user_attributes,
                AccessToken=access_token,
            )

    # Return a response with status code 204 (No Content) on success
    return Response(status_code=204)


class PostConfirmRequestBody(BaseModel):
    """Request body for the POST /user/confirm endpoint."""

    confirmationCode: str


@app.post("/user/confirm", status_code=204, dependencies=[Depends(has_selfmanagement_scope)])
async def verify_user_attribute_email(
    body: PostConfirmRequestBody,
    access_token: str = Depends(get_token),
    region_name: str = Depends(get_token_region),
) -> Response:
    """Verifies the user's email attribute in Amazon Cognito User Pools."""
    # Create a client for Amazon Cognito User Pools
    cognito_idp = boto3.client("cognito-idp", region_name=region_name)

    # Use the client to verify the user's email attribute
    # The verification code is obtained from the request body
    # The access token is used for authentication
    with cognito_idp_exception_handler():
        cognito_idp.verify_user_attribute(
            AttributeName="email",
            Code=body.confirmationCode,
            AccessToken=access_token,
        )

    # Return a response with a status code of 204 (no content)
    return Response(status_code=204)


# Setup lambda handler
lambda_handler = Mangum(app, lifespan="off")

if __name__ == "__main__":
    # noinspection PyPackageRequirements
    import uvicorn

    uvicorn.run(app)
