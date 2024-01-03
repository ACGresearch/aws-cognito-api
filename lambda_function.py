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
from contextlib import contextmanager
from os import environ
from typing import Self

import boto3
from botocore.exceptions import ClientError
from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from mangum import Mangum
from pydantic import BaseModel, EmailStr, model_validator
from starlette.responses import Response
from starlette.status import HTTP_403_FORBIDDEN, HTTP_422_UNPROCESSABLE_ENTITY

REGION = environ["REGION"]
CLIENT_ID = environ["CLIENT_ID"]


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

# Initialize Amazon Cognito User Pools
cognito_idp = boto3.client("cognito-idp", region_name=REGION)

# Initialize FastAPI
app = FastAPI(
    title="AWS Cognito API",
    docs_url="/",
)

http_bearer_scheme = HTTPBearer(auto_error=False)


@contextmanager
def cognito_idp_exception_handler():
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


class PatchUserRequestBody(BaseModel):
    previous_password: str | None = None
    proposed_password: str | None = None
    new_name: str | None = None
    new_email: EmailStr | None = None

    @model_validator(mode="after")
    def check_attribute_combination(self) -> Self:
        if self.proposed_password is not None:
            if self.previous_password is None:
                raise ValueError("previous password is required")
            if self.new_name is not None or self.new_email is not None:
                raise ValueError("cannot change name or email when changing password")
        else:
            if self.new_name is None and self.new_email is None:
                raise ValueError("at least one of name or email is required")
            if self.previous_password is not None:
                raise ValueError(
                    "previous password should only be specified when changing password"
                )
        return self


@app.patch("/user", status_code=204)
async def update_user(body: PatchUserRequestBody = Body(), access_token: str = Depends(get_token)):
    """Update user attributes.

    This end point updates the user attributes like name, email, and password.
    If the proposed_password is provided, it will change the user's password.
    If the proposed_password is not provided, it will update the user's name
    and/or email.
    """
    with cognito_idp_exception_handler():
        # Check if proposed_password is provided
        if body.proposed_password is not None:
            # If proposed_password is provided, change the user's password
            cognito_idp.change_password(
                PreviousPassword=body.previous_password,
                ProposedPassword=body.proposed_password,
                AccessToken=access_token,
            )
        else:
            # If proposed_password is not provided, update user's name and/or email
            user_attributes = []
            if body.new_name is not None:
                # If new_name is provided, add it to the user_attributes list
                user_attributes.append({"Name": "name", "Value": body.new_name})
            if body.new_email is not None:
                # If new_email is provided, add it to the user_attributes list
                user_attributes.append({"Name": "email", "Value": body.new_email})
            # Update the user attributes
            cognito_idp.update_user_attributes(
                UserAttributes=user_attributes,
                AccessToken=access_token,
            )

    # Return a response with status code 204 (No Content) on success
    return Response(status_code=204)


class PostConfirmRequestBody(BaseModel):
    confirmation_code: str


@app.post("/user/confirm", status_code=204)
async def verify_user_attribute_email(
    code: PostConfirmRequestBody,
    access_token: str = Depends(get_token),
):
    """Verifies the user's email attribute in Amazon Cognito User Pools."""
    with cognito_idp_exception_handler():
        cognito_idp.verify_user_attribute(
            AttributeName="email",
            Code=code.confirmation_code,
            AccessToken=access_token,
        )

    return Response(status_code=204)


# Setup lambda handler
lambda_handler = Mangum(app, lifespan="off")

if __name__ == "__main__":
    # noinspection PyPackageRequirements
    import uvicorn

    uvicorn.run(app)
