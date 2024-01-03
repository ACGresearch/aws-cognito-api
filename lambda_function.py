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

from os import environ

import boto3
from botocore.exceptions import ClientError
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from mangum import Mangum
from pydantic import BaseModel, EmailStr
from starlette.status import HTTP_403_FORBIDDEN

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
app = FastAPI()


class LoginRequestBody(BaseModel):
    email: EmailStr
    password: str


http_bearer_scheme = HTTPBearer(auto_error=False)


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


class PasswordChangeRequestBody(BaseModel):
    previous_password: str
    proposed_password: str


def password_change(
    body: PasswordChangeRequestBody,
    access_token: str = Depends(get_token),
):
    """
    Changes the user's password using Amazon Cognito User Pools.

    Parameters:
    - `body`: An instance of the PasswordChangeRequestBody class containing previous and proposed passwords.

    Returns:
    - The HTTP status code indicating the result of the password change.
    - A dictionary with an "error" key containing an error message if password change fails.
    """
    try:
        response = cognito_idp.change_password(
            PreviousPassword=body.previous_password,
            ProposedPassword=body.proposed_password,
            AccessToken=access_token,
        )

    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidPasswordException":
            return {"error": e.response["Error"]["Message"]}
        raise

    return response["ResponseMetadata"]["HTTPStatusCode"]


class UpdateNameRequestBody:
    new_name: str


def update_user_attribute_name(
    update_name: UpdateNameRequestBody,
    access_token: str = Depends(get_token),
):
    """
    Updates the user's name attribute in Amazon Cognito User Pools.

    Parameters:
    - `update_name`: An instance of the UpdateNameRequestBody class containing the new name.

    Returns:
    - The HTTP status code indicating the result of the name update.
    - A dictionary with an "error" key containing an error message if the update fails.
    """
    try:
        response = cognito_idp.update_user_attributes(
            UserAttributes=[
                {"Name": "name", "Value": update_name.new_name},
            ],
            AccessToken=access_token,
        )

    except ClientError as e:
        return {"error": str(e)}

    return response["ResponseMetadata"]["HTTPStatusCode"]


class UpdateEmailRequestBody:
    new_email: str


def update_user_attribute_email(
    update_email: UpdateEmailRequestBody,
    access_token: str = Depends(get_token),
):
    """
    Updates the user's email attribute in Amazon Cognito User Pools.

    Parameters:
    - `update_email`: An instance of the UpdateEmailRequestBody class containing the new email.

    Returns:
    - The HTTP status code indicating the result of the email update.
    - A dictionary with an "error" key containing an error message if the update fails.
    """

    try:
        response = cognito_idp.update_user_attributes(
            UserAttributes=[
                {"Name": "email", "Value": update_email.new_email},
            ],
            AccessToken=access_token,
        )

    except ClientError as e:
        return {"error": str(e)}

    return response["ResponseMetadata"]["HTTPStatusCode"]


class VerifyUserAttribute:
    confirmation_code: str


def verify_user_attribute_email(
    code: VerifyUserAttribute,
    access_token: str = Depends(get_token),
):
    """
    Verifies the user's email attribute in Amazon Cognito User Pools.

    Parameters:
    - `code`: An instance of the VerifyUserAttribute class containing the confirmation code.

    Returns:
    - The HTTP status code indicating the result of the email verification.
    - A dictionary with an "error" key containing an error message if the verification fails.
    """
    try:
        response = cognito_idp.verify_user_attribute(
            AttributeName="email",
            Code=code.confirmation_code,
            AccessToken=access_token,
        )

    except ClientError as e:
        return {"error": str(e)}

    return response["ResponseMetadata"]["HTTPStatusCode"]


lambda_handler = Mangum(app, lifespan="off")

if __name__ == "__main__":
    # noinspection PyPackageRequirements
    import uvicorn

    uvicorn.run(app)
