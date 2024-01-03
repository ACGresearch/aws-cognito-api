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
from fastapi import FastAPI
from mangum import Mangum
from pydantic import BaseModel, EmailStr

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


def authenticate_user(credentials: LoginRequestBody):
    """
    Authenticates a user using Amazon Cognito User Pools.

    Parameters:
    - `credentials`: An instance of the LoginRequestBody class containing user email and password.

    Returns:
    - A dictionary with tokens upon successful authentication.
    - A dictionary with an "error" key containing an error message if authentication fails.
    """

    try:
        initiate_auth_response = cognito_idp.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": credentials.email,
                "PASSWORD": credentials.password,
            },
            ClientId=CLIENT_ID,
        )

    except ClientError as e:
        if (
            e.response["Error"]["Code"] == "NotAuthorizedException"
            or e.response["Error"]["Code"] == "UserNotFoundException"
        ):
            return {"error": e.response["Error"]["Message"]}
        raise

    return {
        "id_token": initiate_auth_response["AuthenticationResult"]["IdToken"],
        "refresh_token": initiate_auth_response["AuthenticationResult"]["RefreshToken"],
        "access_token": initiate_auth_response["AuthenticationResult"]["AccessToken"],
    }


class PasswordChangeRequestBody(BaseModel):
    previous_password: str
    proposed_password: str


def password_change(credentials: LoginRequestBody, body: PasswordChangeRequestBody):
    """
    Changes the user's password using Amazon Cognito User Pools.

    Parameters:
    - `credentials`: An instance of the LoginRequestBody class containing user email and password.
    - `body`: An instance of the PasswordChangeRequestBody class containing previous and proposed passwords.

    Returns:
    - The HTTP status code indicating the result of the password change.
    - A dictionary with an "error" key containing an error message if password change fails.
    """

    tokens = authenticate_user(credentials)

    try:
        response = cognito_idp.change_password(
            PreviousPassword=body.previous_password,
            ProposedPassword=body.proposed_password,
            AccessToken=tokens["access_token"],
        )

    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidPasswordException":
            return {"error": e.response["Error"]["Message"]}
        raise

    return response["ResponseMetadata"]["HTTPStatusCode"]


class UpdateNameRequestBody:
    new_name: str


def update_user_attribute_name(credentials: LoginRequestBody, update_name: UpdateNameRequestBody):
    """
    Updates the user's name attribute in Amazon Cognito User Pools.

    Parameters:
    - `credentials`: An instance of the LoginRequestBody class containing user email and password.
    - `update_name`: An instance of the UpdateNameRequestBody class containing the new name.

    Returns:
    - The HTTP status code indicating the result of the name update.
    - A dictionary with an "error" key containing an error message if the update fails.
    """

    tokens = authenticate_user(credentials)

    try:
        response = cognito_idp.update_user_attributes(
            UserAttributes=[
                {"Name": "name", "Value": update_name.new_name},
            ],
            AccessToken=tokens["access_token"],
        )

    except ClientError as e:
        return {"error": str(e)}

    return response["ResponseMetadata"]["HTTPStatusCode"]


class UpdateEmailRequestBody:
    new_email: str


def update_user_attribute_email(
    credentials: LoginRequestBody, update_email: UpdateEmailRequestBody
):
    """
    Updates the user's email attribute in Amazon Cognito User Pools.

    Parameters:
    - `credentials`: An instance of the LoginRequestBody class containing user email and password.
    - `update_email`: An instance of the UpdateEmailRequestBody class containing the new email.

    Returns:
    - The HTTP status code indicating the result of the email update.
    - A dictionary with an "error" key containing an error message if the update fails.
    """

    tokens = authenticate_user(credentials)

    try:
        response = cognito_idp.update_user_attributes(
            UserAttributes=[
                {"Name": "email", "Value": update_email.new_email},
            ],
            AccessToken=tokens["access_token"],
        )

    except ClientError as e:
        return {"error": str(e)}

    return response["ResponseMetadata"]["HTTPStatusCode"]


class VerifyUserAttribute:
    confirmation_code: str


def verify_user_attribute_email(credentials: LoginRequestBody, code: VerifyUserAttribute):
    """
    Verifies the user's email attribute in Amazon Cognito User Pools.

    Parameters:
    - `credentials`: An instance of the LoginRequestBody class containing user email and password.
    - `code`: An instance of the VerifyUserAttribute class containing the confirmation code.

    Returns:
    - The HTTP status code indicating the result of the email verification.
    - A dictionary with an "error" key containing an error message if the verification fails.
    """

    tokens = authenticate_user(credentials)

    try:
        response = cognito_idp.verify_user_attribute(
            AttributeName="email",
            Code=code.confirmation_code,
            AccessToken=tokens["access_token"],
        )

    except ClientError as e:
        return {"error": str(e)}

    return response["ResponseMetadata"]["HTTPStatusCode"]


lambda_handler = Mangum(app, lifespan="off")

if __name__ == "__main__":
    # noinspection PyPackageRequirements
    import uvicorn

    uvicorn.run(app)
