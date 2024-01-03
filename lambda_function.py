#
# Copyright (c) 2023 ACG Business Analytics Inc. All rights reserved.
#
# This file is part of a proprietary software system of ACG Business Analytics Inc.
# No part of this file may be copied, modified, sold, distributed, or used in any
# way without the written permission of ACG Business Analytics Inc.
#

import os
import boto3
from botocore.exceptions import ClientError
from pydantic import BaseModel, EmailStr

REGION = os.environ["REGION"]
CLIENT_ID = os.environ["CLIENT_ID"]


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

    client = boto3.client("cognito-idp", region_name=REGION)

    try:
        initiate_auth_response = client.initiate_auth(
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
        client = boto3.client("cognito-idp", region_name=REGION)
        response = client.change_password(
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


def update_user_attribute_name(
    credentials: LoginRequestBody, update_name: UpdateNameRequestBody
):
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
        client = boto3.client("cognito-idp", region_name=REGION)
        response = client.update_user_attributes(
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
        client = boto3.client("cognito-idp", region_name=REGION)
        response = client.update_user_attributes(
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


def verify_user_attribute_email(
    credentials: LoginRequestBody, code: VerifyUserAttribute
):
    """
    Verifies the user's email attribute in Amazon Cognito User Pools.

    Parameters:
    - `credentials`: An instance of the LoginRequestBody class containing user email and password.
    - `code`: An instance of the VerifyUserAttribute class containing the confirmation code.

    Returns:
    - The HTTP status code indicating the result of the email verification.
    - A dictionary with an "error" key containing an error message if the verification fails.
    """

    client = boto3.client("cognito-idp", region_name=REGION)
    tokens = authenticate_user(credentials)

    try:
        response = client.verify_user_attribute(
            AttributeName="email",
            Code=code.confirmation_code,
            AccessToken=tokens["access_token"],
        )

    except ClientError as e:
        return {"error": str(e)}

    return response["ResponseMetadata"]["HTTPStatusCode"]

