# AWS Cognito API

This repository contains a Python-based AWS Lambda function designed to interface with AWS Cognito. It facilitates operations such as updating user attributes and verifying user attributes with Cognito's user pools.

## Features

- Updating user attributes: name, email, and password.
- Email verification of user attributes in Amazon Cognito User Pools.

## Requirements

To deploy and run this project, you will need:

- AWS CLI already configured with Administrator permission
- Python 3.12 or higher
- An AWS account with access to AWS Cognito

## Configuration

To accommodate different environments, such as when running locally vs deploying to AWS Lambda with API Gateway, the following environment variable can be set:

- `API_GATEWAY_BASE_PATH`: Specifies the base path for the API when using API Gateway. This is important for routing to work correctly when the API is not deployed at the root path. If not set, the default value is `/`.
- `SENTRY_DSN`: Specifies the DSN for Sentry error tracking. If not set, Sentry will not be used.

## Testing

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/aws-cognito-api.git
   cd aws-cognito-api
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment variables:

   ```bash
   # Optionally, configure the API Gateway base path if deployed behind API Gateway with a custom base path
   export API_GATEWAY_BASE_PATH='/prod'
   
   # Optionally, configure for Sentry
   export SENTRY_DSN='your-sentry-dsn'
   ```

4. Run the function locally:

	```bash
	python lambda_function.py
	```

This will start a local server using `uvicorn`, making the API accessible through `http://localhost:8000`.

## Usage

The API provides the following endpoints:

- PATCH `/user`: Update user attributes.
- POST `/user/confirm`: Verify user email attribute after receiving a confirmation code.

### Updating User Attributes

To update user data, send a `PATCH` request to `/user` endpoint with the `access_token` and accurately filled `PatchUserRequestBody`.

### Verifying User Email

Send a `POST` request to `/user/confirm` with the `confirmation_code` and `access_token` to verify a user's email attribute.

## Deployment

The project includes a `build_package.sh` script to package the Lambda function for deployment, as well as an `update_function.sh` script to update the function code in AWS. Ensure you have set the correct `_function_name` in the `update_function.sh` script.

Before deploying, ensure that you set the `API_GATEWAY_BASE_PATH` environment variable if your API is hosted at a non-root path on API Gateway.

After any changes to the Lambda code, run the following script:

```bash
./update_function.sh
```

This will build the new package, upload it to AWS, and clean up the artifacts.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgments

- AWS SDK for Python (Boto3)
- FastAPI framework
- Mangum for AWS Lambda support
- Sentry for error tracking
