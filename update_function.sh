#!/usr/bin/env bash
# This bash script uploads a new version of AWS Lambda function code.

# Setting options for the shell script:
# -e: Script will exit if any command returns a non-zero value
# -x: Script will print each command executed, useful for debugging
set -ex

# Configuration variables
_function_name=aws-cognito-api

# Change the current directory to the directory where this shell script is present
cd "$(dirname "$0")"

# Create a package file
./build_package.sh

# Use the AWS CLI (Command Line Interface) to update the Lambda function code with the new zip file
# --function-name: Name of the Lambda function we want to update
# --zip-file: Specifies the path to the .zip file that contains the deployment package
aws lambda update-function-code \
        --function-name $_function_name \
        --zip-file fileb://package.zip

# Removing the 'package.zip' file after uploading it to the lambda function.
# This is a cleaner approach to avoid keeping unnecessary files.
rm -rf package.zip
