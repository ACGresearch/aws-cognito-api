#!/usr/bin/env bash

# Setting options for the shell script:
# -e: Script will exit if any command returns a non-zero value
# -x: Script will print each command executed, useful for debugging
set -ex

# Changing the current directory to the same directory where this bash
# script resides "$0" indicates this script. "dirname" gets the directory
# of this script.
cd "$(dirname "$0")"

# Removing the file 'package.zip' if it already exists. '-rf' instructs
# 'rm' to 'remove directories and their contents recursively' and 'ignore
# nonexistent files'
rm -rf package.zip package

# Creating a new directory named 'package'
mkdir package

# Using pip (python package installer) to install the python packages which
# are listed in 'requirements.txt' in the './package' directory
pip3 install \
	--target ./package \
	-r requirements.txt \
	--platform manylinux2014_aarch64 \
	--isolated \
	--only-binary=:all:

# 'cp' (copy) the file 'lambda_function.py' to the folder 'package'
cp lambda_function.py package

# Changing the current directory to 'package'
cd package

# 'zip -r' is used to compress files and directories. This line is
# compressing all the files in the current directory ('.') into the file
# '../package.zip'
zip -r ../package.zip .

# Changing the current directory to the parent directory of 'package'
cd ..

# Removing the directory 'package'
rm -rf package
