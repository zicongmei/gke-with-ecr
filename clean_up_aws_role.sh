#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -euo pipefail

AWS_ROLE_NAME="gke-role-1"
OIDC_PROVIDER_URL="https://accounts.google.com"

echo "Starting AWS IAM Role and OIDC Provider cleanup..."
echo "AWS Role Name to clean up: ${AWS_ROLE_NAME}"
echo "OIDC Provider URL to clean up: ${OIDC_PROVIDER_URL}"

# Get AWS Account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
if [ -z "$AWS_ACCOUNT_ID" ]; then
    echo "Error: Could not retrieve AWS Account ID. Please ensure AWS CLI is configured and authenticated."
    exit 1
fi
echo "Retrieved AWS Account ID: ${AWS_ACCOUNT_ID}"

# Define the AWS OIDC Provider ARN based on the AWS Account ID and OIDC URL
# The OIDC provider ARN format is arn:aws:iam::ACCOUNT_ID:oidc-provider/URL_HOSTNAME
AWS_OIDC_PROVIDER_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER_URL#https://}"

# 1. Clean up the AWS IAM Role
echo "Attempting to clean up AWS IAM Role '${AWS_ROLE_NAME}'..."
if aws iam get-role --role-name "${AWS_ROLE_NAME}" &>/dev/null; then
    echo "IAM Role '${AWS_ROLE_NAME}' found. Detaching policies and deleting role..."

    # Detach all attached policies from the role
    echo "Detaching policies from role '${AWS_ROLE_NAME}'..."
    POLICIES=$(aws iam list-attached-role-policies --role-name "${AWS_ROLE_NAME}" --query 'AttachedPolicies[].PolicyArn' --output text)
    if [ -n "$POLICIES" ]; then
        for POLICY_ARN in $POLICIES; do
            echo "  - Detaching policy: ${POLICY_ARN}"
            if ! aws iam detach-role-policy --role-name "${AWS_ROLE_NAME}" --policy-arn "${POLICY_ARN}" &>/dev/null; then
                echo "Warning: Failed to detach policy '${POLICY_ARN}'. Skipping."
            fi
        done
        echo "All attached policies detached from '${AWS_ROLE_NAME}'."
    else
        echo "No policies attached to '${AWS_ROLE_NAME}'."
    fi

    # Delete the IAM Role
    echo "Deleting IAM Role '${AWS_ROLE_NAME}'..."
    if aws iam delete-role --role-name "${AWS_ROLE_NAME}" &>/dev/null; then
        echo "IAM Role '${AWS_ROLE_NAME}' deleted successfully."
    else
        echo "Error: Failed to delete IAM Role '${AWS_ROLE_NAME}'. It might have inline policies or be in use."
        echo "Please check AWS console for details if deletion failed."
        exit 1
    fi
else
    echo "IAM Role '${AWS_ROLE_NAME}' does not exist. Skipping role deletion."
fi

# 2. Clean up the AWS OIDC Provider
echo "Attempting to clean up AWS OIDC Provider for '${OIDC_PROVIDER_URL}'..."
# Check if the OIDC provider exists using its ARN
if aws iam get-open-id-connect-provider --open-id-connect-provider-arn "${AWS_OIDC_PROVIDER_ARN}" &>/dev/null; then
    echo "OIDC Provider for '${OIDC_PROVIDER_URL}' found. Deleting provider..."
    if aws iam delete-open-id-connect-provider --open-id-connect-provider-arn "${AWS_OIDC_PROVIDER_ARN}" &>/dev/null; then
        echo "OIDC Provider for '${OIDC_PROVIDER_URL}' deleted successfully."
    else
        echo "Error: Failed to delete OIDC Provider for '${OIDC_PROVIDER_URL}'. It might be in use or linked to other resources."
        exit 1
    fi
else
    echo "OIDC Provider for '${OIDC_PROVIDER_URL}' does not exist. Skipping OIDC provider deletion."
fi

echo "AWS IAM Role and OIDC Provider cleanup complete!"
echo "------------------------------------------------------------"