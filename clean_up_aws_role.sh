#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -euo pipefail

STATUS_DIR=".status"
STATUS_FILE="${STATUS_DIR}/aws_role_info.txt"

# Read ARNs from the status file
if [ ! -f "${STATUS_FILE}" ]; then
    echo "Error: Status file '${STATUS_FILE}' not found. Cannot determine AWS role and OIDC provider to clean up."
    echo "Please run 'setup_aws_role.sh' first or manually specify the resources."
    exit 1
fi

echo "Reading AWS role and OIDC provider ARNs from ${STATUS_FILE}..."
# Source the file to load variables, but ensure they are not empty
source "${STATUS_FILE}"

if [ -z "${AWS_ROLE_ARN}" ] || [ -z "${AWS_OIDC_PROVIDER_ARN}" ]; then
    echo "Error: AWS_ROLE_ARN or AWS_OIDC_PROVIDER_ARN not found in ${STATUS_FILE}."
    exit 1
fi

# Derive role name from ARN
# Example ARN: arn:aws:iam::123456789012:role/gke-role-1
AWS_ROLE_NAME=$(echo "${AWS_ROLE_ARN}" | awk -F'/' '{print $2}')
# Derive OIDC provider URL from ARN for logging purposes
# Example ARN: arn:aws:iam::123456789012:oidc-provider/accounts.google.com
OIDC_PROVIDER_URL="https://$(echo "${AWS_OIDC_PROVIDER_ARN}" | awk -F'/' '{print $2}')"

echo "Starting AWS IAM Role and OIDC Provider cleanup..."
echo "AWS Role ARN to clean up: ${AWS_ROLE_ARN} (Name: ${AWS_ROLE_NAME})"
echo "AWS OIDC Provider ARN to clean up: ${AWS_OIDC_PROVIDER_ARN} (URL: ${OIDC_PROVIDER_URL})"

# Get AWS Account ID (for verification, though ARNs from file are primary)
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
if [ -z "$AWS_ACCOUNT_ID" ]; then
    echo "Warning: Could not retrieve AWS Account ID. Proceeding with cleanup using stored ARNs."
fi
echo "Retrieved AWS Account ID: ${AWS_ACCOUNT_ID}"


# 1. Clean up the AWS IAM Role
echo "Attempting to clean up AWS IAM Role '${AWS_ROLE_NAME}' (ARN: ${AWS_ROLE_ARN})..."
if aws iam get-role --role-name "${AWS_ROLE_NAME}" &>/dev/null; then
    echo "IAM Role '${AWS_ROLE_NAME}' found. Detaching policies and deleting role..."

    # Detach all attached policies from the role
    echo "Detaching policies from role '${AWS_ROLE_NAME}'..."
    POLICIES=$(aws iam list-attached-role-policies --role-name "${AWS_ROLE_NAME}" --query 'AttachedPolicies[].PolicyArn' --output text)
    if [ -n "$POLICIES" ]; then
        for POLICY_ARN_TO_DETACH in $POLICIES; do
            echo "  - Detaching policy: ${POLICY_ARN_TO_DETACH}"
            if ! aws iam detach-role-policy --role-name "${AWS_ROLE_NAME}" --policy-arn "${POLICY_ARN_TO_DETACH}" &>/dev/null; then
                echo "Warning: Failed to detach policy '${POLICY_ARN_TO_DETACH}'. Skipping."
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
echo "Attempting to clean up AWS OIDC Provider (ARN: ${AWS_OIDC_PROVIDER_ARN})..."
# Check if the OIDC provider exists using its ARN
if aws iam get-open-id-connect-provider --open-id-connect-provider-arn "${AWS_OIDC_PROVIDER_ARN}" &>/dev/null; then
    echo "OIDC Provider found. Deleting provider..."
    if aws iam delete-open-id-connect-provider --open-id-connect-provider-arn "${AWS_OIDC_PROVIDER_ARN}" &>/dev/null; then
        echo "OIDC Provider for '${OIDC_PROVIDER_URL}' deleted successfully."
    else
        echo "Error: Failed to delete OIDC Provider for '${OIDC_PROVIDER_URL}'. It might be in use or linked to other resources."
        exit 1
    fi
else
    echo "OIDC Provider (ARN: ${AWS_OIDC_PROVIDER_ARN}) does not exist. Skipping OIDC provider deletion."
fi

echo "AWS IAM Role and OIDC Provider cleanup complete!"
echo "------------------------------------------------------------"

# Optional: Remove the status file after successful cleanup
if [ -f "${STATUS_FILE}" ]; then
    echo "Removing status file: ${STATUS_FILE}"
    rm "${STATUS_FILE}"
fi