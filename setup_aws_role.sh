#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -euo pipefail

AWS_ROLE_NAME_PREFIX="gke-role" # Use a prefix as the name might not be fixed but derived from ARN

GCP_PROJECT_ID=$(gcloud config get-value project)
GCP_PROJECT_NUMBER=$(gcloud projects describe ${GCP_PROJECT_ID} --format="value(projectNumber)")
GCP_SERVICE_ACCOUNT_EMAIL="${GCP_PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
GCP_SA_SUB=$(gcloud iam service-accounts describe ${GCP_SERVICE_ACCOUNT_EMAIL} --format=json | jq -r .uniqueId)

# Define the status directory and file
STATUS_DIR=".status"
STATUS_FILE="${STATUS_DIR}/aws_role_info.txt"

echo "Starting AWS IAM Role configuration for GCP Service Account..."
echo "GCP Service Account Email: ${GCP_SERVICE_ACCOUNT_EMAIL}"

# Get AWS Account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
if [ -z "$AWS_ACCOUNT_ID" ]; then
    echo "Error: Could not retrieve AWS Account ID. Please ensure AWS CLI is configured and authenticated."
    exit 1
fi
echo "Retrieved AWS Account ID: ${AWS_ACCOUNT_ID}"

# Derive a unique role name based on project ID and a timestamp or fixed suffix
# Using a fixed name for simplicity as per original, but good to be aware.
AWS_ROLE_NAME="${AWS_ROLE_NAME_PREFIX}-1" # Keeping original role name for consistency with existing script logic

# 1. Create the AWS IAM Role
echo "Checking if AWS IAM Role '${AWS_ROLE_NAME}' already exists..."
if aws iam get-role --role-name "${AWS_ROLE_NAME}" &>/dev/null; then
    echo "IAM Role '${AWS_ROLE_NAME}' already exists. Skipping creation."
else
    echo "IAM Role '${AWS_ROLE_NAME}' does not exist. Creating..."

    # Define the Trust Policy for the IAM Role
    # This policy allows the OIDC provider to assume the role, with conditions
    # ensuring the request comes from the specific GCP Service Account.
    TRUST_POLICY_JSON=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Federated": "accounts.google.com"},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "accounts.google.com:oaud": "sts.amazonaws.com",
                    "accounts.google.com:aud": "${GCP_SA_SUB}",
                    "accounts.google.com:sub": "${GCP_SA_SUB}"
        }
      }
    }
  ]
}
EOF
)
    echo "Generated Trust Policy for role:"
    # Using jq for pretty printing if available, otherwise raw output
    if command -v jq &>/dev/null; then
        echo "${TRUST_POLICY_JSON}" | jq .
    else
        echo "${TRUST_POLICY_JSON}"
    fi

    # Create the role with the defined trust policy
    if ! aws iam create-role \
        --role-name "${AWS_ROLE_NAME}" \
        --assume-role-policy-document "${TRUST_POLICY_JSON}" \
        --description "IAM Role for GCP Service Account (${GCP_SERVICE_ACCOUNT_EMAIL}) to assume via OIDC" ; then
        echo "Error: Failed to create IAM Role '${AWS_ROLE_NAME}'."
        exit 1
    fi
    echo "IAM Role '${AWS_ROLE_NAME}' created successfully."
fi

echo "AWS IAM Role setup complete!"
echo "------------------------------------------------------------"

# Add ECR Pull permissions to the role
ECR_READ_POLICY_ARN="arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
ECR_READ_POLICY_NAME="AmazonECRContainerRegistryReadOnly" # Corrected policy name for clarity based on ARN

echo "Attempting to attach ECR read-only policy '${ECR_READ_POLICY_NAME}' to role '${AWS_ROLE_NAME}'..."

# Check if the policy is already attached
if aws iam list-attached-role-policies --role-name "${AWS_ROLE_NAME}" --query "AttachedPolicies[?PolicyName=='${ECR_READ_POLICY_NAME}']" --output text | grep -q "${ECR_READ_POLICY_NAME}"; then
    echo "Policy '${ECR_READ_POLICY_NAME}' is already attached to role '${AWS_ROLE_NAME}'. Skipping attachment."
else
    if ! aws iam attach-role-policy \
        --role-name "${AWS_ROLE_NAME}" \
        --policy-arn "${ECR_READ_POLICY_ARN}" &>/dev/null; then
        echo "Error: Failed to attach policy '${ECR_READ_POLICY_NAME}' to role '${AWS_ROLE_NAME}'."
        exit 1
    fi
    echo "Policy '${ECR_READ_POLICY_NAME}' attached successfully to role '${AWS_ROLE_NAME}'."
fi

# Optional: Output the Role ARN for convenience
AWS_ROLE_ARN=$(aws iam get-role --role-name "${AWS_ROLE_NAME}" --query Role.Arn --output text 2>/dev/null)
if [ -z "$AWS_ROLE_ARN" ]; then
    echo "Error: Could not retrieve AWS Role ARN for ${AWS_ROLE_NAME}."
    exit 1
fi

echo "AWS Role ARN for ${AWS_ROLE_NAME}: ${AWS_ROLE_ARN}"

# Create .status directory and write ARNs
mkdir -p "${STATUS_DIR}"
echo "Writing AWS role ARN to ${STATUS_FILE}..."
echo "AWS_ROLE_ARN=${AWS_ROLE_ARN}" > "${STATUS_FILE}"
echo "Information saved to ${STATUS_FILE}."