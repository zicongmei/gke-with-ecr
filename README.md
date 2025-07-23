# gke-with-ecr

This project enables GKE nodes to pull container images from AWS ECR private and public registries by configuring Kubelet with a custom credential provider plugin. It leverages OIDC federation for secure authentication from GCP to AWS. The plugin reads the default 
service account (SA) token of the GCP VM instance, exchange this GCP SA token to a AWS role token, and then allow the kubelet 
and containerd to pull image from AWS ECR.

## Quick Start

1.  **Prerequisites:** Ensure `gcloud CLI`, `kubectl`, `aws CLI`, and `gsutil` are installed and configured with appropriate permissions for your GCP project and AWS account. You need a GKE cluster with Workload Identity enabled.

2.  **Setup AWS Role:** Create an AWS IAM role that your GKE nodes can assume.
    ```bash
    ./setup_aws_role.sh
    ```
    This script creates an IAM role (`gke-role-1`) with ECR read-only access and a trust policy allowing your GKE default compute service account to assume it. The role ARN is saved to `.status/aws_role_info.txt`.

3.  **Build & Publish Plugin:** Compile the credential provider plugin and upload it to a Google Cloud Storage (GCS) bucket.
    ```bash
    make publish GCS_PATH=gs://your-gcs-bucket/path
    ```
    Replace `your-gcs-bucket/path` with your desired GCS path. The uploaded binary path is saved to `.status/publish_info.txt`.

4.  **Deploy to GKE:** Deploy the plugin installer as a DaemonSet to your GKE cluster.
    ```bash
    make deploy
    ```
    This creates a privileged DaemonSet that downloads the plugin binary to each node, configures Kubelet to use it for ECR authentication, and restarts the Kubelet service.

5.  **Test** Test a pod with ECR image 
    ```bash
    kubectl apply -f - <<EOF
    apiVersion: v1
    kind: Pod
    metadata:
    name: my-ecr-pod
    labels:
        app: my-ecr-app
    spec:
    containers:
    - name: my-container
        image: xxxxx.dkr.ecr.us-west-2.amazonaws.com/<image-name>
    EOF
    ```

## Introduction

This solution automates the setup for GKE to pull images from AWS ECR:

*   **AWS IAM Role Creation:** A dedicated AWS IAM role (`gke-role-1`) is created, configured to be assumable by your GKE cluster's default compute service account via OIDC federation. This role is granted `AmazonEC2ContainerRegistryReadOnly` permissions.
*   **Plugin Build & Distribution:** A Go-based Kubelet credential provider plugin is built for Linux AMD64 and uploaded to a specified GCS bucket. This plugin retrieves temporary AWS credentials by assuming the configured IAM role using a GCP identity token.
*   **DaemonSet Deployment & Kubelet Setup:** A Kubernetes DaemonSet is deployed. Each pod runs an `initContainer` with elevated privileges. This `initContainer` downloads the plugin binary to the node's `/home/kubernetes/bin` directory, updates the Kubelet's credential provider configuration (`/etc/srv/kubernetes/cri_auth_config.yaml`) to use the plugin for ECR image pulls, and restarts the `kubelet` service.