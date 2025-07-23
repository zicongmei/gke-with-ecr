#!/bin/bash
set -euo pipefail

DAEMONSET_NAME="gke-ecr-image-puller-installer"
NAMESPACE="kube-system" # Must match the namespace used in deploy.sh

echo "Attempting to undeploy GKE ECR Image Puller DaemonSet..."
echo "Deleting DaemonSet '${DAEMONSET_NAME}' from namespace '${NAMESPACE}'..."

# Delete the DaemonSet
kubectl delete ds "${DAEMONSET_NAME}" -n "${NAMESPACE}"

echo "DaemonSet '${DAEMONSET_NAME}' delete command sent."
echo "Note: This script only removes the DaemonSet, which prevents future installations and running instances."
echo "It does NOT revert the changes made by the initContainer on the host nodes (binary, config, kubelet restart)."
echo "Manual cleanup on nodes (if necessary) might involve:"
echo "  - Removing /host/home/kubernetes/bin/gke-ecr-image-puller"
echo "  - Reverting changes to /host/etc/srv/kubernetes/cri_auth_config.yaml"
echo "  - Restarting kubelet after manual changes."