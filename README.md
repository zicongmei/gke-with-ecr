# gke-with-ecr

1. run setup_aws_role.sh and it will create aws role and oidc provider. 
it save the status in .status 
1. run "make publish GCS_PATH=gs://<bucket>/path" and it save the status in .status 
1. run "make deploy" to deploy to k8s