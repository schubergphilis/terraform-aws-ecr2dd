# Usage

Loosely based on:

- <https://github.com/aws-samples/aws-securityhub-remediations/blob/main/aws-ecr-continuouscompliance/cft/aws-ecr-continuouscompliance-v1.yaml>
- <https://aws.amazon.com/blogs/containers/automating-image-compliance-for-amazon-eks-using-amazon-elastic-container-registry-and-aws-security-hub/>

<!-- BEGIN_TF_DOCS -->
<!-- END_TF_DOCS -->

## Using Pre-commit

To make local development easier, we have added a pre-commit configuration to the repo. to use it, follow these steps:

Install the following tools:

```brew install tflint```

Install pre-commit:

```pip3 install pre-commit --upgrade```

To run the pre-commit hooks to see if everything working as expected, (the first time run might take a few minutes):

```pre-commit run -a```

To install the pre-commit hooks to run before each commit:

```pre-commit install```
