# terraform-aws-ecr2dd

This module creates an integration that collects AWS ECR (Enhanced) scan findings, from AWS Inspector and sends them as an event to Datadog.

It can be configured per reposistory base to have the alerts send to different destinations with a specific tag and which level of severity should be included.

## Usage

As a prerequisite a AWS secret is needed. This needs to contain the Datadog URL and API key with keys `url` and `api_key` and their respective values.

For exmaple:
```
resource "aws_secretsmanager_secret" "ecr_scan_dd_secret" {
  name = "ecr-scan-dd-secret"
}

resource "aws_secretsmanager_secret_version" "ecr_scan_dd_secret_version" {
  secret_id = aws_secretsmanager_secret.ecr_scan_dd_secret.id
  secret_string = jsonencode({
    api_key = var.ecr2dd_api_key
    url     = var.ecr2dd_url
  })
}
```

With this exmaple the module can be called as follows:
```
module "ecr-to-datadog" {
  source = "git::https://github.com/schubergphilis/terraform-aws-ecr2dd?ref=main"

  subnet_ids = data.terraform_remote_state.vpc.outputs.shared_vpc.subnets.private.ids

  repo_config = {
    example_test2 = {
      dd_secret_arn = aws_secretsmanager_secret.ecr_scan_dd_secret.arn
      ecr_repo_base = "example/test2"
      ecr_repo_tag  = "exampletest"
    }
    example_test = {
      dd_secret_arn = aws_secretsmanager_secret.ecr_scan_dd_secret.arn
      ecr_repo_base = "example"
    }
  }
}
```

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
