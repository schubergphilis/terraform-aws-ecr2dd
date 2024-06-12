// --------------------------------------------------------------------------------------------------
//  1- Provisions a CloudWatchEvents Rule that is triggered based on ECR Image Scan Event
//  2- Provisions a Lambda that creates a finding in AWS Security Hub/Jira
// --------------------------------------------------------------------------------------------------

locals {
  unique_secret_arns = distinct([for repo, config in var.repo_config : config.dd_secret_arn])
}


data "aws_iam_policy_document" "lambda_ecr_to_datadog_event_policy" {
  statement {
    actions = [
      "cloudwatch:PutMetricData",
      "iam:ListAccountAliases",
    ]

    resources = ["*"]
  }

  # Allow Lambda to read the secrets which are configured.
  statement {
    actions = ["secretsmanager:GetSecretValue"]

    resources = local.unique_secret_arns
  }

  # Adding KMS Decrypt action if dd_secret_kms_arn is null
  dynamic "statement" {
    for_each = var.dd_secret_kms_arn != null ? { create = true } : {}

    content {
      effect    = "Allow"
      actions   = ["kms:Decrypt"]
      resources = local.unique_secret_arns
    }
  }
}

module "lambda_ecr_to_datadog_event_role" {
  source                = "github.com/schubergphilis/terraform-aws-mcaf-role?ref=v0.4.0"
  name                  = "LambdaECRToDatadogEventRole"
  create_policy         = true
  postfix               = false
  principal_type        = "Service"
  principal_identifiers = ["lambda.amazonaws.com"]
  role_policy           = data.aws_iam_policy_document.lambda_ecr_to_datadog_event_policy.json
  tags                  = var.tags
}

resource "aws_iam_role_policy_attachment" "lambda_ecr_finding_policy_vpcaccess" {
  role       = module.lambda_ecr_to_datadog_event_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

data "archive_file" "lambda_ecr_to_datadog_event" {
  type        = "zip"
  source_file = "${path.module}/lambda/lambda_ecr_to_datadog_event.py"
  output_path = "${path.module}/lambda/lambda_ecr_to_datadog_event.zip"
}

resource "aws_lambda_layer_version" "requests_layer" {
  compatible_architectures = ["x86_64"]
  compatible_runtimes      = ["python3.12"]
  filename                 = "${path.module}/lambda/requests_layer.zip"
  layer_name               = "requests"
  source_code_hash         = filebase64sha256("${path.module}/lambda/requests_layer.zip")
}

module "lambda_ecr_to_datadog_event" {
  source        = "github.com/schubergphilis/terraform-aws-mcaf-lambda?ref=v1.4.0"
  name          = "lambda_ecr_to_datadog_event"
  create_policy = false
  description   = "Send ECR findings to Datadog"
  filename      = data.archive_file.lambda_ecr_to_datadog_event.output_path
  handler       = "lambda_ecr_to_datadog_event.lambda_handler"
  layers        = [aws_lambda_layer_version.requests_layer.arn]
  role_arn      = module.lambda_ecr_to_datadog_event_role.arn
  runtime       = "python3.12"
  subnet_ids    = var.subnet_ids
  tags          = var.tags

  environment = {
    LOG_LEVEL               = "INFO"
    POWERTOOLS_SERVICE_NAME = "ecr-finding"
    REPO_CONFIG             = jsonencode(var.repo_config)
  }

  security_group_egress_rules = [
    {
      cidr_ipv4   = "0.0.0.0/0"
      description = "Allow access to HTTPS (for Datadog API)"
      from_port   = 443
      ip_protocol = "tcp"
      to_port     = 443
    }
  ]
}

module "cloudwatch_event_ecr_finding" {
  source                            = "github.com/cloudposse/terraform-aws-cloudwatch-events.git?ref=0.8.0"
  name                              = "rule-ecr-finding"
  cloudwatch_event_rule_description = var.cloudwatch_event_ecr_scan_rule_description
  cloudwatch_event_rule_pattern     = var.cloudwatch_event_ecr_scan_rule_pattern
  cloudwatch_event_target_arn       = module.lambda_ecr_to_datadog_event.arn
}

resource "aws_lambda_permission" "allow_invoke_ecr_finding_lambda" {
  function_name = module.lambda_ecr_to_datadog_event.name
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = module.cloudwatch_event_ecr_finding.aws_cloudwatch_event_rule_arn
  statement_id  = "PermissionForEventsToInvokeLambdachk"
}
