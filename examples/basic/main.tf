resource "aws_secretsmanager_secret" "ecr_scan_dd_secret" {
  name = "ecr-scan-dd-secret"
}

resource "aws_secretsmanager_secret_version" "ecr_scan_dd_secret_version" {
  secret_id = aws_secretsmanager_secret.ecr_scan_dd_secret.id
  secret_string = jsonencode({
    api_key = "example"
    url     = "https://api.datadoghq.com/api/v1/events"
  })
}

module "ecr-to-datadog" {
  source = "../../"

  repo_config = [
    {
      dd_secret_arn = aws_secretsmanager_secret.ecr_scan_dd_secret.arn
      ecr_repo_base = "example/test2"
      ecr_repo_tag  = "exampletest"
    },
    {
      dd_secret_arn = aws_secretsmanager_secret.ecr_scan_dd_secret.arn
      ecr_repo_base = "example"
    }
  ]

  subnet_ids = ["subnet-0f9f5b6b1c4b1b1b1"]
  tags       = { Terraform = true }
}
