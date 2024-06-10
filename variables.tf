variable "cloudwatch_event_ecr_scan_rule_description" {
  type        = string
  description = "The description of the rule"
  default     = "Capture ECR scan findings and trigger a Lambda function"
}

variable "cloudwatch_event_ecr_scan_rule_pattern" {
  type = map(any)
  default = {
    source      = ["aws.inspector2"]
    detail-type = ["Inspector2 Scan"]
  }
  description = "Event pattern described a HCL map which will be encoded as JSON with jsonencode function. See full documentation of CloudWatch Events and Event Patterns for details. http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/CloudWatchEventsandEventPatterns.html"
}

variable "repo_config" {
  type = map(object({
    #create_jira_issue          = optional(bool, false)
    ecr_repo_base         = list(string)
    ecr_repo_tag          = optional(string, null)
    issue_severity_filter = optional(list(string), ["HIGH", "CRITICAL"])
    dd_secret_arn         = optional(string)
  }))
  default     = {}
  description = "Configure per repository: DD destination and the severity filter"
}

variable "dd_secret_kms_arn" {
  type        = string
  description = "The KMS key to encrypt the secret"
  default     = null
}

variable "subnet_ids" {
  type        = list(string)
  description = "List of subnet IDs to deploy Lambda in"
}

variable "tags" {
  type        = map(string)
  description = "Map of tags"
}
