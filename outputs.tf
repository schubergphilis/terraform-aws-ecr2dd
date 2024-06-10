output "security_group_id" {
  value       = module.lambda_ecr_to_datadog_event.security_group_id
  description = "This will output the security group id attached to the Lambda. This can be used to tune ingress and egress rules."
}
