# policies.hcl

policy "deny_ec2_instance_type" {
  query             = "data.terraform.aws.deny_ec2_instance_type"
  enforcement_level = "mandatory"
  description       = "Only t2.medium EC2 instances are allowed."
}

policy "deny_public_security_group" {
  query             = "data.terraform.aws.deny_public_ingress"
  enforcement_level = "mandatory"
  description       = "Security groups cannot allow ingress from 0.0.0.0/0."
}