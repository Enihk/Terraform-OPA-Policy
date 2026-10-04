# aws.rego
package terraform.aws

# Rule 1: Block EC2 instances that are NOT t2.medium
deny_ec2_instance_type[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    
    # Check if the action is create or update
    action := resource.change.actions[_]
    action == "create"

    # Get the instance type from the planned configuration
    instance_type := resource.change.after.instance_type

    # Logic: If the type is not t2.medium, deny it
    instance_type != "t2.medium"

    msg := sprintf("EC2 instance type '%s' is not allowed. Only 't2.medium' is permitted.", [instance_type])
}

# Rule 2: Block Security Groups that allow 0.0.0.0/0
deny_public_ingress[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    
    action := resource.change.actions[_]
    action == "create"

    # Iterate through all ingress blocks in the planned change
    ingress := resource.change.after.ingress[_]
    
    # Check if the CIDR blocks contain the open world
    cidr := ingress.cidr_blocks[_]
    cidr == "0.0.0.0/0"

    msg := sprintf("Security Group '%s' allows ingress from 0.0.0.0/0. This is forbidden.", [resource.address])
}