package main

deny[msg] {
  input.resource_changes[_].type == "aws_instance"
  instance := input.resource_changes[_].change.after

  instance.instance_type != "t3.micro"

  msg = sprintf("Instance must be t3.micro, found %s", [instance.instance_type])
}
