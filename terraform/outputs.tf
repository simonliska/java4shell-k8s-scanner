output "server_public_ip" {
  value = aws_instance.server.public_ip
}

output "agent_public_ip" {
  value = aws_instance.agent.public_ip
}

output "availability_zone" {
  value = aws_instance.server.availability_zone
}

output "allowed_cidr" {
  value = local.allowed_cidr
}

output "ssh_server" {
  value = "ssh -i ~/.ssh/${var.key_name}.pem ec2-user@${aws_instance.server.public_ip}"
}

output "ssh_agent" {
  value = "ssh -i ~/.ssh/${var.key_name}.pem ec2-user@${aws_instance.agent.public_ip}"
}
