#
# 2-node k3s lab for the java4shell exposure scanner.
#   server: t8i.small (Granite Rapids, avx512vbmi)  -> exposed node
#   agent:  t3.small  (Skylake/Cascade Lake)        -> non-exposed x86 node
#

# --- Lookups -----------------------------------------------------------------

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_vpc" "default" {
  default = true
}

# t8i is newer and not offered in every AZ; t3 is everywhere.
data "aws_ec2_instance_type_offerings" "server" {
  location_type = "availability-zone"

  filter {
    name   = "instance-type"
    values = [var.server_instance_type]
  }
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }

  filter {
    name   = "availability-zone"
    values = data.aws_ec2_instance_type_offerings.server.locations
  }
}

data "http" "my_ip" {
  count = var.allowed_cidr == "" ? 1 : 0
  url   = "https://checkip.amazonaws.com"
}

locals {
  # Both nodes in the same AZ: no cross-AZ traffic charges.
  subnet_id    = sort(data.aws_subnets.default.ids)[0]
  allowed_cidr = var.allowed_cidr != "" ? var.allowed_cidr : "${chomp(data.http.my_ip[0].response_body)}/32"
}

resource "random_password" "k3s_token" {
  length  = 48
  special = false
}

# --- Network -----------------------------------------------------------------

resource "aws_security_group" "lab" {
  name_prefix = "java4shell-lab-"
  description = "java4shell lab: SSH and k3s API from my IP, all traffic between nodes"
  vpc_id      = data.aws_vpc.default.id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.lab.id
  description       = "SSH from my IP"
  cidr_ipv4         = local.allowed_cidr
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}

resource "aws_vpc_security_group_ingress_rule" "k3s_api" {
  security_group_id = aws_security_group.lab.id
  description       = "k3s API from my IP (kubectl)"
  cidr_ipv4         = local.allowed_cidr
  ip_protocol       = "tcp"
  from_port         = 6443
  to_port           = 6443
}

# k3s needs 6443, 8472/udp (flannel VXLAN) and 10250 between nodes; allow all within the SG.
resource "aws_vpc_security_group_ingress_rule" "intra" {
  security_group_id            = aws_security_group.lab.id
  description                  = "All traffic between lab nodes"
  referenced_security_group_id = aws_security_group.lab.id
  ip_protocol                  = "-1"
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.lab.id
  description       = "All outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# --- Nodes -------------------------------------------------------------------

resource "aws_instance" "server" {
  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = var.server_instance_type
  key_name                    = var.key_name
  subnet_id                   = local.subnet_id
  vpc_security_group_ids      = [aws_security_group.lab.id]
  associate_public_ip_address = true

  metadata_options {
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1          # pods can't reach IMDS
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/templates/server.sh.tftpl", {
    k3s_token         = random_password.k3s_token.result
    k3s_version       = var.k3s_version
    nfd_chart_version = var.nfd_chart_version
  })
  user_data_replace_on_change = true

  tags = {
    Name = "java4shell-k3s-server"
    Role = "k3s-server"
  }

  # The AMI parameter updates over time; don't replace a running lab because of it.
  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_instance" "agent" {
  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = var.agent_instance_type
  key_name                    = var.key_name
  subnet_id                   = local.subnet_id
  vpc_security_group_ids      = [aws_security_group.lab.id]
  associate_public_ip_address = true

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/templates/agent.sh.tftpl", {
    k3s_token   = random_password.k3s_token.result
    k3s_version = var.k3s_version
    server_ip   = aws_instance.server.private_ip
  })
  user_data_replace_on_change = true

  tags = {
    Name = "java4shell-k3s-agent"
    Role = "k3s-agent"
  }

  lifecycle {
    ignore_changes = [ami]
  }
}
