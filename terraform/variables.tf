variable "region" {
  description = "AWS region for the lab."
  type        = string
  default     = "eu-central-1"
}

variable "key_name" {
  description = "Name of an existing EC2 key pair in the region."
  type        = string
  default     = "vbmi-key"
}

variable "allowed_cidr" {
  description = "CIDR allowed to reach SSH (22) and the k3s API (6443). Empty = auto-detect your current public IP."
  type        = string
  default     = ""
}

variable "server_instance_type" {
  description = "k3s server; must be a CPU with avx512vbmi (exposed node)."
  type        = string
  default     = "t8i.small"
}

variable "agent_instance_type" {
  description = "k3s agent; older Intel without avx512vbmi (non-exposed x86 node)."
  type        = string
  default     = "t3.small"
}

variable "root_volume_gb" {
  description = "Root EBS volume size per node (gp3)."
  type        = number
  default     = 16
}

variable "k3s_version" {
  description = "Exact k3s version. Empty = current stable channel."
  type        = string
  default     = "v1.37.2+k3s1" # verified in lab 2026-11-18
}

variable "nfd_chart_version" {
  description = "Node Feature Discovery Helm chart version. Empty = latest."
  type        = string
  default     = "0.20.1" # verified in lab 2026-11-18
}
