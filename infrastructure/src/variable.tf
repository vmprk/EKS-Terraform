# variable "image_id" {
#   type = string
# }

variable "availability_zone_names" {
  type    = list(string)
}

variable "private_subnets" {
  type    = list(string)
}

variable "public_subnets" {
  type    = list(string)
}

variable "cidr" {
  type     = string
  default = "10.0.0.0/16"
}

variable "environment" {
  type     = string
  default = "stage"
}

variable "cluster_name" {
  type     = string
  default = "eks"
}

variable "eks_user" {
  type     = string
}