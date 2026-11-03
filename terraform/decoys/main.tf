terraform {
  required_version = ">= 1.9.0"

  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.6"
    }
  }
}

provider "docker" {
  host = "ssh://labadmin@decoy:22"

  ssh_opts = [
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes"
  ]
}

variable "opencanary_image" {
  description = "OpenCanary image pinned by digest"
  type        = string
}

resource "docker_image" "opencanary" {
  name         = var.opencanary_image
  keep_locally = true
}

resource "docker_network" "honeypots" {
  name     = "deception-honeypots"
  driver   = "bridge"
  internal = false
  options = {
    "com.docker.network.bridge.name" = "br-decoy"
  }
}

resource "docker_container" "opencanary" {
  name     = "opencanary-01"
  hostname = "fileserver"
  image    = docker_image.opencanary.image_id

  restart    = "unless-stopped"
  memory     = 512
  cpu_shares = 512

  networks_advanced {
    name = docker_network.honeypots.name
  }

  ports {
    internal = 80
    external = 80
    ip       = "10.77.10.10"
    protocol = "tcp"
  }

  ports {
    internal = 21
    external = 21
    ip       = "10.77.10.10"
    protocol = "tcp"
  }

  volumes {
    host_path      = "/opt/deception/opencanary/opencanary.conf"
    container_path = "/root/.opencanary.conf"
    read_only      = true
  }

  volumes {
    host_path      = "/var/log/deception/opencanary"
    container_path = "/var/log/opencanary"
  }

  log_driver = "json-file"

  log_opts = {
    "max-size" = "10m"
    "max-file" = "3"
  }
}

output "http_url" {
  value = "http://10.77.10.10"
}
