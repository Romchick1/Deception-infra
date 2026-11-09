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

resource "docker_network" "honeypots" {
  name     = "deception-honeypots"
  driver   = "bridge"
  internal = false
  options = {
    "com.docker.network.bridge.name" = "br-decoy"
  }
}
