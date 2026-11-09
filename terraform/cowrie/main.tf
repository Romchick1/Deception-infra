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

variable "cowrie_image" {
  description = "Cowrie image pinned by digest"
  type        = string
}

resource "docker_image" "cowrie" {
  name         = var.cowrie_image
  keep_locally = true
}

resource "docker_volume" "cowrie_state" {
  name = "deception-cowrie-state"
}

resource "docker_container" "cowrie" {
  name     = "cowrie-01"
  hostname = "fileserver"
  image    = docker_image.cowrie.image_id
  start    = true
  must_run = false

  restart     = "unless-stopped"
  memory      = 512
  memory_swap = 1024
  cpu_shares  = 512

  networks_advanced {
    name = "deception-honeypots"
  }

  ports {
    internal = 2222
    external = 2222
    ip       = "10.77.10.10"
    protocol = "tcp"
  }

  volumes {
    host_path      = "/opt/deception/cowrie/cowrie.cfg"
    container_path = "/cowrie/cowrie-git/etc/cowrie.cfg"
    read_only      = true
  }

  volumes {
    host_path      = "/opt/deception/cowrie/userdb.txt"
    container_path = "/cowrie/cowrie-git/etc/userdb.txt"
    read_only      = true
  }

  volumes {
    volume_name    = docker_volume.cowrie_state.name
    container_path = "/cowrie/cowrie-git/var"
  }

  volumes {
    host_path      = "/var/log/deception/cowrie"
    container_path = "/cowrie/cowrie-git/var/log/cowrie"
  }

  log_driver = "json-file"

  log_opts = {
    "max-size" = "10m"
    "max-file" = "3"
  }
}
