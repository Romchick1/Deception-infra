#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

usage() {
  cat <<'HELP'
sudo bash prepare-vm.sh monitoring <host-only-if> <admin-if>
sudo bash prepare-vm.sh control    <host-only-if>
sudo bash prepare-vm.sh decoy      <decoy-if> <admin-if>
sudo bash prepare-vm.sh test       <decoy-if>

Run from the VirtualBox console on Ubuntu Server 24.04 LTS, amd64.
Connect a separate NAT adapter with DHCP for package downloads.
HELP
}

if [[ ${1:-} == --help ]]; then
  usage
  exit 0
fi
die() { printf '%s\n' "$*" >&2; exit 1; }
[[ $EUID == 0 ]] || die 'Run with sudo.'
role=${1:-}
case "$role" in
  monitoring) addresses=(192.168.56.20/24 10.77.20.10/24) ;;
  control)    addresses=(192.168.56.10/24) ;;
  decoy)      addresses=(10.77.10.10/24 10.77.20.20/24) ;;
  test)       addresses=(10.77.10.100/24) ;;
  *) usage >&2; exit 2 ;;
esac
shift
[[ $# == "${#addresses[@]}" ]] || { usage >&2; exit 2; }

. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 && $(dpkg --print-architecture) == amd64 ]] ||
  die 'This bootstrap targets Ubuntu Server 24.04 LTS amd64.'
id labadmin >/dev/null 2>&1 || die 'Create user labadmin during Ubuntu installation.'
command -v netplan >/dev/null || die 'Netplan is required.'
interfaces=("$@")
[[ $# != 2 || $1 != "$2" ]] || die 'Use distinct network adapters.'
for iface in "${interfaces[@]}"; do
  [[ $iface =~ ^[[:alnum:]][[:alnum:]_-]{0,14}$ && $iface != lo ]] ||
    die "Invalid interface: $iface"
  ip link show dev "$iface" >/dev/null || die "No such interface: $iface"
  if ip -4 route show default dev "$iface" | grep -q .; then
    die "Refusing to configure the interface carrying the default route: $iface"
  fi
done
if [[ $role == decoy && $1 != enp0s8 ]]; then
  die 'The existing deception-firewall expects the decoy interface enp0s8.'
fi
[[ -n $(ip -4 route show default) ]] || die 'Enable the NAT adapter and its DHCP route first.'

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
netplan_file=/etc/netplan/90-deception-lab.yaml
{
  printf 'network:\n  version: 2\n  ethernets:\n'
  for index in "${!interfaces[@]}"; do
    printf '    %s:\n      dhcp4: false\n      addresses: [%s]\n' \
      "${interfaces[index]}" "${addresses[index]}"
  done
} > "$work/lab.yaml"

if [[ -e $netplan_file ]]; then
  cp -a -- "$netplan_file" "$work/previous.yaml"
fi
install -m 0600 "$work/lab.yaml" "$netplan_file"
if ! netplan generate || ! netplan apply; then
  if [[ -e $work/previous.yaml ]]; then
    cp -a -- "$work/previous.yaml" "$netplan_file"
  else
    rm -f -- "$netplan_file"
  fi
  netplan apply || true
  die 'Netplan validation or application failed. Previous file restored.'
fi

hostnamectl set-hostname "$role"
if grep -q '^127\.0\.1\.1[[:space:]]' /etc/hosts; then
  sed -i -E "s/^127\.0\.1\.1[[:space:]].*/127.0.1.1 $role/" /etc/hosts
else
  printf '127.0.1.1 %s\n' "$role" >> /etc/hosts
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg openssh-server python3
systemctl enable --now ssh.service
install -d -m 0755 /etc/apt/keyrings

apt_repo() {
  local name="$1" key_url="$2" repo_url="$3" suite="$4" component="$5"
  local key="/etc/apt/keyrings/${name}-deception.gpg"
  curl --fail --silent --show-error --location "$key_url" -o "$work/$name.asc"
  gpg --batch --yes --dearmor -o "$work/$name.gpg" "$work/$name.asc"
  install -m 0644 "$work/$name.gpg" "$key"
  printf 'deb [arch=amd64 signed-by=%s] %s %s %s\n' \
    "$key" "$repo_url" "$suite" "$component" > "/etc/apt/sources.list.d/${name}-deception.list"
  apt-get update
}

installed() {
  [[ $(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true) == 'install ok installed' ]]
}

install_agent() {
  if ! installed wazuh-agent; then
    apt_repo wazuh https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      https://packages.wazuh.com/4.x/apt/ stable main
    local version
    version="$(apt-cache madison wazuh-agent | awk '$3 ~ /^4\.14\./ && !found { print $3; found=1 }')"
    [[ -n $version ]] || die 'No Wazuh 4.14 agent package found.'
    WAZUH_MANAGER="$1" WAZUH_REGISTRATION_SERVER="$1" WAZUH_AGENT_NAME="$role" \
      apt-get install -y "wazuh-agent=$version"
  fi
  [[ -s /var/ossec/etc/ossec.conf ]] ||
    die 'Wazuh agent configuration is missing. Repair the package installation before deployment.'
  systemctl daemon-reload
  systemctl enable --now wazuh-agent.service
  systemctl is-active --quiet wazuh-agent.service
}

case "$role" in
  monitoring)
    apt-get install -y acl jq
    if ! installed wazuh-manager || ! installed wazuh-indexer || ! installed wazuh-dashboard; then
      for package in wazuh-manager wazuh-indexer wazuh-dashboard; do
        if installed "$package"; then
          die 'Partial Wazuh installation detected. Check the installer log before retrying.'
        fi
      done
      wazuh_dir=/root/deception-wazuh-install
      install -d -m 0700 "$wazuh_dir"
      curl --fail --silent --show-error --location \
        https://packages.wazuh.com/4.14/wazuh-install.sh -o "$wazuh_dir/wazuh-install.sh"
      (cd "$wazuh_dir" && bash ./wazuh-install.sh -a)
    fi
    conf=/var/ossec/etc/ossec.conf
    if ! grep -Eq '<logall_json>[[:space:]]*yes[[:space:]]*</logall_json>' "$conf"; then
      count="$(grep -Ec '<logall_json>[[:space:]]*no[[:space:]]*</logall_json>' "$conf" || true)"
      [[ $count == 1 ]] || die 'Expected one logall_json setting in ossec.conf.'
      cp -a -- "$conf" "$work/ossec.conf"
      sed -i -E 's|<logall_json>[[:space:]]*no[[:space:]]*</logall_json>|<logall_json>yes</logall_json>|' "$conf"
      if ! /var/ossec/bin/wazuh-analysisd -t || ! systemctl restart wazuh-manager; then
        cp -a -- "$work/ossec.conf" "$conf"
        systemctl restart wazuh-manager || true
        die 'Wazuh archive configuration rolled back.'
      fi
    fi
    for service in wazuh-manager wazuh-indexer wazuh-dashboard; do
      systemctl is-active "$service"
    done
    ;;
  control)
    apt-get install -y ansible git jq rsync util-linux
    if ! command -v terraform >/dev/null; then
      apt_repo hashicorp https://apt.releases.hashicorp.com/gpg \
        https://apt.releases.hashicorp.com "$VERSION_CODENAME" main
      apt-get install -y terraform
    fi
    install_agent 192.168.56.20
    ;;
  decoy)
    apt-get install -y iptables
    if ! installed docker-ce; then
      apt_repo docker https://download.docker.com/linux/ubuntu/gpg \
        https://download.docker.com/linux/ubuntu "$VERSION_CODENAME" stable
      apt-get install -y docker-ce docker-ce-cli containerd.io
    fi
    systemctl enable --now docker.service
    usermod -aG docker labadmin
    install_agent 10.77.20.10
    ;;
  test)
    apt-get install -y netcat-openbsd
    ;;
esac

ip -br -4 address
printf 'Bootstrap complete for %s.\n' "$role"
