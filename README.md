# Deception-Infra

Автоматизированный лабораторный стенд OpenCanary, Cowrie и Wazuh для дипломного проекта.

## Подготовка ВМ

Поддерживается Ubuntu Server 24.04 LTS amd64, пользователь `labadmin` с sudo.
На всех ВМ нужен отдельный NAT-адаптер с DHCP для загрузки пакетов.
Статические лабораторные интерфейсы передаются в `prepare-vm.sh` явно.
Запускайте настройку сети из консоли VirtualBox.

| Роль | Host-only | Сеть администрирования | Сеть приманок |
| --- | --- | --- | --- |
| monitoring | 192.168.56.20/24 | 10.77.20.10/24 | |
| control | 192.168.56.10/24 | | |
| decoy | | 10.77.20.20/24 | 10.77.10.10/24 |
| test | | | 10.77.10.100/24 |

Сначала подготовьте monitoring. Примеры для обычной нумерации адаптеров VirtualBox

```bash
sudo bash prepare-vm.sh monitoring enp0s8 enp0s9
sudo bash prepare-vm.sh control enp0s8
sudo bash prepare-vm.sh decoy enp0s8 enp0s9
sudo bash prepare-vm.sh test enp0s8
```

На каждой машине выполняется только команда её роли. У decoy `enp0s8` относится к сети приманок.
Имена внутренних сетей VirtualBox должны совпадать у подключённых к одному сегменту ВМ.
Для установки с GitHub скачайте `prepare-vm.sh` из корня выбранного тега релиза.
Скрипт устанавливает Wazuh ветки 4.14. Используйте одинаковый актуальный выпуск на новых ВМ.
После подготовки проверьте наличие `/var/ossec/etc/ossec.conf` и активность агента на control и decoy.
Данные доступа к Wazuh сохраняет официальный установщик в `/root/deception-wazuh-install` на monitoring.

## SSH с control

От имени labadmin добавьте в `~/.ssh/config`

```sshconfig
Host monitoring
    HostName 192.168.56.20
    User labadmin

Host decoy
    HostName 10.77.20.20
    User labadmin
    ProxyJump monitoring
```

```bash
test -f ~/.ssh/id_ed25519.pub || ssh-keygen -t ed25519
ssh-copy-id monitoring
ssh-copy-id decoy
ssh monitoring hostname
ssh decoy 'hostname && docker ps'
```

Первый вход запоминает ключи хостов. В Wazuh оба агента должны получить статус Active.

## Установка из GitHub

После публикации исправлений создайте новый тег и укажите его вместо RELEASE.

```bash
curl -fSL https://raw.githubusercontent.com/Romchick1/Deception-infra/RELEASE/install.sh -o /tmp/deception-install.sh
bash /tmp/deception-install.sh https://github.com/Romchick1/Deception-infra.git RELEASE
```

Запускайте от labadmin без sudo. Playbook сам запрашивает пароль повышения прав.
Проект устанавливается в `/home/labadmin/deception-infra`, который используют systemd и сбор журналов.
Загрузчик умеет получать новый тег и переключать чистую рабочую копию на него.
Перед обновлением сохраните локальные изменения отслеживаемых файлов в коммите.
Состояния Terraform, журналы, очередь и локальная политика реагирования хранятся на control.
Обновление кода сохраняет эти данные. Состояния Terraform требуются для управления существующими ресурсами.

`deploy.sh` проверяет агенты и Docker, применяет Ansible, включает firewall,
последовательно применяет Terraform shared, opencanary, cowrie, проверяет порты и запускает watchdog.
На время повторного развёртывания действующий watchdog останавливается.
При ошибке исправьте причину и повторите `bash scripts/deploy.sh`, чтобы завершить запуск службы.
Terraform требует подтверждения плана `yes`, а значения образов загружает из включённых terraform.tfvars.
В Cowrie используется демонстрационная учётная запись `root` с паролем `lab-demo`.

## Проверка и автоматический сброс

С test выполните `ssh -p 2222 root@10.77.10.10`. Проверьте события Cowrie в Wazuh.
На control проверьте `systemctl is-active deception-watchdog` и журнал службы.
Повторное развёртывание должно показать `No changes` для всех трёх модулей Terraform.

Новая установка использует предусмотренный кодом режим с выключенным автоматическим сбросом состояния Cowrie.
После проверки доставки событий и запуска watchdog включите его существующим интерфейсом политики

```bash
cd ~/deception-infra
sudo systemctl stop deception-watchdog
python3 scripts/security_policy.py enable --reason 'Приёмка автоматического сброса на новом стенде'
sudo systemctl start deception-watchdog
python3 scripts/security_policy.py status
```

Команда требует созданную watchdog базу runtime/watchdog.sqlite3. Политика устанавливает новое enabled_since,
чтобы обрабатывать сессии после включения. Локальная configs/security-response.json исключена из Git.
Перед сбросом проверяются завершение сессий и архивирование. Результат фиксируется в runtime/operations.jsonl и Wazuh.

## Проверки исходников

```bash
bash -n install.sh prepare-vm.sh scripts/deploy.sh
ansible-playbook -i ansible/inventory.yml ansible/configure-wazuh.yml --syntax-check
ansible-playbook -i ansible/inventory.yml ansible/preflight.yml -K
```

Полная приёмка требует ВМ VirtualBox и контрольного события от test.
