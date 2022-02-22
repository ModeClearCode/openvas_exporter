# OpenVAS exporter
OpenVAS (also known as GSM) exporter for prometheus.
Supports SSH and TLS (not tested) connections. Tested with GVM Version 21.4.3, another versions not tested, so, there is no guarantee that the exporter will work.
## Usage and preparations
There is 2 variation of use exporter: compiled package with dependencies (download in releases) or pure python script from sources, but need to install dependencies.
### Dependencies
If you choose pure python script, you need to install following libs with pip:
```
pip install lxml prometheus-client python-gvm
```
### SSH connection for GVM
You need some setup on GVM Server for SSH connection, first of all install and enable ssh:
```
apt/yum install ssh
systemctl enable ssh
systemctl start ssh
```
Install socat:
``` 
apt/yum install socat
```
Create user with shell, connected to gvm unix-socket
```
echo "#! /bin/bash
socat UNIX:/var/run/gvm/gvmd.sock -
" > /home/shell.sh

chmod +x  /home/shell.sh
useradd -s /home/shell.sh user
usermod -a -G _gvm user
```
_Group can be **gvm** and another path to socket file, depends on your GVM installation_.

### Environments

Environment | Flag | Descripton | Default |
------------|------|------------|---------|
OPENVAS_CONN_TYPE | '-c', '--connection' | OpenVAS connection type to use by exporter. Options: ssh or tls. | ssh
OPENVAS_EXPORTER_PORT | '-p', '--port' | Listen to this port. | 9966
OPENVAS_EXPORTER_DEBUG | '-d', '--debug' | Enable debug output. | False
OPENVAS_TIME_INTERVAL | '-ti', '--time-interval' | Exporter generates metrics from reports for a certain interval of days. Scan time interval, in days. | 14
OPENVAS_TIMEOUT | '-t ', '--timeout' | Timeout interval after connection loss, also multiplied by 10 for the first connection, in seconds. | 10
OPENVAS_HOSTNAME | '-o', '--hostname' | DNS name or IP address of the remote OpenVAS server |
OPENVAS_USER | '-l', '--login' | Login for GSA |
OPENVAS_PASSWORD | '-os', '--openvas-secret' | Password for GSA |
OPENVAS_SSH_USER | '-u', '--user' | User for ssh on OpenVAS server. Required for ssh-type connection. |
OPENVAS_SSH_PASSWORD | '-ss', '--ssh-secret' | Password for ssh on OpenVAS server. Required for ssh-type connection. |
OPENVAS_SSH_PORT | '-sp', '--ssh-port' | Port for ssh on OpenVAS server. Required for ssh-type connection. | 22
OPENVAS_TLS_CERT | '-cf', '--cert-file' | Path to PEM encoded certificate file. Required for tls-type connection. |
OPENVAS_TLS_CA | '-ca', '--ca-file' | Path to PEM encoded CA file. Required for tls-type connection. |
OPENVAS_TLS_KEY | '-pk', '--private-key' | Path to PEM encoded private key. Required for tls-type connection. | 
OPENVAS_TLS_PASS_KEY | '-ppk', '--pass-key' | Password for the private key. Required for tls-type connection, if set. |
OPENVAS_TLS_PORT | '-tp', '--tls-port' | Port for tls on OpenVAS server. Required for tls-type connection. | 9390

Use example of systemd unit __openvas_exporter.service__ and envoroment's file __openvas_exporter.env__ for planned work in system.

## Grafana
You can use prepared grafana dashboard for this exporter.
![Grafana dashboard for OpenVAS exporter](/grafana/dash.jpg) 


