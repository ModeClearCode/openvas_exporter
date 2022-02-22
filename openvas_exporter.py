import datetime
import os
import argparse
import logging
from datetime import date, timedelta
from sys import exit
import time
from statistics import mean
from lxml.etree import Element
from gvm.connections import SSHConnection
from gvm.connections import TLSConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, REGISTRY

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('openvas_exporter')


class OpenvasCollector:

    def __init__(self, args, i):

        self.i = i
        self.args = args
        # Setup time range
        self.time_interval = args.time_interval
        now = datetime.datetime.now()
        self.to_date = date(now.year, now.month, now.day) + timedelta(days=1)
        self.from_date = self.to_date - timedelta(days=self.time_interval)
        self.server_ip = args.host

        # Create connection
        if args.connection.lower() == 'ssh':
            if args.user is None:
                logger.error('User for ssh on OpenVAS server is not set.')
                exit(1)
            self.conn = SSHConnection(
                hostname=args.host,
                username=args.user,
                password=args.ssh_pass,
                port=args.ssh_port,
                timeout=30
            )
        elif args.connection.lower() == 'tls':
            if args.cert_file is None or args.ca_file is None or args.private_key is None:
                logger.error('Parameters for tls-connection on OpenVAS server is not set.')
                exit(1)
            self.conn = TLSConnection(
                hostname=args.host,
                certfile=args.cert_file,
                cafile=args.ca_file,
                keyfile=args.private_key,
                password=args.pass_key,
                port=args.tls_port,
                timeout=30
            )
        else:
            logger.error('Unknown connection type. Use ssh or tls.')
            exit(1)
        try:
            transform = EtreeTransform()
            with Gmp(self.conn, transform=transform) as self.gmp:
                self.gmp.authenticate(args.login, args.openvas_pass)
        except GvmError as e:
            logger.error(f'Connection is failed. Check if address is correct! Exporter will try to connect after '
                         f'{10*self.args.to_interval}s.')
            logger.debug(f'Details: {e}')
            time.sleep(10*self.args.to_interval)
            logger.info('Last try to connect was unsuccessful. Trying again...')
            self.__init__(self.args, 1)

    def collect(self):
        now = datetime.datetime.now()
        if self.to_date == date(now.year, now.month, now.day):
            logger.info(f'Refreshing date...')
            self.to_date = date(now.year, now.month, now.day) + timedelta(days=1)
            self.from_date = self.to_date - timedelta(days=self.time_interval)
        metrics_total = {
            'low':
                GaugeMetricFamily('openvas_total_low', 'Total sum low-level vulnerabilities per last'
                                                       f' {self.time_interval} days', labels=['server_ip']),
            'medium':
                GaugeMetricFamily('openvas_total_medium', f'Total sum medium-level vulnerabilities per last'
                                                          f' {self.time_interval} days', labels=['server_ip']),
            'high':
                GaugeMetricFamily('openvas_total_high', f'Total sum high-level vulnerabilities per last'
                                                        f' {self.time_interval} days', labels=['server_ip']),
            'sec_index':
                GaugeMetricFamily('openvas_total_sec_index', f'Total index of security per last'
                                                             f' {self.time_interval} days.'
                                                             f' From 0 to 10. 7+ = high risk',
                                  labels=['server_ip'])
        }

        metrics_host = {
            'openvas_host_low':
                GaugeMetricFamily('openvas_host_low', f'Quantity low-level vulnerabilities on host per last'
                                                      f' {self.time_interval} days',
                                  labels=['server_ip', 'hostname', 'ip']),
            'openvas_host_medium':
                GaugeMetricFamily('openvas_host_medium', f'Quantity medium-level vulnerabilities on host per last'
                                                         f' {self.time_interval} days',
                                  labels=['server_ip', 'hostname', 'ip']),
            'openvas_host_high':
                GaugeMetricFamily('openvas_host_high', f'Quantity high-level vulnerabilities on host per last'
                                                       f' {self.time_interval} days',
                                  labels=['server_ip', 'hostname', 'ip']),
            'openvas_host_sec_index':
                GaugeMetricFamily('openvas_host_sec_index', f'Index of security on host per last'
                                                            f' {self.time_interval} days. From 0 to 10. 7+ = high risk',
                                  labels=['server_ip', 'hostname', 'ip'])
        }

        sum_low = 0
        sum_medium = 0
        sum_high = 0
        index_list = []

        results = self.get_results_xml()
        result_hosts = get_result_hosts(results)

        for ip in result_hosts:
            values_list = result_hosts[ip]
            sum_high += values_list[1]
            sum_medium += values_list[2]
            sum_low += values_list[3]
            index_list.append(values_list[4])
            metrics_host['openvas_host_high'].add_metric([self.server_ip, values_list[0], ip],
                                                         values_list[1])
            metrics_host['openvas_host_medium'].add_metric([self.server_ip, values_list[0], ip],
                                                           values_list[2])
            metrics_host['openvas_host_low'].add_metric([self.server_ip, values_list[0], ip],
                                                        values_list[3])
            metrics_host['openvas_host_sec_index'].add_metric([self.server_ip, values_list[0], ip],
                                                              values_list[4])
        for metric in metrics_host.values():
            yield metric
        if len(result_hosts) > 0:
            max_index = max(index_list)
            avg = max_index - mean(index_list)
            sec_index = (max_index ** 2 - avg) ** 0.5
            result_sums = {'low': sum_low, 'medium': sum_medium, 'high': sum_high,
                           'sec_index': sec_index}
            logger.info(
                f'Summary of results from {self.from_date.isoformat()} '
                f'to {(self.to_date - timedelta(days=1)).isoformat()}'
            )
            logger.info(f'High: {int(sum_high)}, Medium: {int(sum_medium)}, Low: {int(sum_low)}')
            for key in result_sums:
                metrics_total[key].add_metric([self.server_ip], result_sums[key])
                yield metrics_total[key]

    def get_results_xml(self) -> Element:
        # Getting the Results in the defined time period
        report_filter = (
            f'levels=hml rows=-1 created>{self.from_date.isoformat()} and '
            f'created<{self.to_date.isoformat()}'
        )
        try:
            results = self.gmp.get_results(filter_string=report_filter)
        except (GvmError, BrokenPipeError, OSError) as e:
            if self.i == 4:
                logger.error(f'Cannot connect after 3 retries. Trying to reconnect after {self.args.to_interval}s.')
            if self.i > 3:
                time.sleep(self.args.to_interval)
            logger.warning(f'Caught exception! Connection # {self.i} was corrupted. Trying to reconnect...')
            logger.debug(f'Details: {e}')
            self.__init__(self.args, self.i + 1)
            self.get_results_xml()
        else:
            self.i = 1
            return results


def get_result_hosts(results_xml: Element):
    results_list = results_xml.xpath('result')
    table_data = {}
    # ['Hostname', 'high', 'medium', 'low', 'index', [names]]
    for result in results_list:
        ip = result.xpath('host/text()')[0]
        hostname = result.xpath('host/hostname/text()')
        if len(hostname) > 0:
            hostname = str(hostname[0])
        else:
            hostname = ""
        severity = float(result.xpath('severity/text()')[0])
        name = result.xpath('name/text()')[0]
        if ip in table_data:
            if name not in table_data[ip][5]:  # Check if duplicates
                table_data[ip] = list_add(table_data[ip], severity, name)
        else:
            if 0 < severity < 4:
                table_data[ip] = [hostname, 0, 0, 1, (severity ** 4) / 1000, [name]]
            elif 4 <= severity < 7:
                table_data[ip] = [hostname, 0, 1, 0, (severity ** 4) / 1000, [name]]
            elif 7 <= severity <= 10:
                table_data[ip] = [hostname, 1, 0, 0, (severity ** 4) / 1000, [name]]
    logger.info(f'Founded {len(table_data)} host results.\n')
    return table_data


def list_add(res_list, severity, name):
    if 0 < severity < 4:
        res_list[3] += 1
    elif 4 <= severity < 7:
        res_list[2] += 1
    elif 7 <= severity <= 10:
        res_list[1] += 1
    if res_list[4] < 10:
        res_list[4] += (severity ** 4) / 1000
    if res_list[4] > 10:
        res_list[4] = 10
    res_list[5].append(name)
    return res_list


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-o', '--hostname',
        dest='host',
        required=False,
        help='DNS name or IP address of the remote OpenVAS server',
        default=os.environ.get('OPENVAS_HOSTNAME')
    )
    parser.add_argument(
        '-u', '--user',
        dest='user',
        required=False,
        help='User for ssh on OpenVAS server. Required for ssh-type connection.',
        default=os.environ.get('OPENVAS_SSH_USER')
    )
    parser.add_argument(
        '-ss', '--ssh-secret',
        dest='ssh_pass',
        required=False,
        help='Password for ssh on OpenVAS server. Required for ssh-type connection.',
        default=os.environ.get('OPENVAS_SSH_PASSWORD')
    )
    parser.add_argument(
        '-cf', '--cert-file',
        dest='cert_file',
        required=False,
        help='Path to PEM encoded certificate file. Required for tls-type connection.',
        default=os.environ.get('OPENVAS_TLS_CERT')
    )
    parser.add_argument(
        '-ca', '--ca-file',
        dest='ca_file',
        required=False,
        help='Path to PEM encoded CA file. Required for tls-type connection.',
        default=os.environ.get('OPENVAS_TLS_CA')
    )
    parser.add_argument(
        '-pk', '--private-key',
        dest='private_key',
        required=False,
        help='Path to PEM encoded private key. Required for tls-type connection.',
        default=os.environ.get('OPENVAS_TLS_KEY')
    )
    parser.add_argument(
        '-ppk', '--pass-key',
        dest='pass_key',
        required=False,
        help='Password for the private key. Required for tls-type connection, if set.',
        default=os.environ.get('OPENVAS_TLS_PASS_KEY')
    )
    parser.add_argument(
        '-tp', '--tls-port',
        dest='tls_port',
        required=False,
        type=int,
        help='Port for tls on OpenVAS server. Required for tls-type connection. Default = 9390',
        default=os.environ.get('OPENVAS_TLS_PORT', '9390')
    )
    parser.add_argument(
        '-sp', '--ssh-port',
        dest='ssh_port',
        required=False,
        type=int,
        help='Port for ssh on OpenVAS server. Required for ssh-type connection. Default = 22',
        default=os.environ.get('OPENVAS_SSH_PORT', '22')
    )
    parser.add_argument(
        '-p', '--port',
        dest='port',
        required=False,
        type=int,
        help='Listen to this port. Default = 9966',
        default=int(os.environ.get('OPENVAS_EXPORTER_PORT', '9966'))
    )
    parser.add_argument(
        '-l', '--login',
        dest='login',
        required=False,
        help='Login for GSA',
        default=os.environ.get('OPENVAS_USER')
    )
    parser.add_argument(
        '-os', '--openvas-secret',
        dest='openvas_pass',
        required=False,
        help='Password for GSA',
        default=os.environ.get('OPENVAS_PASSWORD')
    )
    parser.add_argument(
        '-t', '--timeout',
        dest='to_interval',
        required=False,
        type=int,
        help='Timeout interval after connection loss, also multiplied by 10 for the first connection, in seconds.'
             ' Default = 10 sec',
        default=os.environ.get('OPENVAS_TIMEOUT_INTERVAL', '10')
    )
    parser.add_argument(
        '-ti', '--time-interval',
        dest='time_interval',
        required=False,
        type=int,
        help='Scan time interval, in days. Default = 14 days',
        default=os.environ.get('OPENVAS_TIME_INTERVAL', '14')
    )
    parser.add_argument(
        '-c', '--connection',
        dest='connection',
        required=False,
        help='OpenVAS connection type to use by exporter. Options: ssh or tls. Default = ssh',
        default=os.environ.get('OPENVAS_CONN_TYPE', 'ssh')
    )
    parser.add_argument(
        '-d', '--debug',
        dest='debug',
        action='store_true',
        required=False,
        help='Enable debug output. Default = False',
        default=os.environ.get('OPENVAS_EXPORTER_DEBUG', False)
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    if args.host is None:
        logger.error('Hostname/IP of OpenVAS server is not set.')
        exit(1)
    try:
        logger.info("Connecting to Openvas on: " + args.host)
        start_http_server(args.port)
        REGISTRY.register(OpenvasCollector(args, 1))
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nQuitting...")
        exit(0)


if __name__ == '__main__':
    main()
