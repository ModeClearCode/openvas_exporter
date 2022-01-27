import datetime
import os
import argparse
from datetime import date, timedelta
import time
from statistics import mean
from lxml.etree import Element
from gvm.connections import SSHConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, REGISTRY


class OpenvasCollector:

    def __init__(self, args):
        # Setup time range
        self.time_interval = args.time_interval
        now = datetime.datetime.now()
        self.to_date = date(now.year, now.month, now.day) + timedelta(days=1)
        self.from_date = self.to_date - timedelta(days=self.time_interval)
        self.server_ip = args.host

        # Create connection
        self.conn = SSHConnection(
            hostname=args.host,
            username=args.user,
            password=args.ssh_pass,
            port=args.ssh_port)
        transform = EtreeTransform()
        with Gmp(self.conn, transform=transform) as self.gmp:
            self.gmp.authenticate(args.login, args.openvas_pass)

    def collect(self):

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

        max_index = max(index_list)
        avg = max_index - mean(index_list)
        sec_index = (max_index ** 2 - avg) ** 0.5
        result_sums = {'low': sum_low, 'medium': sum_medium, 'high': sum_high,
                       'sec_index': sec_index}
        print(
            f'Summary of results from {self.from_date.isoformat()} '
            f'to {self.to_date.isoformat()}'
        )
        print(f'High: {int(sum_high)}')
        print(f'Medium: {int(sum_medium)}')
        print(f'Low: {int(sum_low)}')
        for key in result_sums:
            metrics_total[key].add_metric([self.server_ip], result_sums[key])
            yield metrics_total[key]

    def get_results_xml(self) -> Element:
        # Getting the Results in the defined time period
        report_filter = (
            f'levels=hml rows=-1 created>{self.from_date.isoformat()} and '
            f'created<{self.to_date.isoformat()}'
        )
        return self.gmp.get_results(filter_string=report_filter)


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
    print(f'Founded {len(table_data)} host results.\n')
    return table_data


def list_add(res_list, severity, name):
    if 0 < severity < 4:
        res_list[3] += 1
    elif 4 <= severity < 7:
        res_list[2] += 1
    elif 7 <= severity <= 10:
        res_list[1] += 1
    if res_list[4] < 100:
        res_list[4] += (severity ** 4) / 1000
    if res_list[4] > 100:
        res_list[4] = 100
    res_list[5].append(name)
    return res_list


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-o', '--host',
        dest='host',
        required=True,
        help='Openvas host ip',
        default=os.environ.get('OPENVAS_SSH_HOST')
    )
    parser.add_argument(
        '-u', '--user',
        dest='user',
        required=True,
        help='User for ssh on openvas host',
        default=os.environ.get('OPENVAS_SSH_USER')
    )
    parser.add_argument(
        '-ss', '--ssh-secret',
        dest='ssh_pass',
        required=True,
        help='Password for ssh on openvas host',
        default=os.environ.get('OPENVAS_SSH_PASSWORD')
    )
    parser.add_argument(
        '-sp', '--ssh-port',
        dest='ssh_port',
        required=False,
        type=int,
        help='Port for ssh on openvas host. Default = 22',
        default=os.environ.get('OPENVAS_SSH_PORT', '22')
    )
    parser.add_argument(
        '-p', '--port',
        dest='port',
        required=False,
        type=int,
        help='Listen to this port. Default = 9111',
        default=int(os.environ.get('OPENVAS_EXPORTER_PORT', '9111'))
    )
    parser.add_argument(
        '-l', '--login',
        dest='login',
        required=True,
        help='login for openvas api',
        default=os.environ.get('OPENVAS_USER')
    )
    parser.add_argument(
        '-os', '--openvas-secret',
        dest='openvas_pass',
        required=True,
        help='password for openvas api',
        default=os.environ.get('OPENVAS_PASSWORD')
    )
    parser.add_argument(
        '-si', '--scrape-interval',
        dest='scr_interval',
        required=False,
        type=int,
        help='Scrape interval time, in seconds. Default = 10 sec',
        default=os.environ.get('OPENVAS_EXPORTER_INTERVAL', '10')
    )
    parser.add_argument(
        '-t', '--time-interval',
        dest='time_interval',
        required=False,
        type=int,
        help='Scan time interval, in days. Default = 14 days',
        default=os.environ.get('OPENVAS_TIME_INTERVAL', '14')
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        print("Connecting to Openvas on: " + args.host)
        start_http_server(args.port)
        REGISTRY.register(OpenvasCollector(args))
        while True:
            time.sleep(args.scr_interval)
    except KeyboardInterrupt:
        print("\nQuitting...")
        exit(0)


if __name__ == '__main__':
    main()
