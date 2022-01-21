import datetime
import os
import argparse
from datetime import date, timedelta
import time
from lxml.etree import Element
from gvm.connections import SSHConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, REGISTRY


class OpenvasCollector:

    def __init__(self, args):
        # Setup time range
        now = datetime.datetime.now()
        self.to_date = date(now.year, now.month, now.day) + timedelta(days=1)
        self.from_date = self.to_date - timedelta(days=31)
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
                GaugeMetricFamily('openvas_total_low', 'Total sum low-level vulnerabilities per last 30 days',
                                  labels=['server_ip']),
            'medium':
                GaugeMetricFamily('openvas_total_medium', 'Total sum medium-level vulnerabilities per last 30 days',
                                  labels=['server_ip']),
            'high':
                GaugeMetricFamily('openvas_total_high', 'Total sum high-level vulnerabilities per last 30 days',
                                  labels=['server_ip'])
        }

        metrics_host = {
            'openvas_host_low':
                GaugeMetricFamily('openvas_total_low', 'Quantity low-level vulnerabilities on host per last 30 days',
                                  labels=['server_ip', 'hostname', 'ip', 'report']),
            'openvas_host_medium':
                GaugeMetricFamily('openvas_total_medium', 'Quantity medium-level vulnerabilities on host per last 30 '
                                                          'days',
                                  labels=['server_ip', 'hostname', 'ip', 'report']),
            'openvas_host_high':
                GaugeMetricFamily('openvas_total_high', 'Quantity high-level vulnerabilities on host per last 30 days',
                                  labels=['server_ip', 'hostname', 'ip', 'report'])
        }

        reports = self.get_reports_xml()
        pretty_print(reports)
        result_sums = self.get_result_sums(reports)
        result_hosts = self.get_result_hosts(reports)
        for key in result_sums:
            metrics_total[key].add_metric([self.server_ip], result_sums[key])
            yield metrics_total[key]
        for host_list in result_hosts:
            metrics_host['openvas_host_high'].add_metric([self.server_ip, host_list[0], host_list[1], host_list[2]],
                                                         host_list[3])
            metrics_host['openvas_host_medium'].add_metric([self.server_ip, host_list[0], host_list[1], host_list[2]],
                                                           host_list[4])
            metrics_host['openvas_host_low'].add_metric([self.server_ip, host_list[0], host_list[1], host_list[2]],
                                                        host_list[5])
        for metric in metrics_host.values():
            yield metric

    def get_reports_xml(self) -> Element:
        # Getting the Reports in the defined time period

        report_filter = (
            f'levels=hml rows=-1 created>{self.from_date.isoformat()} and '
            f'created<{self.to_date.isoformat()}'
        )

        return self.gmp.get_reports(filter_string=report_filter)

    def get_result_sums(self, reports_xml: Element):
        report_count = len(reports_xml.xpath('report'))
        print(f'Found {report_count} reports\n')

        sum_high = reports_xml.xpath(
            'sum(report/report/result_count/hole/full/text())'
        )
        sum_medium = reports_xml.xpath(
            'sum(report/report/result_count/warning/full/text())'
        )
        sum_low = reports_xml.xpath(
            'sum(report/report/result_count/info/full/text())'
        )

        total = {'low': int(sum_low), 'medium': int(sum_medium), 'high': int(sum_high)}
        print(
            f'Summary of results from {self.from_date.isoformat()} '
            f'to {self.to_date.isoformat()}'
        )
        print(f'High: {int(sum_high)}')
        print(f'Medium: {int(sum_medium)}')
        print(f'Low: {int(sum_low)}')
        return total

    def get_result_hosts(self, reports_xml: Element):
        report_list = reports_xml.xpath('report')
        table_data = []
        # ['Hostname', 'IP', 'Bericht', 'high', 'medium', 'low']
        for report in report_list:
            report_id = report.xpath('report/@id')[0]
            name = report.xpath('name/text()')[0]

            res = self.gmp.get_report(report_id)

            print(f'\nReport: {report_id}------------------------')


            for host in res.xpath('report/report/host'):
                hostname = host.xpath(
                    'detail/name[text()="hostname"]/../' 'value/text()'
                )
                if len(hostname) > 0:
                    hostname = str(hostname[0])
                else:
                    hostname = ""

                ip = host.xpath('ip/text()')[0]
                high = host.xpath('result_count/hole/page/text()')[0]
                medium = host.xpath('result_count/warning/page/text()')[0]
                low = host.xpath('result_count/info/page/text()')[0]
                print(f'{hostname}, {ip}, {name}, {high}, {medium}, {low}++++++++++\n')

                table_data.append([hostname, ip, name, high, medium, low])
        print(f'Founded {len(table_data)} host reports.\n')
        return table_data


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
        '-ss', '--ssh-password',
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
        '-os', '--openvas-password',
        dest='openvas_pass',
        required=True,
        help='password for openvas api',
        default=os.environ.get('OPENVAS_PASSWORD')
    )
    parser.add_argument(
        '-si', '--scrape-interval',
        dest='interval',
        required=False,
        type=int,
        help='Scrape interval time, in seconds. Default = 10 sec',
        default=os.environ.get('OPENVAS_EXPORTER_INTERVAL', '10')
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        print("Connecting to Openvas on: " + args.host)
        start_http_server(args.port)
        REGISTRY.register(OpenvasCollector(args))
        while True:
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nQuitting...")
        exit(0)


if __name__ == '__main__':
    main()
