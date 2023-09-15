#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
# check_opnsense.py - A check plugin for monitoring OPNsense firewalls.
# Copyright (C) 2018  Nicolai Buchwitz <nb@tipi-net.de>
#
# Version: 0.1.0
#
# ------------------------------------------------------------------------------
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ------------------------------------------------------------------------------

from __future__ import print_function
import sys

try:
    from enum import Enum
    import argparse
    import json # is this needed?
    import requests
    import urllib3 # is this needed?

    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

except ImportError as e:
    print("Missing python module: {}".format(e.message))
    sys.exit(255)

MODES = {}

def checkmode(f):
    MODES[(f.__name__.replace('check', '').lower())] = f.__name__

    return f

class NagiosState(Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


class CheckOPNsense:
    VERSION = '0.1.0'
    API_URL = 'https://{}:{}/api/{}'

    options = {}
    perfdata = {}
    checkResult = -1
    checkMessage = ""
    checkLongOutput = []

    def checkOutput(self):
        message = self.checkMessage

        if len(self.checkLongOutput):
            message += "\n" + "\n".join(self.checkLongOutput)

        if self.perfdata:
            message += '|' + self.getPerfdata()

        self.output(self.checkResult, message)

    def getPerfdata(self):
        return ' '.join(['\'{0}\'={1}'.format(key, value) for (key, value) in self.perfdata.items()])

    def output(self, returnCode, message):
        prefix = returnCode.name

        message = '{} - {}'.format(prefix, message)

        print(message)
        sys.exit(returnCode.value)

    def getURL(self, part):
        return self.API_URL.format(self.options.hostname, self.options.port, part)

    def request(self, url, method='get', **kwargs):
        response = None
        try:
            if method == 'post':
                response = requests.post(
                    url,
                    verify=not self.options.api_insecure,
                    #verify=ssl.CERT_NONE,
                    auth=(self.options.api_key, self.options.api_secret),
                    data=kwargs.get('data', None),
                    timeout=5
                )
            elif method == 'get':
                response = requests.get(
                    url,
                    auth=(self.options.api_key, self.options.api_secret),
                    verify=not self.options.api_insecure,
                    #verify=CERT_NONE,
                    params=kwargs.get('params', None)
                )
            else:
                self.output(NagiosState.CRITICAL, "Unsupport request method: {}".format(method))
        except requests.exceptions.ConnectTimeout:
            self.output(NagiosState.UNKNOWN, "Could not connect to OPNsense: Connection timeout")
        except requests.exceptions.SSLError:
            self.output(NagiosState.UNKNOWN, "Could not connect to OPNsense: Certificate validation failed")
        except requests.exceptions.ConnectionError:
            self.output(NagiosState.UNKNOWN, "Could not connect to OPNsense: Failed to resolve hostname")

        if response.ok:
            return response.json()
        else:
            message = "Could not fetch data from API: "

            if response.status_code == 401:
                message += "Could not connection to OPNsense: invalid username or password"
            elif response.status_code == 403:
                message += "Access denied. Please check if API user has sufficient permissions."
            else:
                message += "HTTP error code was {}".format(response.status_code)

            self.output(NagiosState.UNKNOWN, message)

    def check(self):
        self.checkResult = NagiosState.OK

        try:
            f = getattr(self, MODES[self.options.mode])
            f()
        except (KeyError, AttributeError):
            message = "Check mode '{}' not known".format(self.options.mode)
            self.output(NagiosState.UNKNOWN, message)

        self.checkOutput()

    def parseOptions(self):
        p = argparse.ArgumentParser(description='Check command OPNsense firewall monitoring')

        api_opts = p.add_argument_group('API Options')

        api_opts.add_argument("-H", "--hostname", required=True, help="OPNsense hostname or ip address")
        api_opts.add_argument("-p", "--port", required=False, dest='port', help="OPNsense https-api port", default=80)
        api_opts.add_argument("--api-key", dest='api_key', required=True,
                              help="API key (See OPNsense user manager)")
        api_opts.add_argument("--api-secret", dest='api_secret', required=True,
                              help="API key (See OPNsense user manager)")
        api_opts.add_argument("-k", "--insecure", dest='api_insecure', action='store_true', default=False,
                              help="Don't verify HTTPS certificate")

        check_opts = p.add_argument_group('Check Options')

        check_opts.add_argument("-m", "--mode",
                                choices=MODES.keys(),
                                required=True,
                                help="Mode to use.")
        check_opts.add_argument('-w', '--warning', dest='treshold_warning', type=float,
                                help='Warning treshold for check value')
        check_opts.add_argument('-c', '--critical', dest='treshold_critical', type=float,
                                help='Critical treshold for check value')

        options = p.parse_args()

        self.options = options

    @checkmode
    def checkUpdates(self):
        url = self.getURL('core/firmware/status')
        data = self.request(url)

        if data['status'] == 'ok' and data['status_upgrade_action'] == 'all':
            count = data['updates']

            self.checkResult = NagiosState.WARNING
            self.checkMessage = "{} pending updates".format(count)

            if data['upgrade_needs_reboot']:
                self.checkResult = NagiosState.CRITICAL
                self.checkMessage = "{}. Subsequent reboot required.".format(self.checkMessage)
        else:
            self.checkMessage = "System up to date"

        self.checkMessage += ' (version={}/{})'.format(data['product_id'], data['product_version'])

        self.checkLongOutput.append(
            '* Last update check: {}'.format(data['last_check'])
        )

        self.checkLongOutput.append(
            '* OS version: {}'.format(data['os_version'])
        )

    @checkmode
    def checkRoutes(self):
        url = self.getURL('routes/gateway/status')
        data = self.request(url)

        if data['status'] == 'ok':
            count = 0
            count_max = len(data['items'])
            for item in data['items']:
                self.checkLongOutput.append('* {name} ({address}) **{status_translated}** (rtt={delay}, loss={loss})'.format(**item))
                if item['status_translated'] == 'Online':
                    count += 1

            self.checkMessage = 'Gateways online: {}/{}'.format(count, count_max)

            self.checkResult = NagiosState.UNKNOWN

            if count == 0 or count != count_max:
                self.checkResult = NagiosState.CRITICAL
            elif count == count_max:
                self.checkResult = NagiosState.OK

    @checkmode
    def checkIpsec(self):
        url = self.getURL('ipsec/service/status')
        data = self.request(url)

        if data['status'] == 'running':
            self.checkMessage = 'IPsec: {status}'.format(**data)
            self.checkResult = NagiosState.OK


    def __init__(self):
        self.parseOptions()

if __name__ == '__main__':
    opnsense = CheckOPNsense()
    opnsense.check()
