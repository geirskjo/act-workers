#!/usr/bin/env python3

'''iSight worker for the ACT platform

Copyright 2018 the ACT project <opensource@mnemonic.no>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

requirements:

'''


from functools import partialmethod
from logging import error, info
from typing import Generator, List, Optional, Text, Tuple, Set

import argparse
import collections
import contextlib
import email
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import requests
import sys
import time
import traceback
import urllib.parse
import warnings

import act.api
from act.api.helpers import handle_fact, handle_uri
from act.workers.libs import worker


def parseargs() -> argparse.ArgumentParser:
    """Extract command lines argument"""

    parser = worker.parseargs('ACT iSight Client')
    parser.add_argument('--privatekey', metavar='PRIVATEKEY',
                        help='iSight API key')
    parser.add_argument('--publickey', metavar='PUBLICKEY',
                        help='iSight API key')
    parser.add_argument(
        '--days',
        help='How many days back to look for data')
    parser.add_argument(
        '--root',
        help='api endpoint')

    return parser


def main() -> None:
    """main function"""

    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = worker.handle_args(parseargs())

    actapi = worker.init_act(args)

    if not (args.privatekey and args.publickey):
        worker.fatal("You must specify --privatekey and --publickey on command line or in config file")

    proxies = {
        'http': args.proxy_string,
        'https': args.proxy_string
    } if args.proxy_string else None

    iSightHandler = ISightAPIRequestHandler(args.root, args.privatekey, args.publickey)
    data = iSightHandler.indicators()

    if not data['success']:
        print("ERROR!")
        return

    ### DEBUG -- dump json to disc for each run
    with open("/tmp/error.json", "w") as f:
        json.dump(data, f)

    for i, dp in enumerate(data['message']):
        ### --- IP -> malwareFamily
        if dp['malwareFamily'] and dp['ip']:
            chain = act.api.fact.fact_chain(
                actapi.fact('connectsTo')
                .source('content', '*')
                .destination('uri', '*'),
                actapi.fact('componentOf')
                .source('ipv4', dp['ip'])
                .destination('uri', '*'),
                actapi.fact('classifiedAs')
                .source('content', '*')
                .destination('tool', dp['malwareFamily'].lower()))
            for fact in chain:
                handle_fact(fact)
        ### --- URL -> malwareFamily
        elif dp['networkType'] == 'url' and dp['malwareFamily']:
            handle_uri(actapi, dp['url'])
            chain = act.api.fact.fact_chain(
                actapi.fact('connectsTo')
                .source('content', '*')
                .destination('uri', dp['url']),
                actapi.fact('classifiedAs')
                .source('content', '*')
                .destination('tool', dp['malwareFamily'].lower()))
            for fact in chain:
                handle_fact(fact)
        ### --- FQDN -> malwareFamily
        elif dp['networkType'] == 'network' and dp['domain'] and dp['malwareFamily']:
            chain = act.api.fact.fact_chain(
                actapi.fact('connectsTo')
                .source('content', '*')
                .destination('uri', '*'),
                actapi.fact('componentOf')
                .source('fqdn', dp['domain'])
                .destination('uri', '*'),
                actapi.fact('classifiedAs')
                .source('content', '*')
                .destination('tool', dp['malwareFamily'].lower()))
            for fact in chain:
                handle_fact(fact)
        ### --- hash -> malwareFamily
        elif dp['fileType'] and dp['malwareFamily'] and (dp['sha1'] or dp['sha256'] or dp['md5']):
            for digest_type in ['md5', 'sha1', 'sha256']:
                ### In some cases the iSight api does not return a sha256 hashdigest
                ### so we need to make a chain through a placeholder content
                if not dp['sha256']:
                    if dp[digest_type]:
                        chain = act.api.fact.fact_chain(
                            actapi.fact('represents')
                            .source('hash', dp[digest_type])
                            .destination('content', '*'),
                            actapi.fact('classifiedAs')
                            .source('content', '*')
                            .destination('tool', dp['malwareFamily']))
                        for fact in chain:
                            handle_fact(fact)
                else:  ## There is a sha256, so we do _not_ need a chain
                    if dp[digest_type]:
                        handle_fact(actapi.fact('classifiedAs')
                                    .source('content', dp['sha256'])
                                    .destination('tool', dp['malwareFamily']))
                        handle_fact(actapi.fact('represents')
                                    .source('hash', dp[digest_type])
                                    .destination('content', dp['sha256']))
        ### -- Hash --> actor
        elif dp['fileType'] and dp['actor'] and (dp['sha1'] or dp['sha256'] or dp['md5']):
            for digest_type in ['md5', 'sha1', 'sha256']:
                ### In some cases the iSight api does not return a sha256 hashdigest
                ### so we need to make a chain through a placeholder content
                if not dp['sha256']:
                    if dp[digest_type]:
                        chain = act.api.fact.fact_chain(
                            actapi.fact('represents')
                            .source('hash', dp[digest_type])
                            .destination('content', '*'),
                            actapi.fact('observedIn')
                            .source('content', '*')
                            .destination('event', '*'),
                            actapi.fact('attributedTo')
                            .source('event', '*')
                            .destination('incident', '*'),
                            actapi.fact('attributedTo')
                            .source('incident', '*')
                            .destination('threatActor', dp['actor']))
                        for fact in chain:
                            handle_fact(fact)
                else:  ## There is a sha256, so we do _not_ need a chain between all the way from hexdigest
                    if dp[digest_type]:
                        handle_fact(actapi.fact('represents')
                                    .source('hash', dp[digest_type])
                                    .destination('content', dp['sha256']))
                        chain = act.api.fact.fact_chain(
                            actapi.fact('observedIn')
                            .source('content', dp['sha256'])
                            .destination('event', '*'),
                            actapi.fact('attributedTo')
                            .source('event', '*')
                            .destination('incident', '*'),
                            actapi.fact('attributedTo')
                            .source('incident', '*')
                            .destination('threatActor', dp['actor']))
                        for fact in chain:
                            handle_fact(fact)

        ### -- DEBUG!
        else:
            fields = [k for k, v in dp.items() if v and k not in ['reportId', 'title', 'ThreatScape', 'audience', 'intelligenceType', 'publishDate', 'reportLink', 'webLink']]
            logging.error("Unable to handle index[%s] with fields '%s'", i, ", ".join(fields))

## -----------------------------------------



class ISightAPIRequestHandler(object):

    INDICATORS = '/view/indicators'

    def __init__(self, root, private_key, public_key):
        """Create a new iSight api handler with api root and keys"""

        self.URL = root
        self.public_key = public_key
        self.private_key = private_key
        self.accept_version = '2.6'

    def indicators(self) -> None:
        """Download indicators last X days"""

        time_stamp = email.utils.formatdate(localtime=True)
        ENDPOINT = self.INDICATORS
        accept_header = 'application/json'
        new_data = ENDPOINT + self.accept_version + accept_header + time_stamp

        key = bytearray()
        key.extend(map(ord, self.private_key))
        hashed = hmac.new(key, new_data.encode('utf-8'), hashlib.sha256)

        headers = {
            'Accept': accept_header,
            'Accept-Version': self.accept_version,
            'X-Auth': self.public_key,
            'X-Auth-Hash': hashed.hexdigest(),
            'Date': time_stamp,
        }

        r = requests.get(self.URL + ENDPOINT, headers=headers)
        status_code = r.status_code

        if status_code == 200:
            return json.loads(r.text)
        else:
            logging.error(r.text)
            return []


@contextlib.contextmanager
def no_ssl_verification() -> Generator[None, None, None]:
    """Monkey patch request to default to no verification of ssl"""

    old_request = requests.Session.request
    requests.Session.request = partialmethod(old_request, verify=False)  # type: ignore

    warnings.filterwarnings('ignore', 'Unverified HTTPS request')
    yield
    warnings.resetwarnings()

    requests.Session.request = old_request  # type: ignore


def main_log_error() -> None:
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
