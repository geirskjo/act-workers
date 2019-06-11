#!/usr/bin/env python3

"""url unshortener worker for the ACT platform

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
"""


from logging import error

import urllib3

import requests
from urllib.parse import urlparse
import sys
import traceback
import act
import act.api
from act.workers.libs import worker
from typing import Text

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_RECURSIVE = 10  # max number of redirects to attempt to follow (failsafe)

URL_SHORTERNERS = set(['adf.ly', 'bit.ly', 'bitly.com', 'evassmat.com',
                       'goo.gl', 'is.gd', 'lnkd.in', 'www.t2m.io', 'tiny.cc',
                       'tinyurl.com', 'x.co'])

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"


def check_redirect(url: Text, timeout: int = 30) -> Text:
    """Take a url. Attempt to make it a http:// url and check if it is to one
    of the known url shortening services. If it is.. find the first redirect"""

    headers = {'User-agent': USER_AGENT}

    org_url = url

    p = urlparse(url)
    if p.scheme == '':
        url = "http://{}".format(url)
    p = urlparse(url)

    if p.hostname not in URL_SHORTERNERS:
        return org_url

    r = requests.get(url, allow_redirects=False, timeout=timeout, headers=headers)
    if r.is_redirect:
        return str(r.next.url)  # type: ignore

    return org_url


def process(api: act.api.Act, output_format: Text = "json") -> None:
    """Read queries from stdin, resolve each one through passivedns printing
    generic_uploader data to stdout"""

    for query in sys.stdin:
        query = query.strip()
        if not query:
            continue

        n = 0
        while True:
            redirect = check_redirect(query)
            if redirect == query or n > MAX_RECURSIVE:
                break
            n += 1

            act.api.helpers.handle_uri(api, query, output_format=output_format)
            act.api.helpers.handle_uri(api, redirect, output_format=output_format)
            act.api.helpers.handle_fact(
                api.fact("redirectsTo")
                .source("url", query)
                .destination("url", redirect), output_format=output_format)

            query = redirect


def main() -> None:
    """Main function"""
    # Look for default ini file in "/etc/actworkers.ini" and
    # ~/config/actworkers/actworkers.ini (or replace .config with
    # $XDG_CONFIG_DIR if set)
    args = worker.handle_args(worker.parseargs("URL unshortener worker"))
    actapi = worker.init_act(args)

    process(actapi, args.output_format)


def main_log_error() -> None:
    "Main function wrapper. Log all exceptions to error"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
