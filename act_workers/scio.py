#!/usr/bin/env python3

"""NiFi worker to pass Scio produced data to the ACT platform"""

import argparse
import json
import sys
import traceback
from logging import error
from typing import Dict, List, Text, cast

import act
from act.helpers import handle_fact, handle_uri
from act_workers_libs import worker

EXTRACT_GEONAMES = ["countries", "regions", "regions-derived",
                    "sub-regions", "sub-regions-derived"]


EXTRACT_INDICATORS = ["md5", "sha1", "sha256",
                      "fqdn", "ipv4", "ipv6", "email",
                      "msid", "cve", "uri", "ipv4net"]

SCIO_GEONAMES_ACT_MAP = {
    "countries": "country",
    "regions": "region",
    "regions-derived": "region",
    "sub-regions": "subRegion",
    "sub-regions-derived": "subRegion"
}

SCIO_INDICATOR_ACT_MAP = {
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "ipv4net": "ipv4Network",
    "cve": "vulnerability",
    "msid": "vulnerability",
}


def parseargs() -> argparse.Namespace:
    """ Parse arguments """
    parser = worker.parseargs('Get SCIO reports and IOCs from stdin')
    return parser.parse_args()


def get_scio_report() -> Dict:
    """Read scio report from stdin"""

    return cast(Dict, json.load(sys.stdin))


def report_mentions_fact(actapi: act.Act, object_type: Text, object_values: List[Text], report_id: Text, output_format: Text) -> None:
    """Add mentions fact to report"""
    for value in list(set(object_values)):
        try:
            handle_fact(
                actapi.fact("mentions", object_type)
                .source("report", report_id)
                .destination(object_type, value),
                output_format
            )
        except act.base.ResponseError as e:
            error("Unable to create linked fact: %s" % e)


def add_to_act(actapi: act.Act, doc: Dict, output_format: Text = "json") -> None:
    """Add a report to the ACT platform"""

    report_id: Text = doc["hexdigest"]
    title: Text = doc.get("title", "No title")
    indicators: Dict = doc.get("indicators", {})

    try:
        # Report title
        handle_fact(
            actapi.fact("name", title)
            .source("report", report_id),
            output_format
        )
    except act.base.ResponseError as e:
        error("Unable to create fact: %s" % e)

    # Loop over all items under indicators in report
    for scio_indicator_type in EXTRACT_INDICATORS:
        # Get object type from ACT (default to object type in SCIO)
        act_indicator_type = SCIO_INDICATOR_ACT_MAP.get(scio_indicator_type,
                                                        scio_indicator_type)
        report_mentions_fact(
            actapi,
            act_indicator_type,
            indicators.get(scio_indicator_type, []),
            report_id,
            output_format)

    # For SHA256, create content object
    for sha256 in list(set(indicators.get("sha256", []))):
        handle_fact(
            actapi.fact("represents")
            .source("hash", sha256)
            .destination("content", sha256),
            output_format
        )

    # Add all URI components
    for uri in list(set(indicators.get("uri", []))):
        handle_uri(actapi, uri, output_format=output_format)

    # Locations (countries, regions, sub regions)
    for location_type in EXTRACT_GEONAMES:
        locations = doc.get("geonames", {}).get(location_type, [])

        report_mentions_fact(
            actapi,
            SCIO_GEONAMES_ACT_MAP[location_type],
            locations,
            report_id,
            output_format)

    # Threat actor
    report_mentions_fact(
        actapi,
        "threatActor",
        doc.get("threat-actor", {}).get("names", []),
        report_id,
        output_format)

    # Tools
    report_mentions_fact(
        actapi,
        "tool",
        [tool.lower() for tool in doc.get("tools", {}).get("names", [])],
        report_id,
        output_format)

    # Sector
    report_mentions_fact(
        actapi,
        "sector",
        doc.get("sectors", []),
        report_id,
        output_format)


def main() -> None:
    """main function"""
    args = parseargs()

    # Add IOCs from reports to the ACT platform
    add_to_act(
        act.Act(args.act_baseurl, args.user_id, args.loglevel, args.logfile, "scio"),
        get_scio_report(),
        args.output_format,
    )


def main_log_error() -> None:
    """Execute main() and log errors to error"""
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
