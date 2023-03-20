# Exercise G1 - api, caching, multithreading, locks, argparse

import argparse
import os.path
from vt_class import VTHandler
from pprint import pprint
from vt_exceptions import *


def prepare_parser() -> (argparse.ArgumentParser, argparse.Namespace):
    pre_parser = argparse.ArgumentParser(prog="Virus Total API Handler",
                                         description="cmdline tool for using VirusTotal API",
                                         epilog="Made by Or Goldberg")
    pre_parser.add_argument('url', type=str, help="The Website URL")
    pre_parser.add_argument('--scan', '-s', required=False, action='store_true')
    pre_parser.add_argument('--apikey', '-a', type=str, required=False,
                            default='49a1550c63789269f935dd4028f5241b15fdce7de406ee7002a8d8e8816ec0d4')
    pre_parsed_arguments = pre_parser.parse_args()
    return pre_parser, pre_parsed_arguments


def is_url_list(url: str) -> bool:
    if isinstance(url, str):
        if url.count(',') > 0:
            return True
        return False
    else:
        raise TypeError


def split_url_list(url: str) -> list[str]:
    return url.replace(' ', '').split(',')


def perform_analysis(handler: VTHandler) -> list[dict] | dict:
    if is_url_list(parsed_args.url):  # Handling Multiple URLs
        url_list = split_url_list(parsed_args.url)
        if parsed_args.scan:  # Force Scan
            print("##### Forcing a scan #####")
            result_list = handler.scan_multiple_url(url_list, parsed_args.apikey)
        else:
            result_list = handler.get_multiple_url(url_list, parsed_args.apikey)
        return result_list
    else:  # Handling a single URL
        if parsed_args.scan:  # Force Scan
            print("##### Forcing a scan #####")
            result = handler.scan_single_url(parsed_args.url, parsed_args.apikey)
        else:
            result = handler.get_single_url(parsed_args.url, parsed_args.apikey)
        return result


# MAIN CODE
if __name__ == "__main__":
    print("**** START RUN ****\n")
    parser, parsed_args = prepare_parser()
    cache_file_path = "VT_Cache_File.pkl"
    vt_handler = VTHandler(cache_file_path)
    if os.path.exists(cache_file_path):
        vt_handler.load_cache_file()
    try:
        vt_result = perform_analysis(vt_handler)
        pprint(vt_result)
    except TypeError:
        print("Invalid input type")
    except BadScanResult:
        print(BadScanResult)
    vt_handler.save_cache_file()
    print("\n**** RUN END ****")
