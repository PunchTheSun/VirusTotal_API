# Virus Total API - Class
import base64
import datetime
import time
import pickle

import requests
from vt_exceptions import *


class VTHandler:
    def __init__(self, cache_file_path: str,
                 apikey: str = "49a1550c63789269f935dd4028f5241b15fdce7de406ee7002a8d8e8816ec0d4",
                 cache_days_limit: int = 182):
        self._cache = dict()
        self._cache_file_path = cache_file_path
        self._time_limit = datetime.timedelta(days=cache_days_limit)
        self._apikey = apikey
        self._scan_headers = {
            "accept": "application/json",
            "x-apikey": self._apikey,
            "content-type": "application/x-www-form-urlencoded"
        }
        self._get_headers = {
            "accept": "application/json",
            "x-apikey": self._apikey
        }
        self._scan_url_prefix = "https://www.virustotal.com/api/v3/urls"

    @staticmethod
    def prepare_url(url: str) -> str | list[str]:
        if not isinstance(url, str) and not isinstance(url, list):
            raise TypeError
        if isinstance(url, str):
            safe_url = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        else:
            safe_url = []
            for u in url:
                if not isinstance(u, str):
                    raise TypeError
                safe_url.append(base64.urlsafe_b64encode(u.encode()).decode().strip('='))
        return safe_url

    def prepare_url_list(self, url: list[str]):
        safe_url_list = []
        for u in url:
            safe_url_list.append(self.prepare_url(u))
        return safe_url_list

    def set_time_limit(self, new_time_limit: str):
        if not new_time_limit.isnumeric():
            raise ValueError("Not a number")
        self._time_limit = datetime.timedelta(days=float(new_time_limit))

    def is_relevant(self, result_dict: dict) -> bool:
        if result_dict['data']['type'] == 'url':
            last_analysis_date = datetime.datetime.fromtimestamp(result_dict['data']['attributes']['last_analysis_date'])
        elif result_dict['data']['type'] == 'analysis':
            last_analysis_date = datetime.datetime.fromtimestamp(result_dict['data']['attributes']['date'])
        else:
            return False  # Unknown result type (Not from the 2 VT API Endpoints) - Force re-scan
        if datetime.datetime.now() - last_analysis_date >= self._time_limit:
            return False
        return True

    def is_cached(self, url: str) -> bool:
        if url.lower() in self._cache.keys():
            return True
        return False

    @staticmethod
    def is_scanned(result_dict: dict) -> bool:
        if int(result_dict['data']['attributes']['times_submitted']) == 0:
            return False
        return True

    def scan_single_url(self, url,
                        apikey: str = "49a1550c63789269f935dd4028f5241b15fdce7de406ee7002a8d8e8816ec0d4"):
        self._scan_headers = {
            "accept": "application/json",
            "x-apikey": apikey,
            "content-type": "application/x-www-form-urlencoded"
        }
        scan_request = requests.post(self._scan_url_prefix, data=f"url={url}", headers=self._scan_headers)
        if scan_request.status_code == 200:
            result = self.get_single_scan_result(scan_request.json()['data']['id'])
            self.add_to_cache(url, result)
            return result
        else:
            raise BadScanResult(scan_request.status_code)

    def get_single_scan_result(self, scan_id: str):
        scan_result = requests.get("https://www.virustotal.com/api/v3/analyses/"+scan_id, headers=self._scan_headers)
        if scan_result.status_code == 200:
            while scan_result.json()['data']['attributes']['status'] == 'queued':
                time.sleep(0.5)  # My current method of handling the "wait time" while VT API Analyzes the url
                scan_result = requests.get("https://www.virustotal.com/api/v3/analyses/"+scan_id,
                                           headers=self._scan_headers)
                if scan_result.status_code != 200:
                    raise BadScanResult(scan_result.status_code)
            return scan_result.json()
        else:
            raise BadScanResult(scan_result.status_code)

    def scan_multiple_url(self, url_list: list[str],
                          apikey: str = "49a1550c63789269f935dd4028f5241b15fdce7de406ee7002a8d8e8816ec0d4"):
        result_list = []
        for u in url_list:
            result_list.append(self.scan_single_url(u, apikey))
        return result_list

    def get_single_url(self, url: str,
                       apikey: str = "49a1550c63789269f935dd4028f5241b15fdce7de406ee7002a8d8e8816ec0d4"):
        self._get_headers = {
            "accept": "application/json",
            "x-apikey": apikey
        }
        if self.is_cached(url):
            if self.is_relevant(self._cache[url.lower()]):
                print(f"##### Pulling result for {url} from Cache #####")
                return self._cache[url.lower()]
        safe_url = self.prepare_url(url)
        vt_result = requests.get("https://www.virustotal.com/api/v3/urls/"+safe_url, headers=self._get_headers)
        if vt_result.status_code == 200:
            if self.is_scanned(vt_result.json()):
                if self.is_relevant(vt_result.json()):
                    self.add_to_cache(url, vt_result.json())
                    return vt_result.json()
                else:
                    if self.is_cached(url):
                        self.remove_from_cache(url)  # Remove URL from cache - Results older than time limit
            return self.scan_single_url(url, apikey)  # Perform a forced scan for 1 url
        else:
            raise BadScanResult(vt_result.status_code)

    def get_multiple_url(self, url_list: list[str],
                         apikey: str = "49a1550c63789269f935dd4028f5241b15fdce7de406ee7002a8d8e8816ec0d4"):
        self._get_headers = {
            "accept": "application/json",
            "x-apikey": apikey
        }
        vt_result_list = []
        safe_url_list = self.prepare_url_list(url_list)
        for i, safe_url in enumerate(safe_url_list):
            if self.is_cached(url_list[i]):
                if self.is_relevant(self._cache[url_list[i].lower()]):
                    print(f"##### Pulling result for {url_list[i]} from Cache #####")
                    vt_result_list.append(self._cache[url_list[i].lower()])
            else:
                vt_result = requests.get("https://www.virustotal.com/api/v3/urls/"+safe_url, headers=self._get_headers)
                if vt_result.status_code == 200:
                    if self.is_scanned(vt_result.json()):
                        if self.is_relevant(vt_result.json()):
                            self.add_to_cache(url_list[i], vt_result.json())
                            vt_result_list.append(vt_result.json())
                        else:
                            self.remove_from_cache(url_list[i])  # Remove URL from cache - Results older than time limit
                    vt_result_list.append(self.scan_single_url(url_list[i], apikey))  # Perform a forced scan for 1 url
                else:
                    raise BadScanResult(vt_result.status_code)
        return vt_result_list

    def add_to_cache(self, url: str, result: dict):
        self._cache[url.lower()] = result

    def remove_from_cache(self, url: str):
        self._cache.pop(url)

    def load_cache_file(self):
        with open(self._cache_file_path, 'rb') as f:
            self._cache = pickle.load(f)

    def save_cache_file(self):
        with open(self._cache_file_path, 'wb') as f:
            pickle.dump(self._cache, f)
