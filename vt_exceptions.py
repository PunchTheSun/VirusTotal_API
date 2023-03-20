# VirusTotal Class Exceptions

class BadScanResult(Exception):
    def __init__(self, status_code: int):
        super().__init__()
        self._status_code = status_code

    def __str__(self):
        return f"Scan Failed\nStatus Code: {self._status_code}"
