import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from Beacon import Beacon


@pytest.fixture
def beacon():
    return Beacon()


def test_register_instruction_handlers_contains_expected_handlers(beacon):
    handlers = beacon._instruction_handlers

    expected_mapping = {
        "loadmodule": "_handle_load_module",
        "change_directory": "_handle_change_directory",
        "changedirectory": "_handle_change_directory",
        "cd": "_handle_change_directory",
        "download": "_handle_download",
        "upload": "_handle_upload",
        "listdirectory": "_handle_list_directory",
        "ls": "_handle_list_directory",
        "dir": "_handle_list_directory",
        "listprocesses": "_handle_list_processes",
        "ps": "_handle_list_processes",
        "powershell": "_handle_powershell",
        "printworkingdirectory": "_handle_pwd",
        "pwd": "_handle_pwd",
        "run": "_handle_run",
        "shell": "_handle_shell",
        "cat": "_handle_cat",
        "mkdir": "_handle_mkdir",
        "remove": "_handle_remove",
        "rm": "_handle_remove",
        "killprocess": "_handle_kill_process",
        "tree": "_handle_tree",
        "getenv": "_handle_getenv",
        "whoami": "_handle_whoami",
        "netstat": "_handle_netstat",
        "ipconfig": "_handle_ipconfig",
        "enumerateshares": "_handle_enumerate_shares",
    }

    assert set(handlers.keys()) == set(expected_mapping.keys())

    for instruction, handler_name in expected_mapping.items():
        handler = handlers[instruction]
        expected_handler = getattr(beacon, handler_name)
        assert callable(handler)
        assert callable(expected_handler)
        assert handler.__func__ is expected_handler.__func__


def test_exec_instruction_uses_registered_handler(beacon, tmp_path):
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        beacon.tasks.append(
            {
                "instruction": "PWD",
                "cmd": "",
                "args": "",
                "data": b"",
                "inputFile": "",
                "outputFile": "",
                "pid": -1,
                "uuid": "test-uuid",
                "errorCode": 0,
            }
        )

        beacon.execInstruction()

        assert beacon.tasks == []
        assert len(beacon.taskResults) == 1

        result = beacon.taskResults[0]
        assert result["instruction"] == "PWD"
        assert result["returnValue"] == str(tmp_path)
        assert result["data"] == b""
        assert result["uuid"] == "test-uuid"
    finally:
        os.chdir(original_cwd)
