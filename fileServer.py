from flask import request
from flask.ext.api import FlaskAPI, status

import base64
import random
import json

app = FlaskAPI(__name__)

SERVER_KEY='S3cretKey_FileS3rver_1'


#Xor two ASCII strings. May produce non-printable characters.
#We should use a more secure algorithm such as RSA, but this is for demo purposes
def xorstr(data,key):
    r=''
    for i in range(len(data)):
        r+=chr(ord(data[i])^ord(key[i%len(key)]))
    return r


#Encryption algorithm
def encrypt(data,key):
    return xorstr(data,key)


#Decryption algorithm
def decrypt(data,key):
    return xorstr(data,key)
                   
#This route takes 3 POST parameters in a json :
#  -filePath, the file path of the searched file
#  -ticket, the ticket given by the authentication server
#  -fileContents, the contents of the file the user wants to push
#It returns the corresponding server and its associated file path at which the requested file can be found
@app.route('/push/',methods=['POST'])
def pushRoute():
    reqJson=request.get_json()
    if ('filePath' not in reqJson) or ('ticket' not in reqJson) or ('fileContents' not in reqJson):
        return {'error':'One or more parameters missing.'}, status.HTTP_400_BAD_REQUEST

    ticket=base64.b64decode(reqJson['ticket'])
    encryptedFilePath=reqJson['filePath']
    encryptedFileContents=reqJson['fileContents']
    
    sessionKey=decrypt(ticket,SERVER_KEY)
    filePath=decrypt(encryptedFilePath,sessionKey)
    fileContents=decrypt(base64.b64decode(encryptedFileContents),sessionKey)
    
    print filePath,sessionKey
    if not filePath.startswith('filesystem://'):
        return {'error':'Decryption failed.'}, status.HTTP_400_BAD_REQUEST

    filePath=filePath[len('filesystem://'):] #Strip the header

    fo=open(filePath,'wb') #Data is not sanitized, directory traversal is possible here. Do not use in real life
    fo.write(fileContents)
    fo.close()
    
    return {'success':'File has been pushed successfully'}


#This route takes 2 POST parameters in a json :
#  -filePath, the file path of the searched file
#  -ticket, the ticket given by the authentication server
#It returns the corresponding server and its associated file path at which the requested file can be found
@app.route('/pull/',methods=['POST'])
def pullRoute():
    reqJson=request.get_json()
    if ('filePath' not in reqJson) or ('ticket' not in reqJson):
        return {'error':'One or more parameters missing.'}, status.HTTP_400_BAD_REQUEST

    ticket=base64.b64decode(reqJson['ticket'])
    encryptedFilePath=reqJson['filePath']
    
    sessionKey=decrypt(ticket,SERVER_KEY)
    filePath=decrypt(encryptedFilePath,sessionKey)

    print filePath,sessionKey
    if not filePath.startswith('filesystem://'):
        return {'error':'Decryption failed.'}, status.HTTP_400_BAD_REQUEST

    filePath=filePath[len('filesystem://'):] #Strip the header

    fi=open(filePath,'rb') #Data is not sanitized, directory traversal is possible here. Do not use in real life
    fileContents=fi.read()
    fi.close()

    encryptedFileContents=base64.b64encode(encrypt(fileContents,sessionKey))
    return {'fileContents':encryptedFileContents}

    


if __name__ == "__main__":
    app.run(debug=True, port=5000)
