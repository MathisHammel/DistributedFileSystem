from flask import request
from flask.ext.api import FlaskAPI, status

import base64
import random
import json

app = FlaskAPI(__name__)

SERVER_KEY='S3cretKey_LockServ3r'
LOCKS={}

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
#  -filePath, the path of the file we want to lock
#  -ticket, the ticket given by the authentication server
#  -identity, the user's ID encrypted with the server's key
#It locks the specified file (if possible)
@app.route('/lock/',methods=['POST'])
def lockRoute():
    reqJson=request.get_json()
    if ('filePath' not in reqJson) or ('ticket' not in reqJson):
        return {'error':'One or more parameters missing.'}, status.HTTP_400_BAD_REQUEST

    ticket=base64.b64decode(reqJson['ticket'])
    encryptedFilePath=reqJson['filePath']
    encryptedUserId=reqJson['identity']
    
    sessionKey=decrypt(ticket,SERVER_KEY)
    filePath=decrypt(encryptedFilePath,sessionKey)
    userId=decrypt(encryptedUserId,SERVER_KEY)
    print filePath,sessionKey
    if not (filePath.startswith('filesystem://') and userId.startswith('user:')):
        return {'error':'Decryption failed.'}, status.HTTP_400_BAD_REQUEST

    filePath=filePath[len('filesystem://'):] #Strip the header
    userId=userId[len('user:'):]
    
    if filePath not in LOCKS:
        return {'error':'File not found.'}, status.HTTP_404_NOT_FOUND
    if LOCKS[filePath]!=None:
        return {'error':'File is already locked.'}, status.HTTP_409_CONFLICT #Giving out the owner's userId without encryption wouldn't be the best
    
    LOCKS[filePath]=userId
    return {'success':'File has been locked.'}, status.HTTP_200_OK

#This route takes 3 POST parameters in a json :
#  -filePath, the path of the file we want to lock
#  -ticket, the ticket given by the authentication server
#  -identity, the user's ID encrypted with the server's key
#It unlocks the specified file
@app.route('/unlock/',methods=['POST'])
def unlockRoute():
    reqJson=request.get_json()
    if ('filePath' not in reqJson) or ('ticket' not in reqJson):
        return {'error':'One or more parameters missing.'}, status.HTTP_400_BAD_REQUEST

    ticket=base64.b64decode(reqJson['ticket'])
    encryptedFilePath=reqJson['filePath']
    encryptedUserId=reqJson['identity']
    
    sessionKey=decrypt(ticket,SERVER_KEY)
    filePath=decrypt(encryptedFilePath,sessionKey)
    userId=decrypt(encryptedUserId,SERVER_KEY)
    print filePath,sessionKey
    if not (filePath.startswith('filesystem://') and userId.startswith('user:')):
        return {'error':'Decryption failed.'}, status.HTTP_400_BAD_REQUEST

    filePath=filePath[len('filesystem://'):] #Strip the header
    userId=userId[len('user:'):]
    
    if filePath not in LOCKS:
        return {'error':'File not found.'}, status.HTTP_404_NOT_FOUND
    if LOCKS[filePath]==None:
        return {'warning':'File is already unlocked.'}, status.HTTP_200_OK
    if LOCKS[filePath]!=userId:
        return {'error':'You do not own the file.'}, status.HTTP_401_UNAUTHORIZED
    
    LOCKS[filePath]=None
    return {'success':'File has been unlocked.'}, status.HTTP_200_OK



if __name__ == "__main__":
    app.run(debug=False)
