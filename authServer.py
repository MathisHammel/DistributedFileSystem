from flask import request
from flask.ext.api import FlaskAPI, status

import base64
import random
import json

app = FlaskAPI(__name__)


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


#Returns a user's password. Do not use this kind of thing in real work please
def getPassword(userId):
    auth_data = {'User1':'Sup3rS3cr3T_P4ssW0rd!',
                 'User2':'WhatASecureWayToStorePasswords...',
                 'User3':'azerty123'}
    if userId not in auth_data:
        return None
    return auth_data[userId]


#Authenticates the user with the provided credentials
def identityMatch(userId,encryptedId):
    password=getPassword(userId)
    if password==None:
        return False
    encryptedHere = encrypt(userId,password)
    print base64.b64encode(encryptedHere),encryptedId,userId,password
    return base64.b64encode(encryptedHere)==encryptedId


#Generates a pseudorandom key string of length l.
#NOT CRYPTOGRAPHICALLY SECURE !
def generateKey(l):
    r=''
    for i in range(l):
        r+=chr(random.randint(32,127))
    return r


#Returns the key for one of the file servers
def getServerKey(serverId):
    server_keys = {'Directory':'S3cretKey_Directory',
                   'Lock':'S3cretKey_LockServ3r'}

    if serverId not in server_keys:
        return None
    return server_keys[serverId]

                   
#This route takes 3 POST parameters in a json :
#  -userId, a string representing the user's identity
#  -encryptedId, a base64 string containing the user's id encrypted with their password.
#  -serverId, a string describing the file server's identity
#It returns the encrypted ticket for the specified file server
@app.route('/auth/',methods=['POST'])
def auth():
    reqJson=request.get_json()
    if ('userId' not in reqJson) or ('encryptedId' not in reqJson) or ('serverId' not in reqJson):
        return {'error':'One or more parameters missing.'}, status.HTTP_400_BAD_REQUEST
    
    userId=reqJson['userId']
    encryptedId=reqJson['encryptedId']
    serverId=reqJson['serverId']
    
    if identityMatch(userId,encryptedId):
        serverKey=getServerKey(serverId)
        if serverKey==None:
            return {'error':'Server ID unknown.'}, status.HTTP_400_BAD_REQUEST
        sessKey=generateKey(64)
        encryptedSessKey=base64.b64encode(encrypt(sessKey,serverKey))
        encryptedUserId=base64.b64encode(encrypt('user:'+userId,serverKey)) #For when the user has to give their identity to a server and can't give a fake one (non-repudiation)
        token={'ticket':encryptedSessKey,'sessionKey':sessKey,'identity':encryptedUserId}
        encryptedToken=base64.b64encode(encrypt(json.dumps(token),getPassword(userId)))
        return {'token':encryptedToken}
    else:
        return {'error':'User identity does not match.'},status.HTTP_401_UNAUTHORIZED


if __name__ == "__main__":
    app.run(port=5001,debug=False)
