import requests
import base64
import json


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

if __name__ == "__main__":
    authUrl='http://localhost:5000/auth/'
    directoryUrl='http://localhost:5000/directory/'
    userId='User1'
    userPassword='Sup3rS3cr3T_P4ssW0rd!'
    encryptedUserId=base64.b64encode(encrypt(userId,userPassword))
    
    print 'Authenticating on the security server to get a directory server token'
    authJson={'userId':'User1','encryptedId':encryptedUserId,'serverId':'Directory'}
    print 'Sending',authJson
    print ''
    authRequest=requests.post(authUrl,json=authJson)
    print 'Received status code',authRequest.status_code
    print authRequest.text
    print ''

    token=json.loads(decrypt(base64.b64decode(authRequest.json()['token']),userPassword))
    sessionKey=token['sessionKey']
    print 'Decrypted token is',token

    raw_input('\n\nPress enter to begin directory part')

    directoryJson={'filePath':encrypt('filesystem://file1.txt',sessionKey), 'ticket':token['ticket']}
    directoryRequest=requests.post(directoryUrl,json=directoryJson)
    print 'Received status code',directoryRequest.status_code
    print directoryRequest.text
    print ''
    print 'Decrypted path is',decrypt(base64.b64decode(directoryRequest.json()['resolvedPath']),sessionKey)
