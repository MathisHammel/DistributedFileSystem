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


authUrl='http://localhost:5001/auth/'
directoryUrl='http://localhost:5002/directory/'
lockUrl='http://localhost:5003/break/'
userId='User1'
userPassword='Sup3rS3cr3T_P4ssW0rd!'

if __name__ == "__main__":

    encryptedUserId=base64.b64encode(encrypt(userId,userPassword))
    
    print 'Authenticating on the security server to get a directory server token'
    authDirJson={'userId':'User1','encryptedId':encryptedUserId,'serverId':'Directory'}
    print 'Sending',authDirJson
    print ''
    authDirRequest=requests.post(authUrl,json=authDirJson)
    print 'Received status code',authDirRequest.status_code
    print authDirRequest.text
    print ''

    tokenDir=json.loads(decrypt(base64.b64decode(authDirRequest.json()['token']),userPassword))
    sessionKeyDir=tokenDir['sessionKey']
    print 'Decrypted token is',tokenDir

    directoryJson={'filePath':encrypt('filesystem://file1.txt',sessionKeyDir), 'ticket':tokenDir['ticket']}
    directoryRequest=requests.post(directoryUrl,json=directoryJson)
    print 'Received status code',directoryRequest.status_code
    print directoryRequest.text
    print ''
    filepath=decrypt(base64.b64decode(directoryRequest.json()['resolvedPath']),sessionKeyDir)
    print 'Decrypted path is',filepath




    print 'Authenticating on the security server to get a lock server token'
    authLockJson={'userId':'User1','encryptedId':encryptedUserId,'serverId':'Lock'}
    print 'Sending',authLockJson
    print ''
    authLockRequest=requests.post(authUrl,json=authLockJson)
    print 'Received status code',authLockRequest.status_code
    print authLockRequest.text
    print ''

    tokenLock=json.loads(decrypt(base64.b64decode(authLockRequest.json()['token']),userPassword))
    sessionKeyLock=tokenLock['sessionKey']
    print 'Decrypted token is',tokenLock

    lockJson={'filePath':encrypt('filesystem://'+filepath,sessionKeyLock),'identity':tokenLock['identity'],'ticket':tokenLock['ticket']}

    lockRequest=requests.post(lockUrl,json=lockJson)
    
    print 'Received status code',lockRequest.status_code
    print lockRequest.text



    fileServerUrl,fileServerPort,fileServerPath = filepath.split(':')
    
    print 'Authenticating on the security server to get a file server token'
    authFileJson={'userId':'User1','encryptedId':encryptedUserId,'serverId':fileServerUrl+':'+fileServerPort}
    print 'Sending',authFileJson
    print ''
    authFileRequest=requests.post(authUrl,json=authFileJson)
    print 'Received status code',authFileRequest.status_code
    print authFileRequest.text
    print ''

    tokenFile=json.loads(decrypt(base64.b64decode(authFileRequest.json()['token']),userPassword))
    sessionKeyFile=tokenFile['sessionKey']
    print 'Decrypted token is',tokenFile

    newContents='''Nice file you got there !
    file1.txt sure is great :)'''
    fileContents=base64.b64encode(encrypt(newContents,sessionKeyFile))
    

    fileJson={'filePath':encrypt('filesystem://'+fileServerPath,sessionKeyFile),'ticket':tokenFile['ticket'],'fileContents':fileContents}
    fileRequest=requests.post('http://'+fileServerUrl+':'+fileServerPort+'/push/',json=fileJson)

    print 'Received status code',fileRequest.status_code
    print fileRequest.text
    """
    print 'Decrypted file contents are :'
    print '-----------------------------'
    print decrypt(base64.b64decode(fileRequest.json()['fileContents']),sessionKeyFile)
    print '-----------------------------'
    """


    


    
