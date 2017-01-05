from flask import request
from flask.ext.api import FlaskAPI, status

import base64
import random
import json

app = FlaskAPI(__name__)

SERVER_KEY='S3cretKey_Directory'
FILE_PATHS={}

#Set this to True if the server has to make a full backup of its database before overwriting it.
#This is helpful to roll back in case of a server crash while writing to the file
FULL_BACKUP=True


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


#Resolve the server and path on server for a given file in the filesystem
def resolvePath(path):
    if path not in FILE_PATHS:
        return None
    return FILE_PATHS[path]


#Add a new file to the directory resolver
def addFile(fileName,pathString):
    if filename in FILE_PATHS:
        return False
    
    if FULL_BACKUP: #Save the database to another file
        pathFile=open('paths.json','r')
        pathFileBackup=open('paths.json.backup','w')
        pathFileBackup.write(pathFile.read())
        pathFile.close()
        pathFileBackup.close()

    FILE_PATHS[filename]=pathString
    pathFile=open('paths.json','w') #Overwrite the database with the updated one
    pathFile.write(json.dumps(FILE_PATHS))
    return True

                   
#This route takes 2 POST parameters in a json :
#  -filePath, the file path of the searched file
#  -ticket, the ticket given by the authentication server
#It returns the corresponding server and its associated file path at which the requested file can be found
@app.route('/directory/',methods=['POST'])
def directoryRoute():
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

    resolvedPath=resolvePath(filePath)
    if resolvedPath==None:
        return {'error':'File not found.'}, status.HTTP_404_NOT_FOUND

    encryptedResolvedPath=encrypt(resolvedPath,sessionKey)
    return {'resolvedPath':base64.b64encode(encryptedResolvedPath)}


#This route takes 3 POST parameters in a json :
#  -fileResolved, the URL of the file in the format fileserver://serverIP:serverPort:serverFilePath encrypted with the session key
#  -filePath, the file's path as seen by the user encrypted with the session key
#  -token, the token given by the authentication server
#It returns the corresponding server and its associated file path at which the requested file can be found
@app.route('/addfile/',methods=['POST'])
def addfileRoute():
    reqJson=request.get_json()
    if ('fileResolved' not in reqJson) or ('filePath' not in reqJson) or ('token' not in reqJson):
        return {'error':'One or more parameters missing.'}, status.HTTP_400_BAD_REQUEST

    token=reqJson['token']
    encryptedFileResolved=reqJson['fileResolved']
    encryptedFilePath=reqJson['filePath']
    sessionKey=decrypt(token,SERVER_KEY)
    fileResolved=decrypt(encryptedFileResolved,sessionKey)
    filePath=decrypt(encryptedFilePath,sessionKey)
    
    if not fileResolved.startswith('fileserver://'):
        return {'error':'Decryption failed.'}, status.HTTP_400_BAD_REQUEST

    fileResolved=fileResolved[len('fileserver://'):] #Strip the header
    execStatus=addFile(filePath,fileResolved)
    if execStatus==True:
        return {'success':'File succesfully added'}, HTTP_201_CREATED
    return {'error':'File already exists'}, status.HTTP_409_CONFLICT

    


if __name__ == "__main__":
    #Using JSON in a file as a database is fine for small projects, but for bigger filesystems we must use something better like sqlite
    pathFile=open('paths.json','r')
    FILE_PATHS=json.loads(pathFile.read())
    pathFile.close()
    
    app.run(debug=False, port=5002)
