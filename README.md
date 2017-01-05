# DistributedFileSystem
This is a Python 2 implementation of a distributed file system.

This project is made by Mathis HAMMEL (Student ID 16313441) for Trinity College Dublin course CS4032.

Dependencies are Flask and Flask-API.
To install those dependencies, use pip : `pip install flask`

# Functionalities
The system allows to pull files and push them back on the server after editing them. Every time a file is pulled from the file servers for edition, a lock is put on the file so other users cannot edit it at the same time. A lock can be broken by anyone and the corresponding file gets immediately locked for the user who broke the lock.

Every user can see and edit all the files in the system, as well as the identity of the user who owns the lock (if there is one) for each file.

# Limitations
This distributed file system is for demo purposes only.

- The security algorithms are extremely weak : XOR is very straightforward to break. However, the function architecture makes it pretty easy to switch encryption schemes to adopt something more robust such as RSA.
- The databases for file lookups and locks are not optimized at all, they are currently based on JSON written to files (which makes the system easier to test)
- There is currently no caching into the file server's memory, but this would be useful for small files mostly. Bigger files would in most cases be too costly to store into RAM.
- The files are owned by everybody and there is no access control. Any user can read and edit every file (even locked) on the system.
- There is no check whether or not the file contents are being transmitted correctly. TCP should do pretty well but there can still sometimes be transmission errors. A simple md5 hash can fix this.

# Client specification
The client supports commands that can either be executed from the shell like the following :

`python2 client.py edit file1.txt`

Or executed without arguments. In this case, the client takes the form of an interactive shell, in which the user can type commands identical to the program arguments :

`edit file1.txt`

The supported commands on the client are :

- `edit [filename]` Locks the file and pull to update its contents

- `update [filename]` Pulls a file without locking it

- `close [filename]` Unlocks the file and pushes it to the corresponding server

- `owner [filename]` Shows the owner (if there is one) of the lock for a given file

- `help` Displays help

- `exit` Exits the client
