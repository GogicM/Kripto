# Kripto

Simulation of safe file system on remote server.
Communication between client and server are secure, algorithms used for safe communication and storage are asymetric RSA and symmetric AES algorithms.
User can see list of his files, add new file and change existing ones.
At startup, login form appears, asking for user name, password and certificate. After successful authentication, panel with files list and file manipulations appears.
All files on server are encrypted with symmetric keys.
Symmetric keys are stored on server, encrypted with server public key.
Session keys for clients are newly generated every time application starts.