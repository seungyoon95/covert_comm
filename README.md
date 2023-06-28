# Covert Communication Application by Seungyoon Lee, A01210396

### Objective:

- To bring together several stealth software and backdoor concepts covered in class into a single covert communication application.
- To learn how to use such an application in allowing access to a network or to exfiltrate data from systems within a network.

---
## User Guide

Before we start, please note:

Executables for running the program were built on Fedora 36, meaning that it is not guaranteed to work on any other machine running different operating systems.

pip install 

### Victim
Simply start the program with the command : sudo python victim.py, and it will authenticate & accept command packets from the attacker, and send the encrypted result back to the attacker. In addition to that, it will watch the specific directory set by the config file 

Upon termination of the victim program, it will send the entire keylog that happened while the program was running.

### Attacker
The attacker setcion of the program has two different file to start from : attacker.py and accept_knock.py.

attacker.py is used to excute remote commands on the victim machine. Use the following command: sudo python attacker.py to start the program, and the attacker will be prompted to enter a command to send. Once the entered command is encrypted and sent to the victim, it will wait for a response with the result, and the decrypted result will be printed on the console.

accept_knock.py is used for both keylogging and file/directory monitoring. While this is running, it will watch for a sequence of packets to allow access to specific ports for certain amount of time, which are all set in the config.ini file.
