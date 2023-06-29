# Covert Communication Application 
# By Seungyoon Lee, A01210396

### Objective:

- To bring together several stealth software and backdoor concepts covered in class into a single covert communication application.
- To learn how to use such an application in allowing access to a network or to exfiltrate data from systems within a network.

---
## User Guide

To build the executable on your own machine, please ensure that you have pyinstaller installed on your machine with the following command: 

pip install pyinstaller

After that, please run the following commands to build executables required to use the program, and run them:

pyinstaller attacker.py --onefile --distpath ./                -> sudo ./attacker

pyinstaller accept_knock.py --onefile --distpath ./            -> sudo ./accept_knock

pyinstaller victim.py --onefile --distpath ./                  -> sudo ./victim

However, there has been an issue where executables built with PyInstaller does not behave the way it should when KeyboardInterrupt happens, and I was unable to find a fix for it. This is critical to the keylogging feature as it relies on termination of the backdoor (victim.py) to send the stored keylog file. Therefore, it is not recommended to use these executables, instead you could run directly from the source code with following commands:

sudo python attacker.py

sudo python accept_knock.py

sudo python victim.py

### Victim
Simply start the program with the command : sudo python victim.py, and it will authenticate & accept command packets from the attacker, and send the encrypted result back to the attacker. In addition to that, it will watch the specific directory set by the config file. When a file is created in that specific directory, it will perform port knocking to request access on a specific port, then send the created file over to the attacker. The port will stay open for set amount of time upon correct knock sequence is received on the attacker side, or until the transfer is completed.

Upon termination of the victim program, it will send the entire keylog that happened while the program was running. This also triggers port knocking on another specified port for keylog files, where access is granted for set amount of time or until the transfer is completed.

### Attacker
Please note, the backdoor program on the victim side must be running in order for attacker programs to function properly. If not, attacker.py will not receive any results for commands being sent, and accept_knock.py will hang forever as it will not detect any knock sequence.

The attacker setcion of the program has two different file to start from : attacker.py and accept_knock.py.

attacker.py is used to excute remote commands on the victim machine. Use the following command: sudo python attacker.py to start the program, and the attacker will be prompted to enter a command to send. Once the entered command is encrypted and sent to the victim, it will wait for a response with the result, and the decrypted result will be printed on the console.

accept_knock.py is used for both keylogging and file/directory monitoring. While this is running, it will watch for a sequence of packets to allow access to specific ports for certain amount of time, which are all set in the config.ini file. When the correct sequence is received, it will start a server on the specified port to accept keylog files / created file in the monitored directory. Upon receiving the complete file or if the set amount of time is passed, the server will be closed.

### Dependencies
The program uses 4 external libraries, including: 

- scapy for manipulating / sniffing packets
- keyboard for logging all keystroke
- setproctitle for masking the process name
- watchdog for monitoring specific directories

To install all of the above, please run the following command:

- pip install scapy keyboard setproctitle watchdog 

### More Information

*Testing results, packet captures, and any further information can be found inside the submitted .zip file, in a form of report / pcap / video.*
