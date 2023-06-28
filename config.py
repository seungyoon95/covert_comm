import configparser

config = configparser.ConfigParser()
config.read('config.ini')

# IP Addresses
victim_ip = config.get('ip', 'victim_ip')
attacker_ip = config.get('ip', 'attacker_ip')

# Ports used by the victim and the attacker
victim_port = config.get('ports', 'victim_port')
attacker_command_port = config.get('ports', 'attacker_command_port')
attacker_keylogger_port = config.get('ports', 'attacker_keylogger_port')
attacker_monitor_port = config.get('ports', 'attacker_monitor_port')

# Mode to use, either TCP or UDP is supported.
# This will only be applied to command send/receive feature, 
# keylogging and file monitoring will continue to run in UDP. 
protocol = config.get('mode', 'protocol')

# Knock sequence to open attacker's ports for keylogging / file monitoring
keylog_knock_sequence = config.get('knock_sequence', 'keylog_knock_sequence').split(',')
monitor_knock_sequence = config.get('knock_sequence', 'monitor_knock_sequence').split(',')

# Amount of time attacker will keep the port open before closing
keylog_alive = config.get('server_alive', 'keylog_alive')
monitor_alive = config.get('server_alive', 'monitor_alive')

# Password to authenticate packets
auth_password = config.get('auth', 'auth_password')

# Monitor Path
watch_path = config.get('monitor_path', 'watch_path')

# Keylog file which the victim will use
victim_keylog_file = config.get('hidden_keylog', 'victim_keylog_file')

# Output files where keylog / monitored file will be saved to
keylog_file = config.get('output_files', 'keylog_file')
monitor_file = config.get('output_files', 'monitor_file')
