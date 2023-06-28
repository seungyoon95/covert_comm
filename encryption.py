# Hard-coded (NOT SAFE) key for both encryption and decryption
KEY = 'KEYFORENCRYPTION'.encode('utf-8')

# XOR encryption & converting string to bytes, referenced from the first assignment
def encrypt(data):
    data = data.encode('utf-8')
    encrypted_data_byte = bytes([char_byte ^ KEY[i % len(KEY)] for i, char_byte in enumerate(data)])
    
    return encrypted_data_byte


# XOR decryption & converting bytes back to string, referenced from the first assignment
def decrypt(data):
    decrypted_data_byte = bytes([data[i] ^ KEY[i % len(KEY)] for i in range(len(data))])
    decrypted_data = decrypted_data_byte.decode('utf-8')

    return decrypted_data
