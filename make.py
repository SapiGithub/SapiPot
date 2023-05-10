# packet = b'\x00\x00\x05\xe4\n\x14\xa4\x85\xc6\xca_\xaa\xdd\x8a\x11\xd5\xff\xdd\x92lu\xea\x00\x00\x00\xf1curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c\x00\x00\x01\xf4ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256,ssh-rsa\x00\x00\x00lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\x00\x00\x00lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\x00\x00\x00\xd5umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\xd5umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\x1anone,zlib@openssh.com,zlib\x00\x00\x00\x1anone,zlib@openssh.com,zlib\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# # Split the byte sequence into sections
# sections = packet.split(b'\x00')

# # Parse the supported algorithms from each section
# key_exchange_algs = sections[0].decode().split(',')
# auth_algs = sections[1].decode().split(',')
# encryption_algs_c2s = sections[2].decode().split(',')
# encryption_algs_s2c = sections[3].decode().split(',')
# mac_algs_c2s = sections[4].decode().split(',')
# mac_algs_s2c = sections[5].decode().split(',')
# compression_algs_c2s = sections[6].decode().split(',')
# compression_algs_s2c = sections[7].decode().split(',')

# # Print the results
# print('Supported key exchange algorithms:', key_exchange_algs)
# print('Supported authentication algorithms:', auth_algs)
# print('Supported encryption algorithms (C2S):', encryption_algs_c2s)
# print('Supported encryption algorithms (S2C):', encryption_algs_s2c)
# print('Supported MAC algorithms (C2S):', mac_algs_c2s)
# print('Supported MAC algorithms (S2C):', mac_algs_s2c)
# print('Supported compression algorithms (C2S):', compression_algs_c2s)
# print('Supported compression algorithms (S2C):', compression_algs_s2c)

from datetime import datetime, timedelta
from time import sleep
payload_3 ="""POST /dvwa/login.php HTTP/1.1
Host: 192.168.8.189
Connection: keep-alive
Content-Length: 91
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.8.189
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Linux; Android 10; M2010J19CG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.8.189/dvwa/login.php
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: PHPSESSID=7a8r074s4po0nddnk0b8ig6eah; security=impossible

username=kali&password=password&Login=Login&user_token=50dd079bc51fe9993a425ede60e529a5"""
payload_3 = """GET /dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealtert%28%22sad%22%29%3C%2Fscript%3E HTTP/1.1
Host: 192.168.8.189
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Linux; Android 6.0.1; CPH1701) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Mobile Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.8.189/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealtert%28%22sad%22%29%3C%2Fscript%3E
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=f22ca5rfo189cu5841dgpvcc77; security=low"""
# A dictionary to keep track of connection attempts
# connection_attempts = {}
# # threshold for the number of connections in a given time frame
# threshold = 5
# # time frame in seconds
# time_frame = 3
# src_ip = 123
# dst_ip = 232
# dst_port = 99
# for j in range(3):
#     if (src_ip,dst_ip,dst_port) not in connection_attempts:
#         connection_attempts[(src_ip,dst_ip,dst_port)] = {}
#     # Append the current timestamp to the list of connection attempts for the source IP,destination IP,port
#         connection_attempts[(src_ip,dst_ip,dst_port)]["time"] = []
#         connection_attempts[(src_ip,dst_ip,dst_port)]["payload"] = []
#     connection_attempts[(src_ip,dst_ip,dst_port)]["time"].append(datetime.now())
#     connection_attempts[(src_ip,dst_ip,dst_port)]["payload"].append(payload_3)
#     recent_attempts = [i for i in connection_attempts[(src_ip,dst_ip,dst_port)]["time"] if i > datetime.now() - timedelta(seconds=time_frame)]


# print("password" in connection_attempts[(src_ip,dst_ip,dst_port)]["payload"][0])

# i = urllib.parse.unquote(i)

import json

payload_bf = []
payload_sql = []
payload_xss = []
with open('data.json', 'r') as f:
    json_data = json.load(f)

with open('rockyou.txt', 'r',encoding="iso-8859-1") as t:
    # Read the contents of the file
    for i, line in enumerate(t):
        line = line.replace('\n', '')
        payload_bf.append(line)
with open('SQL_Payload.txt', 'r') as t:
    # Read the contents of the file
    for i, line in enumerate(t):
        line = line.replace('\n', '')
        payload_sql.append(line)
with open('XSS_Payload.txt', 'r') as t:
    # Read the contents of the file
    for i, line in enumerate(t):
        line = line.replace('\n', '')
        payload_xss.append(line)
# print(json_data["intents"][0]["patterns"])
# print(payload)
json_data["intents"][0]["patterns"] = payload_bf
json_data["intents"][1]["patterns"] = payload_sql
json_data["intents"][2]["patterns"] = payload_xss
with open('data.json', 'w') as w:
     json.dump(json_data, w)