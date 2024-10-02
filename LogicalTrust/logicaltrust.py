import base64
import json
import requests
from bs4 import BeautifulSoup
import hashlib

url = 'https://task.zostansecurity.ninja/'
page = requests.get(url)

soup = BeautifulSoup(page.text, 'html.parser')

last_line = page.text.strip().splitlines()[-1]
url = last_line.split(' ')[-1]

task2_url = 'https://task.zostansecurity.ninja'+url
response1 = requests.get(task2_url)

response_text = response1.text
lines = response_text.strip().split('\n')
timestamp_line = lines[-1]
challenge_line = lines[-2]

challenge = challenge_line.split(': ')[1].strip()
timestamp = timestamp_line.split(': ')[1].strip()

headers = {'X-challenge': challenge, 'X-timestamp': timestamp}

response2 = requests.get('https://task.zostansecurity.ninja/?step=2', headers=headers)

response2_text = response2.text

lines = response2.text.split('\n')
timestamp_line = lines[-32]
challenge_line = lines[-33]
challenge_value = challenge_line.split(': ')[1].strip()
timestamp_value = timestamp_line.split(': ')[1].strip()

linie_od_11_do_32 = '\n'.join(lines[10:32])

raw_1 = json.loads(linie_od_11_do_32)

formatted_output = ""
for key in sorted(raw_1.keys()):
    formatted_output += f"{key}={raw_1[key]}&"

finalna_wartosc = formatted_output[:-1]

hashes_string = hashlib.sha256(finalna_wartosc.encode('utf-8')).hexdigest()

data = {'challenge':challenge_value, 'timestamp':timestamp_value, 'hash':hashes_string}

response3 = requests.post('https://task.zostansecurity.ninja/?step=3',data=data)

long_base = response3.text
to_decod = long_base.splitlines()[-1]


while True:
    try:
        to_decod = base64.b64decode(to_decod).decode('utf-8')
    except:
        break

print(to_decod)
