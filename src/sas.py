import math
import time
import requests
import json
from Crypto.Util import number
from Crypto.Random import random
from utils import to_bytes


import secrets
import time

def get_safe_prime_and_g():
    url = "https://2ton.com.au/getprimes/random/2048"
    data = json.loads(requests.get(url).content.decode())
    p = int((data["p"]["base10"]))
    g = int(data["g"]["base10"])
    return p, g

print(get_safe_prime_and_g())