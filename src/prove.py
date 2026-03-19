import math
from base64 import b64decode
from string import hexdigits

from src.MTProto_Session import MTProto_Session
from src.TGMessage import TGMessage
import time
import random
from src.utils import *
import base64
# random.seed(1)

user = load_user_data("user1")
auth_key = bytearray.fromhex(user["auth_key"])
session = MTProto_Session(rand_bytes(8), auth_key)
msg = TGMessage(bytearray("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
                          .encode()), session, "server_response", False, True)
# tcp_payload_base64 = "JPxO+vQAcGZVdzFZCABFAAGdDOxAAEAG4gwKNAM5lZqnW9oUAbtAb+Oy5ntKUoAYAfZ2IAAAAQEICq1Dxzzf4UPMFoJkQ/qZdBan8m07ipG3v3tK5AhMphQfsl4/D3O/tcgzKY/lIhie+MB6ocWJh0l72t8fC5O13YHSVHKXMWqqAIPHifGQuDhoLCtaEKJ44a97NlzRH785aI8N8saWPpJ2ICXgz4o5lnVt0kOs3fXrDF8Xb3ln3BZFCoLmXCWKAl+PE0nUS5NNVeydCg7EZl2KzIs+A6BYDlpobbYG43vsmFccH5ABFVwfsOvvLZNCjbIViAnS6R0dJsJluXKLJ4ynCKkG+uRzhDJfkYzrpPtOyccBybQbvPsun0Eg/QIH4cyCo7lZtcPQ9pq9wStu1MDA1upgPYHriVhscIkBHr9CSiURHbsYksIqw9u/FLZrlH1i6pYlNo8pL72hAma97vviMeg4WWeh/2rnG5PKz4cIaO2A21BBtH7T75/AOprKfz73M45bNBWgPh3RWQAOH+p7aWaPKd3HzEqLKSIGMK7TtN5bHcpH3yesAA=="
tcp_payload_base64 = "JPxO+vQAcGZVdzFZCABFAAFGDPBAAEAG4l8KNAM5lZqnW9oUAbtAb+Xk5ntNwIAYAfAofgAAAQEICq1Dx6zf4UQ1Ho95gGRXfKOFqVksDBpKRL+7qCvjFm2vOoHSmDg+c4U++4uNEzlLvhDPX2/mmw/Vbyrlofp7VbWmHhF7z1EjlYtrPreHaJ2zZVa5jiaw3cuhWbexIwq6eCSJIUcCMLsTLWOiPcvZ/O48/4JApFIpiG9NNkEVjoVKJ6i3LEBQuNCby3JRrM/18z0x08BZMejOSlfJCyORirdN9BEM5UXyXMPAJebr0tRY9fKzVwxPfi0Id9/F8ahL9LyJTk4v5NdTBXp9yNYen2snJAh4cEBMIvJCzqccjVaAezMtzCSaou6Sht1gydxdRZO9ZV+Qw5e/5yLSQUYasOOV4WkcHHlDfy0n1MhUeLPE94wQeXVBI96Zhw=="
# tcp_payload_base64 = "JPxO+vQAcGZVdzFZCABFAAD9DO1AAEAG4qsKNAM5lZqnW9oUAbtAb+Ub5ntKUoAYAfZOeQAAAQEICq1Dxz7f4UPMos8o4vXoJt76qA1OQsZU0FeUP0ZmiUALG/Kq51scexQfctDy6OSGYfE7BhFIufcF720A8HyiDBFbK5TQyWPIrc8loqhqRd7JEx3uhqPAC9yR1Kt2rQKCHpk+K32UKYyWCp2PlhJzQ1c6wmnFsMZEkIqzk1dDojKl3Q1JSVCQUWwqge6jaknjavOTeQ05G+KemkgUGHMvgz1UI7LCwOIOf96BCXRjt99IGCDjFkg0yEEwzfMnevEvseP8svRqrT/V6udB3x/VXEoe"
tcp_payload_bytes = b64decode(tcp_payload_base64)[0x42:]
print(to_hex_str(tcp_payload_bytes[:64]))
print(to_hex_str(extract_protocol_bytes(tcp_payload_bytes[:64])))
# a = math.floor(time.time())<< 32
# b = (time.time_ns() - math.floor(time.time()) * 10**9)
# print(a + b)
# print(a.to_bytes(8, 'big').hex())
# print(b.to_bytes(8, 'big').hex())
# print((a+b).to_bytes(8, 'big').hex())
# print((int(time.time())).to_bytes(4, 'big'))
# print((time.time_ns() - int(time.time()) * 10**9).to_bytes(4, 'big'))
# t = (int(time.time()).to_bytes(4,'big')) +  (time.time_ns() - int(time.time()) * 10**9).to_bytes(4, 'big')
# print(t.hex())