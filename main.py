import base64
import hashlib
import hmac
import math
import threading
import time


def time_s():
    return math.floor(time.time())


def hotp(C: bytes, K: bytes, H=hashlib.sha1, Digit=6):
    digest = hmac.digest(K, C, H)
    offset = digest[-1] & 0x0F
    bin_code = bytearray(digest[i] for i in range(offset, offset + 4))
    bin_code[0] &= 0x7F
    return int.from_bytes(bin_code, byteorder="big") % 10 ** Digit


def totp(K, X=30, T0=0, H=hashlib.sha1, Digit=6):
    T = (time_s() - T0) // X
    return hotp(T.to_bytes(8, byteorder="big"), K, H=H, Digit=Digit)


DIGIT = 6
INTERVAL = 30
FIRST = True
K = base64.b32decode("")


def _print():
    def inner(interval):
        threading.Timer(interval, _print).start()

    print(str(totp(K, X=INTERVAL, Digit=DIGIT) + 10 ** DIGIT)[1:])
    now = time_s()
    interval = 0
    while (now + interval) % INTERVAL:
        interval += 1
    if not interval:
        interval = INTERVAL
    inner(interval)


_print()
