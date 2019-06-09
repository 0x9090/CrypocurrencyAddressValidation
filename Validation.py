#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ====================================
# Cryptocurrency Validation Functions
# BTC, LTC, XMR
#
# Code modified from:
#
# Base58 decoding: https://github.com/keis/base58
# P2PKH validation: http://bit.ly/2DSVAXc
# Bech32 Validation: http://bit.ly/2Eaw40N
# XMR Validation: https://github.com/monero-project
# ====================================

import os
import sys
if os.path.exists(os.getcwd() + "\\venv"):
    sys.path.append(os.getcwd() + "\\venv\\Lib\\site-packages")
from decimal import Decimal
from binascii import hexlify, unhexlify
import re
import struct
import sha3
import operator as _oper
import base58


# --------------------- Global Variables -------------------- #


_ADDR_REGEX = re.compile(r'^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{95}$')
_IADDR_REGEX = re.compile(r'^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{106}$')
_str_types = (str, bytes)
__alphabet = [ord(s) for s in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz']
__UINT64MAX = 2**64
__encodedBlockSizes = [0, 2, 3, 5, 6, 7, 9, 10, 11]
__fullBlockSize = 8
__fullEncodedBlockSize = 11
indexbytes = _oper.getitem
intlist2bytes = bytes
int2byte = _oper.methodcaller("to_bytes", 1, "big")
b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
PICONERO = Decimal('0.000000000001')
EMPTY_KEY = '0' * 64
_integer_types = (int,)


# ----------------- Global Functions ----------------- @


def to_atomic(amount):
    """Convert Monero decimal to atomic integer of piconero."""
    if not isinstance(amount, (Decimal, float) + _integer_types):
        raise ValueError("Amount '{}' doesn't have numeric type. Only Decimal, int, long and "
                         "float (not recommended) are accepted as amounts.")
    return int(amount * 10**12)


def from_atomic(amount):
    """Convert atomic integer of piconero to Monero decimal."""
    return (Decimal(amount) * PICONERO).quantize(PICONERO)


def as_monero(amount):
    """Return the amount rounded to maximal Monero precision."""
    return Decimal(amount).quantize(PICONERO)


def _hexToBin(hex_):
    if len(hex_) % 2 != 0:
        raise ValueError("Hex string has invalid length: %d" % len(hex_))
    return [int(hex_[i:i + 2], 16) for i in range(0, len(hex_), 2)]


def _binToHex(bin_):
    return "".join('%02x' % int(b) for b in bin_)


def _uint8be_to_64(data):
    if not (1 <= len(data) <= 8):
        raise ValueError("Invalid input length: %d" % len(data))

    res = 0
    for b in data:
        res = res << 8 | b
    return res


def _uint64_to_8be(num, size):
    if size < 1 or size > 8:
        raise ValueError("Invalid input length: %d" % size)
    res = [0] * size

    twopow8 = 2**8
    for i in range(size-1,-1,-1):
        res[i] = num % twopow8
        num = num // twopow8

    return res


def xmr_base58_encode_block(data, buf, index):
    l_data = len(data)

    if l_data < 1 or l_data > __fullEncodedBlockSize:
        raise ValueError("Invalid block length: %d" % l_data)

    num = _uint8be_to_64(data)
    i = __encodedBlockSizes[l_data] - 1

    while num > 0:
        remainder = num % 58
        num = num // 58
        buf[index+i] = __alphabet[remainder]
        i -= 1

    return buf


def xmr_base58_encode(hex):
    '''Encode hexadecimal string as base58 (ex: encoding a Monero address).'''
    data = _hexToBin(hex)
    l_data = len(data)

    if l_data == 0:
        return ""

    full_block_count = l_data // __fullBlockSize
    last_block_size = l_data % __fullBlockSize
    res_size = full_block_count * __fullEncodedBlockSize + __encodedBlockSizes[last_block_size]

    res = bytearray([__alphabet[0]] * res_size)

    for i in range(full_block_count):
        res = xmr_base58_encode_block(data[(i*__fullBlockSize):(i*__fullBlockSize+__fullBlockSize)], res, i * __fullEncodedBlockSize)

    if last_block_size > 0:
        res = xmr_base58_encode_block(data[(full_block_count*__fullBlockSize):(full_block_count*__fullBlockSize+last_block_size)], res, full_block_count * __fullEncodedBlockSize)

    return bytes(res).decode('ascii')


def xmr_base58_decode_block(data, buf, index):
    l_data = len(data)

    if l_data < 1 or l_data > __fullEncodedBlockSize:
        raise ValueError("Invalid block length: %d" % l_data)

    res_size = __encodedBlockSizes.index(l_data)
    if res_size <= 0:
        raise ValueError("Invalid block size: %d" % res_size)

    res_num = 0
    order = 1
    for i in range(l_data-1, -1, -1):
        digit = __alphabet.index(data[i])
        if digit < 0:
            raise ValueError("Invalid symbol: %s" % data[i])

        product = order * digit + res_num
        if product > __UINT64MAX:
            raise ValueError("Overflow: %d * %d + %d = %d" % (order, digit, res_num, product))

        res_num = product
        order = order * 58

    if res_size < __fullBlockSize and 2**(8 * res_size) <= res_num:
        raise ValueError("Overflow: %d doesn't fit in %d bit(s)" % (res_num, res_size))

    tmp_buf = _uint64_to_8be(res_num, res_size)
    buf[index:index + len(tmp_buf)] = tmp_buf

    return buf


def xmr_base58_decode(enc):
    '''Decode a base58 string (ex: a Monero address) into hexidecimal form.'''
    enc = bytearray(enc, encoding='ascii')
    l_enc = len(enc)

    if l_enc == 0:
        return ""

    full_block_count = l_enc // __fullEncodedBlockSize
    last_block_size = l_enc % __fullEncodedBlockSize
    try:
        last_block_decoded_size = __encodedBlockSizes.index(last_block_size)
    except ValueError:
        raise ValueError("Invalid encoded length: %d" % l_enc)

    data_size = full_block_count * __fullBlockSize + last_block_decoded_size

    data = bytearray(data_size)
    for i in range(full_block_count):
        data = xmr_base58_decode_block(enc[(i*__fullEncodedBlockSize):(i*__fullEncodedBlockSize+__fullEncodedBlockSize)], data, i * __fullBlockSize)

    if last_block_size > 0:
        data = xmr_base58_decode_block(enc[(full_block_count*__fullEncodedBlockSize):(full_block_count*__fullEncodedBlockSize+last_block_size)], data, full_block_count * __fullBlockSize)

    return _binToHex(data)


def expmod(b, e, m):
    if e == 0: return 1
    t = expmod(b, e//2, m)**2 % m
    if e & 1: t = (t*b) % m
    return t


def inv(x):
    return expmod(x, q-2, q)


d = -121665 * inv(121666)
I = expmod(2, (q-1)//4, q)


def xrecover(y):
    xx = (y*y-1) * inv(d*y*y+1)
    x = expmod(xx, (q+3)//8, q)
    if (x*x - xx) % q != 0: x = (x*I) % q
    if x % 2 != 0: x = q-x
    return x


def compress(P):
    zinv = inv(P[2])
    return (P[0] * zinv % q, P[1] * zinv % q)


def decompress(P):
    return (P[0], P[1], 1, P[0]*P[1] % q)


By = 4 * inv(5)
Bx = xrecover(By)
B = [Bx%q, By%q]


def edwards(P, Q):
    x1 = P[0]
    y1 = P[1]
    x2 = Q[0]
    y2 = Q[1]
    x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
    y3 = (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2)
    return [x3%q, y3%q]


def add(P, Q):
    A = (P[1]-P[0])*(Q[1]-Q[0]) % q
    B = (P[1]+P[0])*(Q[1]+Q[0]) % q
    C = 2 * P[3] * Q[3] * d % q
    D = 2 * P[2] * Q[2] % q
    E = B-A
    F = D-C
    G = D+C
    H = B+A
    return (E*F, G*H, F*G, E*H)


def add_compressed(P, Q):
    return compress(add(decompress(P), decompress(Q)))


def scalarmult(P, e):
    if e == 0: return [0, 1]
    Q = scalarmult(P, e//2)
    Q = edwards(Q, Q)
    if e & 1: Q = edwards(Q, P)
    return Q


def encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return b''.join([int2byte(sum([bits[i*8 + j] << j for j in range(8)])) for i in range(b//8)])


def encodepoint(P):
    x = P[0]
    y = P[1]
    bits = [(y >> i) & 1 for i in range(b-1)] + [x & 1]
    return b''.join([int2byte(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b//8)])


def bit(h, i):
    return (indexbytes(h, i//8) >> (i%8)) & 1


def isoncurve(P):
    x = P[0]
    y = P[1]
    return (-x*x + y*y - 1 - d*x*x*y*y) % q == 0


def decodeint(s):
    return sum(2**i * bit(s, i) for i in range(0, b))


def decodepoint(s):
    y = sum(2**i * bit(s, i) for i in range(0, b-1))
    x = xrecover(y)
    if x & 1 != bit(s, b-1): x = q - x
    P = [x, y]
    if not isoncurve(P): raise Exception("decoding point that is not on curve")
    return P


def public_from_secret(k):
    keyInt = decodeint(k)
    aB = scalarmult(B, keyInt)
    return encodepoint(aB)


def public_from_secret_hex(hk):
    return hexlify(public_from_secret(unhexlify(hk))).decode()


def bech32_decode(bech):
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return False
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return False
    if not all(x in charset for x in bech[pos+1:]):
        return False
    hrp = bech[:pos]
    data = [charset.find(x) for x in bech[pos+1:]]
    if not bech32_verify_checksum(hrp, data):
        return False
    return True


def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def hextobin(hexstr):
    if (hexstr.length % 2) is not 0:
        return False
    res = list()
    index = 0
    for char in hexstr:
        res[index] = int(hexstr[(index * 2):(index * 2 + 2)])
        index += 1
    return res


# ------------------ Helper Classes ---------------- #


class BaseAddress(object):
    label = None

    def __init__(self, addr, label=None):
        addr = str(addr)
        if not _ADDR_REGEX.match(addr):
            raise ValueError("Address must be 95 characters long base58-encoded string, "
                             "is {addr} ({len} chars length)".format(addr=addr, len=len(addr)))
        self._decode(addr)
        self.label = label or self.label

    def is_mainnet(self):
        """Returns `True` if the address belongs to mainnet.
        :rtype: bool
        """
        return self._decoded[0] == self._valid_netbytes[0]

    def is_testnet(self):
        """Returns `True` if the address belongs to testnet.
        :rtype: bool
        """
        return self._decoded[0] == self._valid_netbytes[1]

    def is_stagenet(self):
        """Returns `True` if the address belongs to stagenet.
        :rtype: bool
        """
        return self._decoded[0] == self._valid_netbytes[2]

    def _decode(self, address):
        self._decoded = bytearray(unhexlify(xmr_base58_decode(address)))
        checksum = self._decoded[-4:]
        if checksum != sha3.keccak_256(self._decoded[:-4]).digest()[:4]:
            raise ValueError("Invalid checksum in address {}".format(address))
        if self._decoded[0] not in self._valid_netbytes:
            raise ValueError("Invalid address netbyte {nb}. Allowed values are: {allowed}".format(
                nb=self._decoded[0],
                allowed=", ".join(map(lambda b: '%02x' % b, self._valid_netbytes))))

    def __repr__(self):
        return xmr_base58_encode(hexlify(self._decoded))

    def __eq__(self, other):
        if isinstance(other, BaseAddress):
            return str(self) == str(other)
        if isinstance(other, _str_types):
            return str(self) == other
        return super(BaseAddress, self).__eq__(other)

    def __hash__(self):
        return hash(str(self))


class Address(BaseAddress):
    """Monero address.
    Address of this class is the master address for a :class:`Wallet <monero.wallet.Wallet>`.
    :param address: a Monero address as string-like object
    :param label: a label for the address (defaults to `None`)
    """
    _valid_netbytes = (18, 53, 24)
    # NOTE: _valid_netbytes order is (mainnet, testnet, stagenet)

    def view_key(self):
        """Returns public view key.
        :rtype: str
        """
        return hexlify(self._decoded[33:65]).decode()

    def spend_key(self):
        """Returns public spend key.
        :rtype: str
        """
        return hexlify(self._decoded[1:33]).decode()

    def check_private_view_key(self, key):
        """Checks if private view key matches this address.
        :rtype: bool
        """
        return public_from_secret_hex(key) == self.view_key()

    def check_private_spend_key(self, key):
        """Checks if private spend key matches this address.
        :rtype: bool
        """
        return public_from_secret_hex(key) == self.spend_key()

    def with_payment_id(self, payment_id=0):
        """Integrates payment id into the address.
        :param payment_id: int, hexadecimal string or :class:`PaymentID <monero.numbers.PaymentID>`
                    (max 64-bit long)
        :rtype: `IntegratedAddress`
        :raises: `TypeError` if the payment id is too long
        """
        payment_id = PaymentID(payment_id)
        if not payment_id.is_short():
            raise TypeError("Payment ID {0} has more than 64 bits and cannot be integrated".format(payment_id))
        prefix = 54 if self.is_testnet() else 25 if self.is_stagenet() else 19
        data = bytearray([prefix]) + self._decoded[1:65] + struct.pack('>Q', int(payment_id))
        checksum = bytearray(sha3.keccak_256(data).digest()[:4])
        return IntegratedAddress(xmr_base58_encode(hexlify(data + checksum)))


class SubAddress(BaseAddress):
    """Monero subaddress.
    Any type of address which is not the master one for a wallet.
    """

    _valid_netbytes = (42, 63, 36)
    # NOTE: _valid_netbytes order is (mainnet, testnet, stagenet)

    def with_payment_id(self, _):
        raise TypeError("SubAddress cannot be integrated with payment ID")


class IntegratedAddress(Address):
    """Monero integrated address.
    A master address integrated with payment id (short one, max 64 bit).
    """

    _valid_netbytes = (19, 54, 25)
    # NOTE: _valid_netbytes order is (mainnet, testnet, stagenet)

    def __init__(self, address):
        address = str(address)
        if not _IADDR_REGEX.match(address):
            raise ValueError("Integrated address must be 106 characters long base58-encoded string, "
                             "is {addr} ({len} chars length)".format(addr=address, len=len(address)))
        self._decode(address)

    def payment_id(self):
        """Returns the integrated payment id.
        :rtype: :class:`PaymentID <monero.numbers.PaymentID>`
        """
        return PaymentID(hexlify(self._decoded[65:-4]).decode())

    def base_address(self):
        """Returns the base address without payment id.
        :rtype: :class:`Address`
        """
        prefix = 53 if self.is_testnet() else 24 if self.is_stagenet() else 18
        data = bytearray([prefix]) + self._decoded[1:65]
        checksum = sha3.keccak_256(data).digest()[:4]
        return Address(xmr_base58_encode(hexlify(data + checksum)))


class PaymentID(object):
    """
    A class that validates Monero payment ID.

    Payment IDs can be used as str or int across the module, however this class
    offers validation as well as simple conversion and comparison to those two
    primitive types.

    :param payment_id: the payment ID as integer or hexadecimal string
    """
    _payment_id = None

    def __init__(self, payment_id):
        if isinstance(payment_id, PaymentID):
            payment_id = int(payment_id)
        if isinstance(payment_id, _str_types):
            payment_id = int(payment_id, 16)
        elif not isinstance(payment_id, _integer_types):
            raise TypeError("payment_id must be either int or hexadecimal str or bytes, "
                            "is {0}".format(type(payment_id)))
        if payment_id.bit_length() > 256:
            raise ValueError("payment_id {0} is more than 256 bits long".format(payment_id))
        self._payment_id = payment_id

    def is_short(self):
        """Returns True if payment ID is short enough to be included
        in :class:`IntegratedAddress <monero.address.IntegratedAddress>`."""
        return self._payment_id.bit_length() <= 64

    def __repr__(self):
        if self.is_short():
            return "{:016x}".format(self._payment_id)
        return "{:064x}".format(self._payment_id)

    def __int__(self):
        return self._payment_id

    def __eq__(self, other):
        if isinstance(other, PaymentID):
            return int(self) == int(other)
        elif isinstance(other, _integer_types):
            return int(self) == other
        elif isinstance(other, _str_types):
            return str(self) == other
        return super(PaymentID, self).__eq__(other)


# ------------------ Validation Class ----------------- #


class Validation:
    @staticmethod
    def is_btc_chain(chain):
        chain = chain.lower()
        chains = ["main", "testnet"]
        if chain in chains:
            return True
        return False

    @staticmethod
    def is_xmr_chain(chain):
        chain = chain.lower()
        chains = ["mainnet", "testnet", "stagenet"]
        if chain in chains:
            return True
        return False

    @staticmethod
    def is_coin_ticker(coin):
        coin = coin.lower()
        coins = ["btc", "ltc", "xmr"]
        if coin in coins:
            return True
        return False

    @staticmethod
    def is_coin_name(coin):
        coin = coin.lower()
        coins = ["bitcoin", "litecoin", "monero"]
        if coin in coins:
            return True
        return False

    @staticmethod
    def is_address(coin, address):
        coin = coin.lower()
        if not Validation.is_coin_ticker(coin):
            return False
        address = address.strip()
        if coin == "btc":
            return Validation.is_btc_address(address)
        if coin == "ltc":
            return Validation.is_ltc_address(address)
        if coin == "xmr":
            return Validation.is_xmr_address(address)
        return False

    @staticmethod
    def is_btc_address(address):  # Level 4 Validation
        if address[0] == "1":  # P2PKH Address
            return base58.b58decode_check(address)
        elif address[0] == "3":  # P2SH Address
            return base58.b58decode_check(address)
        elif address[:3] == "bc1":  # Bech32 Addresses (Segwit)
            return bech32_decode(address)
        else:
            return False

    @staticmethod
    def is_ltc_address(address):  # Level 4 Validation
        if len(address) > 43 or len(address) < 26:
            return False
        if address[0] == "L":  # Legacy Non-P2SH Address
            return base58.b58decode_check(address)
        elif address[0] == "3":  # P2SH Address - Deprecated
            return False
        elif address[0] == "M":  # P2SH Address
            return base58.b58decode_check(address)
        elif address[:4] == "ltc1":  # P2WPKH Bech32 (Segwit)
            return bech32_decode(address)
        return False

    @staticmethod
    def is_xmr_address(address, label=None):  # Level 4 Validation
        addr = str(address)
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        for char in address:
            if char not in charset:
                return False
        if len(address) not in [95, 106]:
            return False
        if _ADDR_REGEX.match(addr):
            try:
                netbyte = bytearray(unhexlify(xmr_base58_decode(addr)))[0]
                if netbyte in Address._valid_netbytes:
                    Address(addr, label=label)
                    return True
                elif netbyte in SubAddress._valid_netbytes:
                    SubAddress(addr, label=label)
                    return True
            except Exception:
                return False
        elif _IADDR_REGEX.match(addr):
            try:
                IntegratedAddress(addr)
                return True
            except Exception:
                return False
        return False
