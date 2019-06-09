# Cryptocurrency Address Validation
## BTC, LTC, XMR

This is a Python class which performs strong validation of different cryptocurrency addresses, chains, and ticker symbols. It will ensure that the data provided calculates to a correct value, and is syntactically safe to use. Segwit compatible

## Validation Levels
1. **Length** - Ensure the given address is the expected length
2. **Character Set** - Ensure that only the expected characters are used in the address
3. **Character Position** - Ensure that certain key characters are in their expected positions in the address
4. **Cryptographic** - Deconstruct the address into it's logical components, and validate that it parsed, and any checksums or signatures are correct

This library performs Levels 1 through 4 for all supported coins and address formats

### Supported Address Formats
* **BTC / LTC:** P2PKH, P2SH, Bech32
* **XMR:** Standard Address, Subaddress, Integrated Address

### Structure
This library has two dependencies: pysha3 and base58. You use this library by importing and calling static methods in the top-level Validation class. Coin tickers, chains, and names are case-insensitive. All functions return a boolean True/False answer.

```Python
class Validation:
    @staticmethod
    def is_btc_chain(chain): ...
    
    @staticmethod
    def is_xmr_chain(chain): ...
    
    @staticmethod
    def is_coin_ticker(coin): ...
    
    @staticmethod
    def is_coin_name(name): ...
    
    @staticmethod
    def is_address(coin, address): ...
    
    @staticmethod
    def is_btc_address(address): ...
    
    @staticmethod
    def is_ltc_address(address): ...
    
    @staticmethod
    def is_xmr_address(address, label=None): ...
```

### Usage:
```Python
from Validation import Validation

if Validation.is_coin_ticker("BTC"):
    print("Valid")
    
if Validation.is_btc_chain("testnet"):
    print("Valid")
    
if Validation.is_xmr_chain("stagenet"):
    print("Valid")

if Validation.is_coin_name("lITeCoiN"):
    print("Valid")
   
if Validation.is_address("BTC", "3FkenCiXpSLqD8L79intRNXUgjRoH9sjXa"):
    print("Valid")
    
if Validation.is_address("BTC", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"):
    print("Valid")

if Validation.is_address("LTC", "LS78aoGtfuGCZ777x3Hmr6tcoW3WaYynx9"):
    print("Valid")

if Validation.is_address("XMR", "46E5ekYrZd5UCcmNuYEX24FRjWVMgZ1ob79cRViyfvLFZjfyMhPDvbuCe54FqLQvVCgRKP4UUMMW5fy3ZhVQhD1JLLufBtu"):
    print("Valid")

```

### Disclaimers
I borrowed / modified code from these projects:
* Base58 decoding: https://github.com/keis/base58
* P2PKH validation: http://bit.ly/2DSVAXc
* Bech32 Validation: http://bit.ly/2Eaw40N
* XMR Validation: https://github.com/monero-project

Please test throughly before using this in a production environment. There are no warrantees, guarentees, or strings attached when using this software

### Future Work
* Integrate the base58 module code into the library itself
* Namespace the XMR, LTC, and BTC functions & classes
* Consolidate XMR and BTC base58 functions
