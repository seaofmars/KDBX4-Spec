import hashlib
import struct
import hmac
import copy
# pip3 install argon2-cffi 
import argon2

sample_file = open('PasswordLetterA.kdbx', 'rb').read()
password    = 'a'
# aes256
# argon2d
# 38 rounds
# 64mib
# 2 threads

header_size = 253
hash_size   = 32
# For sanity checking
hc_header_hash = 'A60B604C1F5AF8482F70121CB873F28BB652E6F7401D7F78B59103FB4EE71E3C'.lower()

extracted_header = sample_file[0:header_size]
# Is this compsci
extracted_hash   = sample_file[header_size:header_size+hash_size]

if hc_header_hash != extracted_hash.hex():
	print('Unexpected kdbx database')
	exit()

header_hash = hashlib.sha256(extracted_header).hexdigest()

print('Extracted SHA-256:  ', extracted_hash.hex())
print('Calculated SHA-256: ', header_hash)
if extracted_hash.hex() == header_hash:
	print('OK')
else:
	print('ERR')

print()

extracted_hmac         = bytearray.fromhex('35F7537A2758DC3FED993C3F57755BA6EA2B8E081C03BBA956C1054A84DE98BD')
extracted_kdf_salt     = bytearray.fromhex('2F6DC429B7696F860B010159884DD755E237FAB60AD351CCBBE14DC05235A78E')
extracted_master_seed  = bytearray.fromhex('743ADA7E469A0E224986C2F1A888108BA1D54225758E4052EBE64CAE77020E61')


pbHmacKey64 = copy.deepcopy(extracted_master_seed)
pbHmacKey64.extend(
		argon2.low_level.hash_secret_raw(
			hashlib.sha256(hashlib.sha256(password.encode('utf-8')).digest()).digest(),
			bytes(extracted_kdf_salt),
			time_cost=38,
			memory_cost=67108864 // 1024,
			hash_len=32,
			parallelism=2,
			type=argon2.Type.D,
		)
)
pbHmacKey64.append(1)

hmac_key = hashlib.sha512(pbHmacKey64).digest()


# https://github.com/dlech/KeePass2.x/blob/6bb7f0cbe1afa5365fcdbed7adc124e82ac01fef/KeePassLib/Serialization/KdbxFile.cs#L479
pbBlockKey = hashlib.sha512(b'\xff' * 8 + hmac_key).digest()
calculated_hmac = hmac.digest(pbBlockKey, extracted_header, 'sha256')

print('Extracted HMAC:  ', extracted_hmac.hex())
print('Calculated HMAC: ', calculated_hmac.hex())
if extracted_hmac == calculated_hmac:
	print('OK')
else:
	print('ERR')
	