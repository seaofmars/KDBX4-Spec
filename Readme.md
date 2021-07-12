# Unofficial specification for KDBX 4

This is an unofficial specification based on the parsers of KeePass and
KeePassXC.

It's a WIP, some parts are undocumented.

# Binary format

KDBX is little-endian, so this document's representation of hex values is too.

## Magic and header

|  Type  |   Contents   |              Notes               |
| ------ | ------------ | -------------------------------- |
| uint32 | `0x03D9A29A` | KDBX magic                       |
| uint32 | `0x67FB4BB5` | KDBX v4 magic                    |
| uint32 | `0x00000400` | KDBX version (minor revisions may become `0x01000400` etc.) |

## Database information

Header entries are in the format:

```
struct entry
{
    // Correlates to what the entry contains, rather than its index in the file
    uint8 id;
    // The size of data in bytes
    uint32 size;
    uint8[] data;
};
```

Some IDs are legacy and only parsed in older KDBX versions.
There may be entries with the following fields:

### ID 0 End of header

End of header; stop reading header data. Encrypted content begins here.

- Size: N/A
- Data: N/A

### ID 1 Comment

**Unknown**

### ID 2 Cipher ID

Specifies the cipher used for encrypting the payload.

- Size: 16
- Data: Cipher UUID (see: Supported ciphers)

### ID 3 Compression

Specifies the compression algorithm used.

- Size: 4
- Data:
    - 0: No compression
    - 1: GZip

### ID 4 Master seed

The seed used to seed PRNG

- Size: 32
- Data: The seed

### ID 7 Encryption IV

The cipher IV

- Size: 16
- Data: The IV

### ID 11 KDF parameters

Key-derivation function parameters.

- Size: Variable
- Data: A variant dictionary:

```
struct variant_dictionary
{
    uint16 version;
    variant[] dictionary;
};

struct variant
{
    uint8   type;
    uint32  name_len;
    uint8[] name;
    uint32  value_len;
    uint8[] value;
};
```

The following `type` values are expected:

| Value | Description |
| ----- | ----------- |
| 0     | None        |
| 4     | uint32      |
| 5     | uint64      |
| 8     | bool        |
| 12    | int32       |
| 13    | int64       |
| 24    | string      |
| 66    | uint8[]     |


- The current variant dictionary version is `0x0001` as of 2021.
- When `0` is encountered, parsing of the variant dictionary ends.
- Strings are arrays of uint8s in UTF-8, without a BOM, without a null
terminator.

Known KDF parameters (title = name)

#### $UUID

- UUID of the KDF used (see: Supported KDFs)

#### I

- number of iterations to use

#### M

- memory in kibibytes to use

#### P

- parallelism factor

#### S

- salt

#### V

version of the kdf to use (e.g., argon2 v19, the latest)

### ID 12 Public custom data

**Unknown**

## Header SHA256

- Size: 32
- Data: Sha256 hash of the header contents (that is, every byte of the file up to this point)

## Header HMAC

- Size: 32
- Data: HMAC of the header

# Supported ciphers

|   Name   |                 UUID             | Notes |
| -------- | -------------------------------- | 
| AES-256  | 31c1f2e6bf714350be5805216afc5aff |
| Twofish  | ad68f29f576f4bb9a36ad47af965346c |
| ChaCha20 | d6038a2b8b6f4cb5a524339a31dbb59a |

# Supported KDFs

|   Name   |                 UUID             | Notes |
| -------- | -------------------------------- | 
| Argon2   | ef636ddf8c29444b91f7a9a403e30a0c |
| AES256   | c9d9f39a628a4460bf740d08c18a4fea |

# Process

- Read the header into the structure defined above
- Hash all read bytes with sha256. Compare this to the header sha256

## Computing the HMAC

Combine these three components into one byte array, in this order:
- the master seed from the header
- the kdf of the composite password
- the integer `1`

Hash the resulting array with sha512, append 8 `0xFF` bytes to the beginning, and hash it with sha512 again.

Compute the HMAC of the header (the same byte range as the sha256 hash used) using HMAC-SHA256 and the above array as the key. This should match the header hmac.

## KDF of passsord elements

### Composite password

If the database uses a password, hash it with SHA-256.

If the database uses a keyfile, read its contents and hash it with SHA-256.

Hash these components again. Even if the user has only a password and not a keyfile, hash the password *again*.

### KDF

A majority of the KDF parameters are exclusively for Argon2.

Additionally, when using Argon2, **use a raw hash**. If your KDF output looks like `$argon2d$v=19$m=400,t=5,p=4$....`, it's wrong. Your argon2 library should have facilities for "raw" hashes.

## 

# References

- <https://gist.github.com/msmuenchen/9318327>
- KeePass and KeePassXC source
- <https://github.com/keeweb/kdbxweb/tree/master/format>
- <https://github.com/Evidlo/examples/blob/master/python/kdbx4_decrypt.py>