# computer-security
Repository for computer security programming assignments

Libraries Used:
---------------
hashlib - common interface for different secure hash and message digest algorithms

SHA and MD5 algorithms

zlib - adler32 and crc32 hash functions

- Simple to use interface. Example: sha256() creates a SHA-256 hash object
- Input type : bytes-like object

For larger than 2074 bytes use Python's GIL library ( multi threading performance boost)

NOTE: Feeding of string objects is not supported to update() method. Hashes work on bytes, not characters.

sha