## PackageProtector

Safe and secure data-at-rest protection for untrusted remote storage.

PackageProtector provides authenticated encryption for arbitrary-length streams by splitting them into independently signed and encrypted chunks. It combines the SP800-108 CTR KDF, HMAC-SHA512, and AES256-CBC to deliver a key-committing and message/context-committing design with random read/write access.

Protected streams have no headers or markers, making them indistinguishable from random data.
