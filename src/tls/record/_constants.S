// ─────────────────────────────────────────────────────────────────────
// File: src/tls/record/_constants.S — TLS record layer constants
//
// These constants are extracted from defs.S for use by the record
// submodules. This file is included by each submodule to get access
// to the .equ definitions needed for instruction immediates.
// ─────────────────────────────────────────────────────────────────────

.equ TLS_VERSION_1_0,                  0x0301
.equ TLS_VERSION_1_2,                  0x0303

.equ TLS_RECORD_CHANGE_CIPHER_SPEC,    20
.equ TLS_RECORD_ALERT,                 21
.equ TLS_RECORD_HANDSHAKE,             22
.equ TLS_RECORD_APPLICATION_DATA,      23
.equ TLS_RECORD_HEADER_LEN,            5
.equ TLS_MAX_PLAINTEXT,                16384
.equ TLS_TAG_LEN,                      16
.equ TLS_INNER_TYPE_LEN,               1
.equ TLS_MAX_CIPHERTEXT,               16640
.equ TLS_MAX_AEAD,                     16401

.equ TLS_RECORD_ERR_SHORT,             1
.equ TLS_RECORD_ERR_TYPE,              2
.equ TLS_RECORD_ERR_VERSION,           3
.equ TLS_RECORD_ERR_LENGTH,            4
.equ TLS_RECORD_ERR_BOUNDS,            5
.equ TLS_RECORD_ERR_MAC,               6
.equ TLS_RECORD_ERR_INNER,             7
.equ TLS_RECORD_ERR_EMPTY,             8
