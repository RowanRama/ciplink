# S7comm-plus protocol notes

This page is the clean-room protocol description for the planned S7comm-plus client (Siemens S7-1200 / S7-1500
over TLS). It contains protocol facts only: byte layouts, identifiers, sequences, encodings and worked examples.
It contains no code from any existing driver. Implementers work from this page alone.

All example bytes on this page are **invented**: tag names, block names, comments, project name, serial number,
session IDs and process values were made up and re-encoded with the rules below. They are consistent with the real
format (every example decodes with the rules on this page) but they are not a recording of a real machine. Fixed
protocol constants that contain no project data (for example the client RID in CreateObject and the DB filter in
13.2) are given exactly as sent.

Evidence markers used below:

| Marker | Meaning |
|---|---|
| **[C]** | Observed in plaintext captures of sessions against a real S7-1500 F-CPU, firmware V3.1, project from TIA Portal V19, TLS mode: read-only sessions plus one session that wrote a single BOOL. |
| **[R]** | Known from studying an existing implementation's behaviour but **not** seen in our captures. Treat as likely, verify before relying on it. |
| **[W]** | From public protocol notes (Wireshark developer list). |

Scope: connect, session setup, CPU information, browse, symbolic read of many tags, symbolic write
(SetMultiVariables, section 17), symbol comments, disconnect. Subscriptions, alarms, password login (legitimation)
and CPU control are **out of scope** (not captured); their identifiers are listed in [Out of scope](#out-of-scope)
only so a parser can recognise them.

---

## 1. Layering

```
TCP port 102
 └ TPKT (RFC 1006, 4 bytes)
    └ COTP (ISO 8073 class 0): CR / CC / DT
       ├ first DT payload: one cleartext S7comm-plus PDU (InitSsl request / response)
       └ every later DT payload: a TLS 1.3 byte stream
            └ TLS application data: S7comm-plus frames (72 vv LL LL ... 72 vv 00 00)
```

There is exactly one cleartext S7comm-plus exchange (InitSsl). Everything after it is TLS. [C]

---

## 2. TPKT and COTP

### 2.1 TPKT

| Offset | Size | Value |
|---|---|---|
| 0 | 1 | `03` version |
| 1 | 1 | `00` reserved |
| 2 | 2 | total frame length including these 4 bytes, big endian |

### 2.2 Connection request (client) and confirm (PLC) [C]

Client sends (36 bytes):

```
03 00 00 24                      TPKT, length 36
1f                               COTP length indicator (31 bytes follow)
e0                               CR (connection request), class/credit 0
00 00                            destination reference
00 01                            source reference
00                               class 0, no options
c0 01 0a                         parameter C0 (TPDU size), length 1, value 0x0A = 2^10 = 1024 bytes
c1 02 06 00                      parameter C1 (calling / source TSAP), length 2, value 0x0600
c2 10 53 49 4d 41 54 49 43 2d    parameter C2 (called / destination TSAP), length 16,
      52 4f 4f 54 2d 48 4d 49      ASCII "SIMATIC-ROOT-HMI"
```

PLC answers with the same layout and `d0` (CC) instead of `e0`, destination reference `00 01` (the client's
source reference), its own source reference, and echoes the three parameters (TPDU size `0a` = 1024, `06 00`,
`SIMATIC-ROOT-HMI`). [C] The PLC's source reference varies per connection (`00 01` and `00 04` were both seen);
a client must not check it against a fixed value. [C]

* Remote TSAP for an HMI-type client: ASCII `SIMATIC-ROOT-HMI` (16 bytes). [C]
  An engineering client uses `SIMATIC-ROOT-ES`. [R] A read-only client should use the HMI TSAP.
* Local TSAP `06 00`. [C]
* Negotiated TPDU size: 1024 bytes (TPKT + COTP + payload). [C]

### 2.3 Data transfer (DT) frames

```
03 00 LL LL   TPKT
02            COTP length indicator
f0            DT
80 / 00       bit 7 = EOT (last data unit), bits 0..6 = TPDU number 0
...           payload (cleartext S7comm-plus, or TLS stream bytes)
```

* Maximum frame size is the negotiated TPDU size, 1024 bytes, so at most 1017 payload bytes per frame. [C]
* PLC to client: every DT frame observed carried EOT = 1, including full 1024-byte frames whose TLS record continued
  in the next frame. A client must treat the payloads as one continuous TLS byte stream and must not rely on EOT to
  find record boundaries. [C]
* Client to PLC: a TLS record longer than 1017 bytes was sent as several DT frames with EOT = 0 on all but the last
  frame; the PLC accepted this. Example: a TLS record whose length field was 0x0646 (1,606 bytes, so 1,611 bytes
  with the 5-byte record header) travelled as 1,017 + 594 payload bytes in two DT frames. [C]
* A DT frame with zero payload (`03 00 00 07 02 f0 00`) can occur and carries nothing. [R]

---

## 3. Cleartext InitSsl exchange [C]

Directly after COTP CC, the client sends one S7comm-plus PDU in cleartext inside a DT frame; the PLC answers in
cleartext. The framing (72 / version / length / trailer) is described in [section 5](#5-s7comm-plus-framing);
the PDU layouts in [section 6](#6-pdu-header).

Request on the wire (33 bytes including TPKT/COTP):

```
03 00 00 21 02 f0 80                       TPKT + COTP DT, EOT
72 01 00 12                                frame header: marker, protocol version 1, data length 18
31 00 00 05 b3 00 00 00 01 00 00 01 20 30  opcode Request, reserved, function InitSsl (0x05B3), reserved,
                                           sequence 1, session ID 0x00000120, transport flags 0x30
00 00 00 00                                4 zero bytes (end of request)
72 01 00 00                                frame trailer
```

Response (31 bytes):

```
03 00 00 1f 02 f0 80
72 01 00 10
32 00 00 05 b3 00 00 00 01 70             opcode Response, function InitSsl, sequence 1, transport flags 0x70
00                                         return value 0 (VLQ)
00 00 00 00 00                             5 zero bytes
72 01 00 00
```

* Session ID in the InitSsl request (and in the following CreateObject request) is `0x00000120` = 288
  ("null server session"). [C]
* As soon as the InitSsl response has arrived, the client starts the TLS handshake on the same COTP connection.

---

## 4. TLS

### 4.1 Starting TLS

The TLS ClientHello is sent as the payload of the next COTP DT frame after the InitSsl response. From then on
every DT payload in both directions is part of the TLS stream (records may be split across DT frames and one DT
frame may carry several records). [C]

### 4.2 Version, cipher suites, key exchange

Observed handshake (client offered TLS 1.3 only):

| Item | Value |
|---|---|
| Record-layer version in ClientHello | `03 01`; ClientHello legacy_version `03 03`; supported_versions extension: TLS 1.3 only [C] |
| Cipher suites offered | `13 02` TLS_AES_256_GCM_SHA384, `13 01` TLS_AES_128_GCM_SHA256 [C] |
| Cipher chosen by PLC | `13 02` TLS_AES_256_GCM_SHA384 [C] |
| Key share chosen by PLC | group 29 (x25519), 32-byte key [C] |
| Groups offered by the test client | x25519, x448, secp256r1, secp384r1, ffdhe2048, ffdhe3072, ffdhe4096 [C] |
| Session ID echo | 32-byte legacy session ID present (middlebox-compatibility mode) [C] |
| Client certificate | not requested [C] |

ClientHello extensions sent by the tested client, all accepted [C]: `00 05` status_request, `00 0d`
signature_algorithms, `00 0a` supported_groups, `00 2b` supported_versions (TLS 1.3 only), `00 33` key_share
(x25519). No server_name (SNI) and no ALPN extension was sent; whether the PLC tolerates them is **untested**
(a client should leave them out). Whether the PLC also accepts TLS 1.2 or ChaCha20 was not tested. TLS 1.3 with
AES-GCM is known to work.

Right after the handshake the PLC sends two encrypted records of 250 bytes ciphertext each (one DT frame) that
carry no S7comm-plus data; the TLS library consumed them. Their size and timing fit two TLS 1.3 NewSessionTicket
messages. Session resumption was never attempted, so whether the PLC accepts it is unknown; a client should do a
full handshake on every connect. [C for the records, R for their meaning]

Observed timings (for choosing timeouts, not limits) [C]: TLS handshake 400 to 550 ms from ClientHello to
completion in four of five connects; in one connect the ClientHello left 2.5 s after the InitSsl response and the
handshake took 1.28 s (the delay looked client-side, but a client must tolerate it); InitSsl and small requests
answered in 20 to 160 ms; a 30 KB Explore response complete after 1.8 s; the 466 KB type-info Explore after 6.4 s.
A connect timeout of 10 s or more, a response timeout of a few seconds for small requests and of tens of seconds
for large Explore requests is consistent with this. (The capture client's 5 s connect timeout was too short once.)

Record sizes: the PLC sends application-data records of at most 1,000 bytes of ciphertext (983 bytes of plaintext
+ 17 bytes AES-GCM overhead) and puts exactly one S7comm-plus frame in each record. The client may send larger
records. [C]

### 4.3 Server certificate [C]

| Field | Observed |
|---|---|
| Chain length | 1 (self-signed leaf only) |
| Key | ECDSA P-256 (prime256v1) |
| Signature | ecdsa-with-SHA256 |
| Subject = Issuer | `C=DE, O=Siemens, OU=Industrial Communication, CN=<device name>/<interface name>` (for example `CN=PLC_Line1/Communication-1`; follows the names configured in TIA Portal) |
| Validity | about 11 years (issued at project download, expiring 2037) |
| Basic constraints | CA:FALSE |
| Key usage | Digital Signature, Non Repudiation, Key Encipherment, Key Agreement, Certificate Sign |
| Extended key usage | TLS Web Server Authentication, TLS Web Client Authentication |
| Subject alternative name | the PLC's configured IP address (one `IP Address` entry) |

What a client must and must not verify:

* The certificate is self-signed by the PLC (or by the TIA project CA when one is configured; not seen here), so
  verification against the operating-system trust store fails.
* The SAN holds the IP configured in the project. Behind NAT or a router (our case) it differs from the address the
  client connects to, so host-name / IP verification fails even for a genuine PLC.
* Consequence: a standard verifier (operating-system store, webpki / rustls default verifier) rejects this
  certificate (unknown issuer, and an address mismatch behind NAT), so a client **must** install its own certificate
  check. The check replaces only the chain and name validation: the TLS 1.3 CertificateVerify signature must still
  be verified with the presented certificate's key, so that the server proves it holds the pinned key.
* Recommended policy: pin the certificate (SHA-256 fingerprint of the DER certificate, or of its public key) per
  PLC, trust on first use with an explicit operator confirmation, and alert when it changes (it changes after a new
  hardware configuration download). Offer an "accept any" mode only as an explicit option.
* signature_algorithms: the key is P-256, so the client must offer `04 03` ecdsa_secp256r1_sha256. The tested
  client offered a long list that included it (ed25519, ed448, ecdsa P-256 / P-384 / P-521, RSA-PSS, RSA PKCS#1
  and others); which one the PLC chose is inside the encrypted handshake and was not seen. [C for the offer]
* The TLS exporter (RFC 8446 section 7.5) with label `EXPERIMENTAL_OMS`, no context, 32 bytes, is used only for
  password login (legitimation), which is out of scope. [R]

### 4.4 Closing

On disconnect the client sends a TLS close_notify alert (an encrypted 19-byte record) after the DeleteObject
exchange, then closes TCP. [C]

The PLC never sent a close_notify of its own: in every session its last TLS record was the one carrying the
DeleteObject response (or, in the aborted attempt, the post-handshake records). A client must not wait for a peer
close_notify and must treat a TCP close without one as a normal end after DeleteObject. [C]

---

## 5. S7comm-plus framing

Inside TLS (and for the cleartext InitSsl) S7comm-plus data travels in frames:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `72` frame marker |
| 1 | 1 | protocol version: `01`, `02`, `03`, or `fe` (system event) |
| 2 | 2 | length of the data part that follows, big endian |
| 4 | n | data part |

A PDU may be split over several frames. The **last** frame of a PDU is followed by a 4-byte trailer
`72 vv 00 00` (same version byte, zero length). Frames without a trailer are continued by the next frame. The
trailer is what marks the end of the PDU. [C]

* PLC to client: each frame carries at most 979 (0x3D3) data bytes; the trailer follows the last frame of the PDU
  in the same TLS record. A 465,622-byte Explore response arrived as 476 frames. [C] 979 is only the maximum:
  110 of 688 continuation frames (frames without a trailer) carried 972 to 978 data bytes. A reassembler must use
  the length field of each frame and must not assume a fixed continuation size. [C]
* Client to PLC: every request in the captures was sent as **one** frame (data part plus trailer) in one TLS
  record. The largest was a GetMultiVariables request with a 1,581-byte data part (frame header `72 02 06 2d`;
  1,582 bytes when the version byte is counted as on this page), which the PLC accepted. [C] Splitting a request
  into several frames the way the PLC does is **untested**; a client should send each request as one frame. [R]
* Protocol version byte per PDU: `01` for InitSsl and CreateObject (and their responses); `02` for everything after
  the session is created. [C] `03` is used in legacy (non-TLS) mode with packet digests. [R]
* Version `fe` frames are "system events" (extended keep-alive / status) that have **no trailer**; their data part
  uses fixed-width integers instead of VLQ. None were received in our sessions. [R]

Throughout this page, "PDU" and the example hex mean the reassembled PDU: the protocol version byte followed by the
concatenated data parts, without the 72-headers and trailer.

---

## 6. PDU header

### 6.1 Request (opcode 0x31)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | protocol version (from frame header) |
| 1 | 1 | opcode `31` = request |
| 2 | 2 | reserved `00 00` |
| 4 | 2 | function code, big endian |
| 6 | 2 | reserved `00 00` |
| 8 | 2 | sequence number, big endian |
| 10 | 4 | session ID, big endian |
| 14 | 1 | transport flags |
| 15 | .. | function-specific request body |

### 6.2 Response (opcode 0x32)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | protocol version |
| 1 | 1 | opcode `32` = response |
| 2 | 2 | reserved |
| 4 | 2 | function code (same as request) |
| 6 | 2 | reserved |
| 8 | 2 | sequence number (same as request) |
| 10 | 1 | transport flags |
| 11 | VLQ64 | return value (see [section 12](#12-return-values-and-errors)) |
| .. | .. | function-specific response body |

Responses carry no session ID. Other opcodes: `33` notification (subscriptions, out of scope), `02` an alternative
response opcode. [R]

### 6.3 Function codes

| Code | Name | Used here |
|---|---|---|
| `04 B1` | Error | recognise only |
| `04 BB` | Explore | yes |
| `04 CA` | CreateObject | yes (session only) |
| `04 D4` | DeleteObject | yes (session only) |
| `04 F2` | SetVariable | no (write) |
| `04 FC` | GetVariable | no (older S7-1200 firmware) |
| `05 06` / `05 1A` / `05 24` | AddLink / RemoveLink / GetLink | no |
| `05 42` | SetMultiVariables | session setup and writes (section 17) |
| `05 4C` | GetMultiVariables | yes (reads) |
| `05 56` / `05 60` | BeginSequence / EndSequence | no |
| `05 6B` | Invoke | no |
| `05 7C` | SetVarSubStreamed | no |
| `05 86` | GetVarSubStreamed | yes |
| `05 90` | GetVariablesAddress | no |
| `05 9A` | Abort | no |
| `05 A9` | Error (2) | recognise only |
| `05 B3` | InitSsl | yes (cleartext) |

### 6.4 Transport flags

| Value | Seen on |
|---|---|
| `30` | InitSsl request [C] |
| `70` | InitSsl response [C] |
| `36` | CreateObject request and response [C]. In a CreateObject response bit 0x02 announces that a response object follows the object-ID list. |
| `34` | every other request and response in our sessions [C] |
| `74` | requests that expect no response [R] |

### 6.5 Sequence number

16-bit counter per session, starting at 1 with InitSsl and incremented by 1 for every request the client sends.
The response echoes the request's sequence number. [C] (The highest sequence number in the captures is 68.)
After 0xFFFF it continues at 1 (0 is skipped). [R, the wrap was never observed; this is what the studied
implementation does]

### 6.6 Integrity ID

Requests with protocol version 2 carry an integrity ID (VLQ) near the end of the body (position given per
function below). InitSsl, CreateObject and the session-setup SetMultiVariables carry none. [C]

* The client keeps **two** counters, both starting so that the first value sent is 1 [C]:
  * one for SetMultiVariables, SetVariable, SetVarSubStreamed, CreateObject and DeleteObject (after session setup);
  * one for all other functions (GetMultiVariables, GetVarSubStreamed, Explore, ...).
  Each request takes the next value of its counter. [C] Example from the write session: the two tag writes took
  "set" values 1 and 2 and the DeleteObject took 3, while the reads in between continued the other counter. [C]
  (The highest request integrity ID in the captures is 64.) After 0xFFFFFFFF a counter continues at 0. [R, never
  observed]
* Which responses carry an integrity ID [C]:

  | Response | Integrity ID in the response |
  |---|---|
  | GetMultiVariables, GetVarSubStreamed, Explore | yes: request sequence number + request integrity ID. Example: sequence 4, integrity 1 is answered with 5. |
  | SetMultiVariables (tag write) | yes, same rule: sequence 10, integrity 1 was answered with 11 (0x0B); sequence 12, integrity 2 with 14 |
  | SetMultiVariables (session setup) | yes, the field is present (after the error list) and was `00`; the request carried none |
  | DeleteObject | **no**, although the request carries one |
  | InitSsl, CreateObject | no |

  The addition wraps at 32 bits (unsigned). [R, never observed]
* A wrong sequence number or integrity ID causes the PLC to report a protocol error, after which the connection
  must be closed. [R, never provoked]

### 6.7 End of PDU

Every request body ends with 4 zero bytes (`00 00 00 00`); Explore requests end with 5. Every response body we saw
ends with 4 zero bytes after the last field, except the InitSsl response, which has 5 zero bytes after its return
value. [C]

### 6.8 Requests in flight

In every capture the client sent one request and waited for its response before sending the next; requests and
responses strictly alternate. [C] The studied implementation can optionally keep up to 16 GetMultiVariables
requests outstanding (default 1, documented as "2 helps on some CPUs"), matches each response to its request by
sequence number, accepts responses in any order, checks the integrity ID per response, and keeps all other
functions (writes included) strictly sequential. [R] Default for a client: one request at a time.

---

## 7. Integer and string encodings

* Fixed-width integers in PDU headers and in values of type UInt, Int, Word, DWord, LWord, RID, Timestamp, Real,
  LReal are **big endian**. [C]
* Inside type-information lists (section 10.5) most fields are **little endian**. [C]
* Floating point is IEEE 754 binary32 / binary64. [C]

### 7.1 VLQ, unsigned 32 bit (VLQ32)

Big-endian base-128: the value is split into 7-bit groups, most significant group first; every byte except the last
has bit 7 set. At most 5 bytes. Minimal length is used. [C]

| Value | Bytes |
|---|---|
| 0 | `00` |
| 127 | `7f` |
| 300 | `82 2c` |
| 1000 | `87 68` |
| 2550 | `93 76` |
| 0x8A0E0005 | `88 d0 b8 80 05` |
| 0x70000A10 | `87 80 80 94 10` |

### 7.2 VLQ, signed 32 bit (SVLQ32)

Same grouping, two's complement. In the **first** byte, bit 6 is the sign bit: if it is set, the value is
negative and the first byte's low 6 bits are the top bits of a sign-extended number. The encoder uses the fewest
bytes such that the value fits in 7*n - 1 bits (n = 1..5). [C]

| Value | Bytes |
|---|---|
| 0 | `00` |
| 63 | `3f` |
| 64 | `80 40` |
| -1 | `7f` |
| -64 | `40` |
| -65 | `ff 3f` |
| -300 | `fd 54` |
| -1934830580 | `f8 e5 b3 a8 0c` |

(A non-minimal 5-byte form with extra leading sign bytes is also decoded by the PLC. [R])

### 7.3 VLQ, 64 bit (VLQ64 / SVLQ64)

As above with up to 8 bytes of 7-bit groups (bit 7 = continuation). If the 8th byte still has bit 7 set, a **9th
byte follows that contributes all 8 bits** (so 8*7 + 8 = 64 bits). Values below 2^56 use the normal form.
Signed variant: sign in bit 6 of the first byte as in 7.2. [C]

| Value | Bytes |
|---|---|
| 1234567 | `cb ad 07` |
| 0x60228000012D0011 | `b0 88 d0 80 80 84 da 80 11` |
| 17380307404114137132 | `f8 cc e8 97 fe b5 a1 90 2c` |

When encoding, a value that needs the 9-byte form must use it even when an 8-byte form would decode to the same
number; the PLC expects the 9-byte form for values from 2^56 upwards. [R]

### 7.4 Strings

* WString values (datatype `15`): VLQ32 byte length, then UTF-8 bytes, no terminator. [C]
* Names in varname lists: 1-byte length, UTF-8 bytes, then one `00` byte. [C]
* PLC STRING / WSTRING *tag values* are transported as arrays, see section 11.4.

---

## 8. Values

A value is: `flags` (1 byte), `datatype` (1 byte), payload. [C]

### 8.1 Flags

| Bit | Meaning |
|---|---|
| `10` | array: payload starts with a VLQ32 element count, then the elements (payload only, no per-element header) |
| `20` | address array: same wire form as an array |
| `40` | sparse array: list of (VLQ32 key, element) pairs terminated by key 0 |
| `80` | seen combined with the shape bits in notifications [R, never seen] |

Flags `10`, `20` and `40` were all seen [C]; `80` never.

### 8.2 Datatypes

| Code | Name | Scalar payload | |
|---|---|---|---|
| `00` | Null | none | [R] |
| `01` | Bool | 1 byte, 0 or 1 | [C] |
| `02` | USInt | 1 byte | [C] |
| `03` | UInt | 2 bytes BE | [C] |
| `04` | UDInt | VLQ32 | [C] |
| `05` | ULInt | VLQ64 | [C] |
| `06` | SInt | 1 byte, two's complement | [C] |
| `07` | Int | 2 bytes BE, two's complement | [C] |
| `08` | DInt | SVLQ32 | [C] |
| `09` | LInt | SVLQ64 | [C] |
| `0A` | Byte | 1 byte | [C] |
| `0B` | Word | 2 bytes BE | [C] |
| `0C` | DWord | 4 bytes BE | [C] |
| `0D` | LWord | 8 bytes BE | [R] |
| `0E` | Real | 4 bytes IEEE BE | [C] |
| `0F` | LReal | 8 bytes IEEE BE | [C] |
| `10` | Timestamp | 8 bytes BE, nanoseconds since 1970-01-01 00:00 (time zone: see 11.5) | [C] |
| `11` | Timespan | SVLQ64, nanoseconds | [R] |
| `12` | RID | 4 bytes BE | [C] |
| `13` | AID | VLQ32 | [C] |
| `14` | Blob | see 8.4 | [C] |
| `15` | WString | VLQ32 length + UTF-8 | [C] |
| `16` | Variant | VLQ32 | [R] |
| `17` | Struct | see 8.5 | [C] |
| `19` | S7String | VLQ32 (a maximum length) | [R] |

[R] rows never occurred in any capture; their payload encodings are taken from the studied implementation.

Array elements use the scalar payload of the element type (for example a UDInt array is a count followed by VLQ32
elements; a UInt array is a count followed by 2-byte elements). [C]

### 8.3 Sparse arrays

`flags 40`: repeated `key (VLQ32)` + element payload, ended by key `00`. For blobs each element is
`root ID (VLQ32)`, `length (VLQ32)`, bytes. Seen with WString (`15`) and Blob (`14`). [C]

### 8.4 Blob

`root ID (VLQ32)`; if root ID > 1: 8 bytes (zero so far) and a 1-byte blob type [R]; then `length (VLQ32)` and that
many bytes. All blobs in our captures had root ID 0. [C]

### 8.5 Struct

`struct ID` (4 bytes BE), then either:

* **Normal struct**: repeated `element ID (VLQ32)` + full value (flags + datatype + payload), ended by element ID
  `00`. [C]
* **Packed struct**, used when the struct ID is in 0x02000001..0x02FFFFFE (system datatypes, ID = 0x02000000 +
  softdatatype or a system type number) or 0x90000001..0x9FFFFFFE (user types): [C]

  | Field | Encoding |
  |---|---|
  | interface timestamp | 8 bytes BE; equals attribute 529 of the type's type-info object |
  | transport flags | VLQ32; bit 0x02 always set; bit 0x01 = classic (non-optimized) byte layout [C]; bit 0x400 = an array of structs: two counts follow [C] |
  | byte count | VLQ32; with bit 0x400: the size of one element, then the total byte count [C] |
  | data | raw bytes in the PLC memory layout of the type, see 11.8 |

  The struct ID of a packed struct is the base-form type RID of the struct type (the relation ID in the member's
  offset info, section 13.5), never one of the DB-form variants. Seen: 0x02000043 (DTL), 0x0200001F (IEC_TIMER),
  0x9204nnnn (a STRUCT member declared inside a DB, 13.3), 0x0208072A (a system struct in the I area). [C]

---

## 9. Objects

Objects appear in CreateObject and Explore. Element tags: [C]

| Tag | Meaning | Layout after the tag |
|---|---|---|
| `A1` | start of object | relation ID (4 bytes BE), class ID (VLQ32), class flags (VLQ32), attribute ID (VLQ32); then nested elements |
| `A2` | end of object | none |
| `A3` | attribute | attribute ID (VLQ32), value |
| `A4` | relation | [R] |
| `A7` / `A8` | start / end of tag description | old non-TLS firmware only [R] |
| `AB` | vartype list | section 10.5 |
| `AC` | varname list | section 10.5 |

An Explore response body is a sequence of `A1 ... A2` objects; objects nest.

### 9.1 Object qualifier

Several requests end with this fixed block [C]:

```
00 00 04 e8                 ID 1256 (ObjectQualifier), 4 bytes BE
89 69  00 12 00 00 00 00    1257 ParentRID     = RID 0
89 6a  00 13 00             1258 CompositionAID = AID 0
89 6b  00 04 00             1259 KeyQualifier   = UDInt 0
00                          end of list
```

---

## 10. Session

### 10.1 Sequence [C]

1. TCP connect to port 102, COTP CR/CC.
2. InitSsl request / response (cleartext, protocol version 1, sequence 1).
3. TLS 1.3 handshake.
4. CreateObject (version 1, sequence 2) creates the server session.
5. SetMultiVariables (version 2) writes the server's session-version struct back to the session object.
6. Optional reads: system limits, effective protection level.
7. Normal requests (version 2).
8. DeleteObject of the session, TLS close_notify, TCP close.

### 10.2 CreateObject request

Example (byte for byte what the tested client sent; no project data in it):

```
0131000004ca0000000200000120360000011d00040000000000a1000000d3821f0000a3822c001280c3c901a1000000
d3817f0000a2a200000000
```

| Bytes | Meaning |
|---|---|
| `01 31 0000 04ca 0000 0002` | version 1, request, CreateObject, sequence 2 |
| `00000120` | session ID 288 (null server session) |
| `36` | transport flags |
| `0000011d` | request ID 285 = ObjectServerSessionContainer (4 bytes BE) |
| `00 04 00` | value UDInt 0 |
| `00000000` | 4 zero bytes (meaning unknown; send as shown) |
| `a1 000000d3 821f 00 00` | object: RID 211 (GetNewRIDOnServer), class 287 (ClassServerSession), flags 0, AID 0 |
| `a3 822c 00 12 80c3c901` | attribute 300 ServerSessionClientRID = RID 0x80C3C901 (meaning unknown; the only value ever sent, in every captured session; whether other values are accepted is untested) |
| `a1 000000d3 817f 00 00 a2` | child object: RID 211, class 255 (ClassSubscriptions), empty |
| `a2` | end of session object |
| `00000000` | end of request |

No integrity ID.

### 10.3 CreateObject response

Example:

```
0132000004ca0000000236b088d0808084da80110287808094108780809411a100000120821f0100a381690015133030
3a30313233343536373839414243444546a3822b000402a3822d0015245365727665723a204f4d53505f31342e30302e
30302e30335f36362e30332e30302e3031a3822f100214101112131415161718191a1b1c1d1e1f20212223a382320017
0000013a823b00048701823c00048701823d000484818540823e000484818540823f00151a313b36455337203558582d
58585858582d584142303b56332e31824000150a323b313233343536373882410003000300a200000000
```

| Bytes | Meaning |
|---|---|
| `36` | transport flags (bit 0x02: response object present) |
| `b0 88 d0 80 80 84 da 80 11` | return value VLQ64 = 0x60228000012D0011 (non-zero on success, see 12) |
| `02` | object-ID count (1 byte) |
| `87 80 80 94 10`, `87 80 80 94 11` | object IDs (VLQ32). The first is the **session ID** for all later requests [C]; the second (always first + 1 here) is used for notification-based jobs such as subscriptions [R, never used]. |
| `a1 00000120 821f 01 00` | session object, class 287 |
| attribute 233 | WString, session name (`00:` + 16 hex digits) |
| attribute 299 | UDInt, server session role (2 observed) |
| attribute 301 | WString, server version text (`Server: OMSP_...`) |
| attribute 303 | USInt array of 20 bytes, server session challenge (used only by legitimation) |
| attribute 306 | Struct 314, **ServerSessionVersion** |
| `a2 00000000` | end |

Struct 314 (ServerSessionVersion) elements [C]:

| Element | Type | Meaning |
|---|---|---|
| 315 | UDInt | system OMS version |
| 316 | UDInt | project OMS version |
| 317 | UDInt | system PAOM version |
| 318 | UDInt | project PAOM version |
| 319 | WString | system PAOM string, `1;<order number>;V<major>.<minor>`, e.g. `1;6ES7 5XX-XXXXX-XAB0;V3.1` |
| 320 | WString | project PAOM string, `2;<number>` |
| 321 | UInt | project format (3) |

The firmware version in element 319 decides the login style (out of scope) and is a cheap way to identify the CPU.

Observation: the same session ID was handed out again by the PLC for each later connection after the previous
session had been deleted with DeleteObject (four sessions, all with the same ID). [C] Session IDs must therefore
not be used to tell connections apart. Whether the ID is also reused after a connection that is dropped without
DeleteObject is unknown: in the one aborted attempt the CreateObject request never reached the wire. [C]

### 10.4 Session setup: SetMultiVariables

The client writes struct 306 back to the session object **byte for byte as received**:

```
0231000005420000000370000a103470000a10010182320100170000013a823b00048701823c00048701823d00048481
8540823e000484818540823f00151a313b36455337203558582d58585858582d584142303b56332e31824000150a323b
31323334353637388241000300030000000004e88969001200000000896a001300896b0004000000000000
```

| Bytes | Meaning |
|---|---|
| `02 31 0000 0542 0000 0003` | version 2, request, SetMultiVariables, sequence 3 |
| `70000a10` | session ID |
| `34` | transport flags |
| `70000a10` | object ID to write into (the session ID), 4 bytes BE |
| `01` | value count (VLQ32) |
| `01` | address count (VLQ32) |
| `82 32` | address: attribute 306 |
| `01` | item number 1 |
| `00 17 0000013a ... 00` | value: struct 314 exactly as received |
| `00` | fill byte (meaning unknown; send as shown) |
| object qualifier | section 9.1 |
| `00000000` | end (no integrity ID) |

Response (18 bytes) [C]:

```
023200000542000000033400000000000000
```

| Bytes | Meaning |
|---|---|
| `02 32 0000 0542 0000 0003` | version 2, response, SetMultiVariables, sequence 3 |
| `34` | transport flags |
| `00` | return value 0 (VLQ64) |
| `00` | end of the item error list (an entry would be item number VLQ32 + item error VLQ64, as in 11.3) |
| `00` | integrity ID (VLQ32), 0 here because the request carried none |
| `00000000` | end |

This is the same layout as the response to a tag write (section 17.2), where the integrity ID field is non-zero
(sequence + request integrity ID). That settles the split of the six bytes after the return value: error-list end,
integrity ID, 4-byte end. [C] For the session setup the PLC sends integrity 0, not sequence + 0. [C]

### 10.5 System limits (optional) [C]

GetMultiVariables (section 11) of area RID 201 (ObjectRoot), sub-area 1037 (SystemLimits), LIDs:

| LID | Meaning | Observed |
|---|---|---|
| 1000 | max tags per read request | 100 |
| 1001 | max tags per write request | 100 |
| 0 | max subscriptions | 250 |
| 1 | max PLC attributes | 2000 |
| 2 | subscription memory, bytes | 524288 |

The same with sub-area 1081 (FreeItems) and LIDs 0, 1, 2 returns the currently free subscriptions, attributes and
subscription memory. All values are DInt (or UDInt). [C]

```
request  02310000054c0000000470000a103400000000051900814902880d876800814902880d876900814902880d0000814902
         880d0100814902880d02000004e88969001200000000896a001300896b000400000100000000
response 02320000054c00000004340001000880640200088064030008817a0400088f50050008a0800000000500000000
```

### 10.6 Effective protection level (optional) [C]

GetVarSubStreamed of the session object, attribute 1842 (EffectiveProtectionLevel), returns a UDInt.
0 was returned for a CPU without read protection. A non-zero value above "full access" means a password login
would be needed for some operations; reading HMI-accessible tags worked without login here. Levels other than 0
were not observed.

```
request  0231000005860000000570000a103470000a102004018e32000004e88969001200000000896a001300896b0004000000
         010200000000
response 023200000586000000053400000004000700000000
```

### 10.7 Keep-alive

No request is needed to keep the session open for at least 40 s: a session left idle for 40 s still answered the
following DeleteObject normally, and the PLC sent nothing during the idle time. [C] The PLC's idle timeout is
unknown; a client should send a cheap request (for example the protection-level read, or a read of one known tag)
every 10 to 20 s when otherwise idle. System-event frames (version `fe`) from the PLC must be accepted and ignored
unless they carry a negative return value, which means the connection is dead. [R]

### 10.8 Disconnect [C]

```
request  0231000004d40000000e70000a103470000a1000000004e88969001200000000896a001300896b000400000100000000
response 0232000004d40000000e349088f08080828e802d70000a1000000000
```

Request body: object ID to delete (the session ID, 4 bytes BE), `00`, object qualifier, integrity ID (from the
"set" counter), 4 zero bytes. Response: return value (non-zero on success, 0x202380000087002D), the deleted object
ID (4 bytes BE), then `00 00 00 00`; **no integrity ID**. Then TLS close_notify and TCP close.

---

## 11. Reading tags: GetMultiVariables

### 11.1 Request

| Field | Encoding |
|---|---|
| link ID | 4 bytes BE, 0 for reads |
| item count | VLQ32 |
| field count | VLQ32 = sum over items of (4 + number of LIDs) |
| items | one address per item, see 11.2 |
| object qualifier | section 9.1 |
| integrity ID | VLQ32 |
| end | `00 00 00 00` |

Limit: at most "max tags per read request" items (100 on the tested CPU). [C] A request with more items was not
tried; the client must split.

### 11.2 Item address

| Field | Encoding |
|---|---|
| symbol CRC | VLQ32 (0 = do not check, see 11.6) |
| access area | VLQ32 |
| number of IDs | VLQ32 = 1 + number of LIDs |
| access sub-area | VLQ32 |
| LIDs | VLQ32 each |

Access areas and sub-areas [C]:

| Area | Value | Sub-area |
|---|---|---|
| Data block *n* | 0x8A0E0000 + *n* | 2550 (DB_ValueActual) |
| Inputs (I) | 80 (0x50) | 3736 (ControllerArea_ValueActual) |
| Outputs (Q) | 81 (0x51) | 3736 |
| Memory (M) | 82 (0x52) | 3736 |
| S7 timers | 84 (0x54) | 3736 [R] |
| S7 counters | 83 (0x53) | 3736 [R] |
| Object root (system limits) | 201 | 1037 / 1081 |

The LIDs are the "access sequence" obtained by browsing (section 13), for example `8A0E0005.A.B` means area
0x8A0E0005 and LIDs 0xA, 0xB.

### 11.3 Response

| Field | Encoding |
|---|---|
| return value | VLQ64 (0 if all items succeeded; non-zero when at least one item failed, see 12) |
| value list | repeated: item number (VLQ32, 1-based request position) + value; ended by `00` |
| error list | repeated: item number (VLQ32) + item error (VLQ64); ended by `00` |
| integrity ID | VLQ32 |
| end | `00 00 00 00` |

Each requested item appears in exactly one of the two lists. [C]

### 11.4 Worked example (invented tags)

Tags in data block 5 ("Line1"), plus one input and one bad address:

| # | Symbol | Access sequence | Symbol CRC |
|---|---|---|---|
| 1 | `Line1.Conveyor.Speed` (REAL) | `8A0E0005.A.B` | 0x6E44A73A |
| 2 | `Line1.Conveyor.Running` (BOOL) | `8A0E0005.A.9` | 0x2556A63B |
| 3 | `Line1.Count` (DINT) | `8A0E0005.C` | 0xDA026CFF |
| 4 | `Line1.Total` (ULINT) | `8A0E0005.D` | 0x646C6642 |
| 5 | `Line1.Recipe` (STRING[10]) | `8A0E0005.E` | 0x8C4EAA1D |
| 6 | `Line1.Label` (WSTRING[4]) | `8A0E0005.F` | 0xA8FA43BE |
| 7 | `Line1.Stamp` (DTL) | `8A0E0005.10` | 0xFCA84867 |
| 8 | `IArea.StartButton` (BOOL) | `50.C` | 0xB285B00A |
| 9 | (no such LID) | `8A0E0005.7FFF` | 0 |

Request:

```
02310000054c0000002870000a103400000000092f86f292ce3a88d0b880050393760a0b82aadacc3b88d0b880050393
760a098dd089d97f88d0b880050293760c86a3b1cc4288d0b880050293760d88e2bad41d88d0b880050293760e8ac7e9
873e88d0b880050293760f8fe5a1906788d0b88005029376108b9496e00a50029d180c0088d0b8800502937681ff7f00
0004e88969001200000000896a001300896b000400001e00000000
```

Reading the first item: `86 f2 92 ce 3a` CRC 0x6E44A73A, `88 d0 b8 80 05` area 0x8A0E0005, `03` three IDs,
`93 76` sub-area 2550, `0a` LID 0xA, `0b` LID 0xB. Item count `09`, field count `2f` = 47.

Response:

```
02320000054c00000028349089f0808082c2801301000e3fc0000002000101030008fd54040005cbad070510020c0a04
4d6978310000000000000610030600040002004f004b000000000700170200004310ff4ad6dfd5774c020c07ea0b1204
10222e05f5e100080001000009c0d3d18080a5c5ff01004600000000
```

| Bytes | Decoded |
|---|---|
| `90 89 f0 80 80 82 c2 80 13` | return value 0x2027800000A10013 (one item failed) |
| `01 00 0e 3fc00000` | item 1: Real 1.5 |
| `02 00 01 01` | item 2: Bool true |
| `03 00 08 fd54` | item 3: DInt -300 |
| `04 00 05 cbad07` | item 4: ULInt 1234567 |
| `05 10 02 0c 0a 04 4d697831 000000000000` | item 5: USInt array, 12 elements: max length 10, current length 4, "Mix1", padding |
| `06 10 03 06 0004 0002 004f 004b 0000 0000` | item 6: UInt array, 6 elements: max 4, current 2, "OK" as UTF-16 code units |
| `07 00 17 02000043 10ff4ad6dfd5774c 02 0c 07ea0b1204 10222e 05f5e100` | item 7: packed struct (DTL, see 11.5) |
| `08 00 01 00` | item 8: Bool false |
| `00` | end of value list |
| `09 c0d3d18080a5c5ff01` | error list: item 9, error 0x814E88000962FF01 (invalid address) |
| `00` | end of error list |
| `46` | integrity ID 70 |
| `00000000` | end |

### 11.5 Value encoding per PLC datatype

"Softdatatype" is the PLC-side type number from the type information (section 13.5). "Wire" is the datatype code
of the returned value.

| PLC type | Softdatatype | Wire | Interpretation | |
|---|---|---|---|---|
| BOOL | 1 | `01` Bool | 0/1 | [C] |
| BOOL in optimized block | 40 (BBOOL) | `01` Bool | 0/1 | [C] |
| BYTE | 2 | `0A` Byte | | [C] |
| CHAR | 3 | `02` USInt | one byte character | [R] |
| WORD | 4 | `0B` Word | | [C] |
| INT | 5 | `07` Int | | [C] |
| DWORD | 6 | `0C` DWord | | [C] |
| DINT | 7 | `08` DInt | | [C] |
| REAL | 8 | `0E` Real | | [C] |
| DATE | 9 | `03` UInt | days since 1990-01-01 | [R] |
| TIME_OF_DAY | 10 | `04` UDInt | ms since midnight | [R] |
| TIME | 11 | `08` DInt | milliseconds, signed | [C] |
| S5TIME | 12 | `0B` Word | BCD value in bits 0..11, time base in bits 12..13 | [R] |
| DATE_AND_TIME | 14 | `02` USInt array of 8 | BCD bytes: year (90..99 = 1990s, 00..89 = 2000s), month, day, hour, minute, second, milliseconds hundreds and tens; last byte: high nibble = milliseconds units, low nibble = weekday (1 = Sunday) | [C] |
| STRING[n] | 19 | `02` USInt array of n+2 | byte 0 = max length n, byte 1 = current length, then n bytes (only the first *current length* are valid; code page of the PLC, Windows-1252 in practice) | [C] |
| ANY / pointer types (REMOTE) | 96 | `02` USInt array of 10 | raw 10-byte ANY pointer | [C] |
| LREAL | 48 | `0F` LReal | | [C] |
| ULINT | 49 | `05` ULInt | | [C] |
| LINT | 50 | `09` LInt | | [C] |
| LWORD | 51 | `0D` LWord | | [R] |
| USINT | 52 | `02` USInt | | [C] |
| UINT | 53 | `03` UInt | | [C] |
| UDINT | 54 | `04` UDInt | | [C] |
| SINT | 55 | `06` SInt | | [C] |
| WCHAR | 61 | `03` UInt | UTF-16 code unit | [R] |
| WSTRING[n] | 62 | `03` UInt array of n+2 | element 0 = max length, element 1 = current length, then n UTF-16 code units | [C] |
| LTIME | 64 | `11` Timespan | nanoseconds | [R] |
| LTOD | 65 | `05` ULInt | ns since midnight | [R] |
| LDT | 66 | `10` Timestamp | ns since 1970-01-01 | [C] |
| DTL | 67 | `17` packed struct, ID 0x02000043, 12 bytes | year UInt BE, month, day, weekday (1 = Sunday), hour, minute, second (USInt each), nanosecond UDInt BE | [C] |
| HW_ANY, HW_IO and other hardware IDs | 144..156 | `0B` Word | | [C] |
| DB_ANY | 208 | `03` UInt | DB number | [C] |
| IEC_TIMER (TON/TOF) instance | 31 | `17` packed struct, ID 0x0200001F | byte count **13**: ST, PT, ET (TIME, 4 bytes BE each, offsets 0, 4, 8), then one byte with RU (bit 0), IN (bit 1), Q (bit 2) (bit numbers from attribute flags & 7 of the members, 13.5); no trailing pad bytes although the type's attribute 1502 is 16 | [C] |

DTL example from above: `07ea 0b 12 04 10 22 2e 05f5e100` = 2026-11-18, Wednesday, 16:34:46.100000000.

Packed-struct length rule [C]: the number of data bytes is always the **byte count** in the value. It equals the
end of the last member in the layout that was sent (section 11.8): trailing padding is not sent. It is **not**
type-info attribute 1502, which is the size of the classic layout and can be smaller or larger than the byte count
(IEC_TIMER: 13 bytes sent, 1502 = 16; a STRUCT of one INT and 14 BOOLs in an optimized DB: 16 bytes sent,
1502 = 4). A client must take the byte count from the value.

The time zone of DT, DTL and LDT values (PLC local time or UTC) is not stated on the wire and was not determined.

### 11.6 Arrays and structures

* **Element of an array**: append the zero-based element index as one more LID (independent of the declared lower
  bound): `ARRAY[1..50] OF UINT` at LID 0xF, element `[4]` is `.F.3`. [C]
* **Whole array of an elementary type**: address the array's own LID. The PLC returns one array value: `UInt`
  array of 50 elements for `ARRAY[..] OF UINT`, `DInt` array for DINT, and so on. [C]
  `ARRAY[0..255] OF BOOL` is returned as a **Byte array of 32 bytes** (8 elements per byte). Bit order: element
  *i* is bit (*i* mod 8) of byte (*i* div 8), bit 0 = least significant. Verified in one request: whole array first
  byte `0x10`, elements 0..7 read singly = only element 4 true. [C]
* **Element of an array of structs / UDTs / FB instances**: array LID, element index, the literal LID `1`, then the
  member LID: `8A0E0012.C.0.1.B` is member 0xB of element `[lower bound + 0]` of the struct array at LID 0xC. [C]
* **Multi-dimensional elementary arrays** (offset-info type 11): the whole array is read with the array's LID and
  comes back as one flat array of all elements (a 2-dimensional DINT array of 16 x 4 came back as a DInt array of
  64). An element is addressed with **one** extra LID holding the linear index 0 .. total - 1 into that flat order:
  linear indices 5, 6 and 63 returned the same values as positions 5, 6 and 63 of the whole read. Index = total
  (64) gave item error 0x814E8D000641FFC3. [C] Which declared dimension varies fastest in the flat order (last
  dimension fastest is expected) is not verified, because the declarations were not available. [R] An address with
  two index LIDs (`.B.1.1`) was not rejected: it returned a DInt array of **one** element; its meaning is unknown and
  a client must not use that form. [C] For multi-dimensional BOOL arrays in optimized blocks each run of the
  innermost dimension is padded to a multiple of 8 indices. [R] Multi-dimensional arrays of structs (offset-info
  type 14) were not seen.
* **Element or whole array of structs** [C]: the value has flags `10` (array) and datatype `17`, but no
  element count: one packed struct follows whose transport flags have bit 0x400 (0x402 optimized, 0x403 classic),
  then the element size and the total byte count, then the elements back to back. An element read
  (`.C.0.1`) returns one element in this form. A whole array of 5 structs of 90 bytes in a classic DB read as
  size 90, total 450; a whole array of 50 structs in an optimized DB was refused with item error
  0x800989000C18FFD1 (-47) while its elements read.
* **Whole struct / UDT instance / system type** (DTL, IEC timers, hardware telegram structs): address the struct's
  LID; the PLC returns one **packed struct** (section 8.5) whose struct ID is the type-info RID of the struct type and
  whose interface timestamp equals that type's attribute 529. The bytes are a memory image of the struct; section
  11.8 says how to find each member in it. [C] A struct read from an I/Q area was returned with transport flags 3
  (classic layout); structs read from optimized DBs came with flags 2. [C]

### 11.7 Symbol CRC

The symbol CRC in an item address protects against reading a different variable after a program change. [C]

* `0` disables the check: reads with CRC 0 succeeded. [C]
* A wrong non-zero CRC gives the item error 0x8009890012C9FFEF. [C]
* Computation (verified against the CPU): CRC-32 with polynomial `0xF4ACFB13`, initial value 0, MSB-first
  (non-reflected) table, no final XOR. [C]
  * For each path segment below the block (for `Line1.Conveyor.Speed` the segments are `Conveyor` and `Speed`)
    compute the **member CRC** = CRC over the UTF-8 member name followed by one type-code byte. The type code is the
    member's **own softdatatype** (section 13.5), with these exceptions [C]:

    | Member softdatatype | Type code |
    |---|---|
    | BBOOL (40) | 1 |
    | hardware ID types (HW_ANY, HW_IO, ...: 144 and 149 seen; 144..156 expected) | 4 (WORD) |
    | DB_ANY (208) | 53 (UINT) |
    | OB / event types | 5 (INT) [R, none in the captures] |
    | AOM identifiers | 6 (DWORD) [R, none in the captures] |

    There is no special code for structured members: a plain STRUCT or UDT member has softdatatype 17 and uses 17,
    but a DTL member uses 67, an IEC_TIMER member 31, an FB instance 21, and the system types with softdatatypes
    99 and 100 use 99 and 100. [C] (Using 17 for all of these gives wrong CRCs.)
    One-dimensional array members use 16 followed by the element's type code (same table) and the 4-byte
    little-endian lower bound, for example a DB_ANY array: name, `10`, `35`, lower bound. [C]
  * **Preferred source**: the member CRC is the CRC field of that member's element in the vartype list
    (section 13.5). A client that browses should take it from there instead of recomputing it. The name-based
    formula above reproduced the vartype CRC for all 15,406 vartype elements that are not array elements, except
    the 13 multi-dimensional elementary arrays (offset-info type 11), which use the next rule. [C]
  * Multi-dimensional elementary arrays: their vartype CRC equals CRC over name, `10`, element type code, then
    three 4-byte little-endian integers: lower bound of dimension 1, upper bound of dimension 1, lower bound of
    dimension 2 (fits all 13 cases: 2 dimensions, all lower bounds 0; how further dimensions and non-zero bounds
    enter is unknown). The PLC **accepted** a whole-array read whose address CRC was built from the vartype CRC and
    **rejected** (item error -17) one built from the one-dimensional formula (name, `10`, type code, lower bound
    only). [C]
  * Address CRC for a one-segment path = CRC over the 4 bytes of the member CRC in little-endian order.
  * Address CRC for more segments = CRC over: member CRC 1 (4 bytes LE), then for each further segment the byte
    `89` followed by its member CRC (4 bytes LE).
  * Examples (invented names): `Speed` (REAL, 8) member CRC 0x8C95C2CE, one-segment address CRC 0x888EC040;
    path `Conveyor` (struct, 17) member CRC 0x8F17B175 + `Speed` gives 0x6E44A73A.
  * Members of a whole-read system struct are addressable with a full CRC: a DTL member (`<db>.<struct>.<dtl>.MONTH`,
    three segments, MONTH member CRC from the DTL type's vartype list) was read as USInt with a non-zero CRC
    without error. [C]
  * Elements of arrays were read with CRC 0 by the observed client; a CRC for an array element (index LID) is not
    defined on this page. [C]
  * A **whole** member of softdatatype 17 (STRUCT, UDT, system struct, and arrays of them) is refused with item
    error -17 when its address carries the vartype CRC, although the same member CRC works as a prefix of a
    deeper path; with CRC 0 it reads. Whole DTL (67), IEC_TIMER (31) and softdatatype-100 members accept their
    CRC. [C]
* Recommendation: send the CRC for scalar paths (cheap program-change protection) and 0 where it is not known.

### 11.8 Packed-struct data layout

A packed struct (8.5) carries the struct in one of two layouts, chosen by the PLC and reported in its transport
flags [C]:

* bit 0x01 clear (flags 2): **optimized layout**, used for structs in optimized DBs and FB instances;
* bit 0x01 set (flags 3): **classic layout**, used for the I/Q/M areas and (expected) standard-access DBs.

Which layout a container uses can be seen before reading: all members of a classic-layout DB or area type have
bit-offset info bit 0x08 set (13.5); the I, Q and M area types and the classic DB-form variants have it, optimized
ones do not. [C] Attribute flag 0x0080 must **not** be used for this: it is set on every element of every type,
classic ones included. [C]

Member positions come from the member elements of the **struct's own type** (the type whose RID is the packed
struct ID). Those are struct-element forms (offset-info types 1 to 7, 13.5), whose fields give both layouts:

| Offset-info type | Optimized offset | Classic offset | |
|---|---|---|---|
| 1 (elementary) | second u16 | first u16 | [C] |
| 2 (string) | first u32 | second u32 | [C] |
| 5, 6 (struct, array of struct) | first u32 | second u32 | [C] |
| 3, 4 (arrays) | first u32 | second u32 | [R, not seen in struct forms] |

This field order was cross-checked on all 1,433 members of the struct types that also exist as a classic DB-form
variant (13.5): the classic offset above equals the variant's offset every time. [C]

BOOL members [C for the type information; only optimized packed data with BOOLs was read]:

* softdatatype 40 (BBOOL) in the optimized layout: **one whole byte** (0 or 1) at the optimized offset. Example:
  a STRUCT of one INT and 14 BBOOLs was sent as 16 bytes: the INT at 0..1, the BOOLs at bytes 2 to 15, each 0 or 1.
* softdatatype 1 (BOOL), and every BOOL in the classic layout: **one bit** of the byte at the offset; the bit number
  is attribute flags & 7 of the member. Example: the IEC_TIMER bits RU / IN / Q share the byte at offset 12 with
  bit numbers 0 / 1 / 2. (The IEC_TIMER's optimized and classic layouts are identical; a softdatatype-1 BOOL in an
  optimized layout that differs from the classic one was not seen.)
* In struct-element forms the bit-offset info is 0 or 1; the value 1 (seen on IEC_TIMER ST, ET, RU, Q) is **not**
  a bit number and its meaning is unknown.

The bit-offset info fields (`70` classic bit, `07` optimized bit) are used only by DB-form elements (offset-info
types 8 to 15), which describe top-level DB members, not packed-struct contents. [C] Example: four BBOOLs at
optimized offsets 752, 753, 754, 755 (bit-offset info `07` = 0, own byte each) share classic byte 180 with
bit-offset info `70` = 0, 1, 2, 3.

---

## 12. Return values and errors

The return value (responses) and item errors (GetMultiVariables error list) are 64-bit values sent as VLQ64.
Field layout per the public Wireshark notes [W]:

| Bits (mask) | Field |
|---|---|
| `0x000000000000FFFF` | error code, signed 16 bit |
| `0x00000000FFFF0000` | OMS line |
| `0x000000FF00000000` | error source |
| `0x00007F0000000000` | generic error code |
| `0x0000800000000000` | server error flag |
| `0x3FFF000000000000` | debug info |
| `0x4000000000000000` | error extension (an error object follows in some responses) |

Rules for a client [C]:

* Return value `0` = success.
* CreateObject and DeleteObject returned non-zero values on success (0x60228000012D0011 and
  0x202380000087002D: error code field positive). Treat a non-negative error code (low 16 bits as signed) as
  success / information.
* GetMultiVariables returns a non-zero return value when at least one item failed (0x2027800000A10013 and
  0x2027800001780013 observed: only the OMS-line field differed, the low 16 bits were 0x0013 both times); the
  per-item result is in the error list. Do not compare the whole 64-bit value.
* SetMultiVariables (tag write) returned 0 with an empty error list for a successful single-item write. [C] A
  failed item is expected to give a non-zero return value and an error-list entry as for reads. [R]
* Item errors observed (the full 64-bit values differ in the upper fields; classify by the low 16 bits):

  | Item error | Low 16 bits | Cause |
  |---|---|---|
  | 0x814E88000962FF01 | -255 | LID does not exist in the block |
  | 0x814E8D000641FFC3 | -61 | array index LID out of range |
  | 0x8009890012C9FFEF | -17 | symbol CRC mismatch |

* Reads of tags without "Accessible from HMI/OPC UA/Web API" succeeded on this CPU (no access error). [C]
* In InitSsl and DeleteObject responses, if bit 0x4000000000000000 is set, an error object (`A1 ... A2`) follows
  the return value / object ID. [R] (The CreateObject return value above has this bit set and no error object
  followed, so the bit must not be used to parse CreateObject responses.) [C]
* Never captured: an Error PDU (function `04 B1` or `05 A9`), a response with a negative return value, an error
  object after bit 0x4000000000000000, and the PLC's reaction to a wrong sequence number or integrity ID. A client
  should treat any of these as fatal for the connection (close it) until captures show otherwise. [R]

---

## 13. Browse

Browsing builds the full symbol table (names, types, access sequences, HMI flags) from three kinds of requests.
All are read-only. [C]

### 13.1 Explore request

| Field | Encoding |
|---|---|
| explore ID | 4 bytes BE: RID of the object to explore |
| explore request ID | VLQ32, 0 |
| children | 1 byte: 1 = include children recursively, 0 = not |
| (unknown) | 1 byte, always `01` (meaning unknown; send as shown) |
| parents | 1 byte: 1 = include parent objects, 0 = not |
| filter part | either the single byte `00` (no filter), or `01`, one filter value (section 13.2), then `00` |
| attribute count | VLQ32 |
| attribute IDs | VLQ32 each; with count 0 all attributes are returned |
| integrity ID | VLQ32 |
| end | `00 00 00 00 00` (5 bytes; the 5th zero byte is unexplained, send as shown) |

All 57 captured Explore requests used explore request ID 0 and the `01` unknown byte; 56 had no filter, one had
the DB filter of 13.2. Whether the filter part can hold more than one value is unknown. [C]

Response body: a 4-byte BE field, integrity ID (VLQ32), then the objects (`A1 ... A2`), then `00 00 00 00`. [C]

* The 4-byte field is the **RID of the parent of the explored object**, whatever was requested: 0x00000001 when
  exploring RID 3 (with or without filter) or RID 114, 0x00000003 when exploring a DB or the structure object
  0x8A11FFFF, 0x000000C9 when exploring RID 537, 0x00000219 when exploring a single type-info object. It held for
  all 57 captured Explore responses. [C]
* What the objects are [C]:

  | Request | Top-level object(s) in the response |
  |---|---|
  | parents 0, no filter | the explored object itself, with its children nested inside when children = 1 |
  | parents 1 | RID 1 (AS root, class 2478), containing each ancestor in turn down to the explored object (RID 1 > RID 114; RID 1 > RID 3 > 0x8A11FFFF) |
  | parents 0, with filter | only the matching descendants, each as its own top-level object, without the explored object around them |

Large Explore responses are a single PDU of many frames (30 KB for the block list, 466 KB for the type-info
container of a mid-size program with 18,600 symbols). [C] No paging or continuation of a large Explore response
was seen; whether the PLC splits or refuses responses beyond about 466 KB is unknown.

### 13.2 Step 1: block list

Explore RID 3 (PLC program), children 1, parents 0, attributes 233 (name), 2521 (block number),
4288 (comment):

```
0231000004bb0000000b70000a10340000000300010100000381699359a140080000000000
```

The response's top-level object is RID 3 itself (class 2520, PLC program, flags 0x30); it contains one object per
block, area and folder (437 direct children on the tested program). There is no RID 1 wrapper, because parents
was 0. [C]

| Class ID | Kind | RID pattern |
|---|---|---|
| 2574 | data block | 0x8A0E0000 + DB number |
| 4600 | technology-object data block (for example a motion axis) | 0x8A0E0000 + DB number |
| 3932 | PLC data type (UDT) | 0x89FD0000 + n |
| 2578 / 2579 | FB / FC | |
| 2610 and 2637..2658, 8440 | OBs (various OB classes) | |
| 2595 / 2621 / 2602 / 2625 / 2627 | I / Q / M area / S7 counters / S7 timers | 80 / 81 / 82 / 83 / 84 |
| 2483 | software events folder | |

DB objects carry class flags 0x20 or 0x40000020; on the tested program 0x40000000 was set on 41 of 92 DBs, and
all 41 belonged to the safety (F) program. Its exact meaning is not known. [C]

The direct children also include classes that the table does not list: 4273 (three times; 4273 is also the class
of the PLC structure object, section 15), 4637, 4639, 7825, 7842, 8040, 8135 and 8157. [C] A client builds the
symbol table only from class 2574 (data blocks, by RID 0x8A0E0000 + n) and the five areas, and **ignores every
other class**, including 4600 (technology-object DBs) and any class it does not know. This reproduces the observed
client's 18,633-symbol table, and it is what the studied implementation does. [C, R] Whether technology-object DBs
can be read like other DBs was not tested.

Attribute 4288 (block comment) is a sparse WString array keyed by a number that is **not** the CPU text language
(the CPU's only text language was 1033) [C]:

* 303 of 423 objects had an empty sparse array (`40 15 00`);
* 119 had key 1034 only (116 of them with a non-empty text);
* 1 had keys 1034 and 1032, both with empty text, for example `a3 a140 40 15 880a 00 8808 00 00`.

The meaning of the key is unknown. (Unverified idea: key = LCID + 1, i.e. 1034 = en-US, 1032 = de-DE.) A client
should show any non-empty entry and keep the key as an opaque number.

**DB-only variant with a filter** [C]: the same Explore of RID 3, children 1, parents 0, attribute 233 only, with
a filter value, returns only data blocks:

```
0231000004bb0000000e70000a10340000000300010100010017000004de895f0008088961000400896210042000000000
000000000000000000000000000000000000000000000000000000008963001200000a0e00000181690b0000000000
```

| Bytes | Meaning |
|---|---|
| `00000003 00 01 01 00` | explore ID RID 3, request ID 0, children 1, unknown `01`, parents 0 |
| `01` | one filter value follows |
| `00 17 000004de` | value: Struct 1246 (Filter) |
| `89 5f 00 08 08` | element 1247 (filter operation) = DInt 8 ("instance of" a class) |
| `89 61 00 04 00` | element 1249 (address count) = UDInt 0 |
| `89 62 10 04 20` + 32 x `00` | element 1250 (address) = UDInt array of 32 zeros |
| `89 63 00 12 00000a0e` | element 1251 (filter value) = RID 0x00000A0E = class 2574 (data block) |
| `00` | end of struct |
| `00` | end of filter part |
| `01 81 69` | 1 attribute: 233 (name) |
| `0b` | integrity ID |
| `00 00 00 00 00` | end |

The response holds every data block as its own top-level object, without the RID 3 object around it: 96 objects
on the tested program, 92 of class 2574 and 4 of class 4600 (technology-object DBs, which therefore count as
"instance of" class 2574), each with its name only. The 4-byte response field is 0x00000001 (parent of RID 3).
Filter operations other than 8 and non-zero address lists were not tried. As with the unfiltered list, a client
keeps only the class-2574 objects; the observed client did not read LID 1 of the four class-4600 objects. [C]

### 13.3 Step 2: type RID of every DB

Read LID 1 of every DB (area 0x8A0E0000 + n, sub-area 2550, LIDs `[1]`, CRC 0) in GetMultiVariables requests of up
to 100 items. Each value is a RID: the RID of the DB's type-info object. [C]

```
request  02310000054c0000000c70000a10340000000001050088d0b8800502937601000004e88969001200000000896a001300
         896b000400000900000000
response 02320000054c0000000c34000100129200000500001500000000     -> RID 0x92000005
```

Type RIDs returned by LID 1 (the DB's type) [C]: 0x9200nnnn (global DB, nnnn = DB number), 0x9300xxxx (FB
instance DB: the FB's type), 0x0205xxxx (instance DB of a system FB), 0x91FDxxxx (a DB whose type is a PLC data
type, see the DB forms in 13.5). Struct types nested in a global DB are 0x92ssnnnn (ss = 01, 02, ...; nnnn = DB
number); they are reached through relation IDs, not through LID 1. DBs that return an item error (for example DBs
only in load memory) are skipped. [C] The I, Q, M, timer and counter areas have fixed type RIDs 0x90010000,
0x90020000, 0x90030000, 0x90050000, 0x90060000. [C for I/Q/M]

### 13.4 Step 3: all type information

Explore RID 537 (OMS type-info container), children 1, parents 0, no attributes:

```
0231000004bb0000000d70000a1034000002190001010000000a0000000000
```

The response is object 537 (class 534) containing one type-info object (class 511) per type: DB types, struct and
UDT types, FB types, system types, I/Q/M areas. 1,011 type objects on the tested program. [C] A single type can also
be explored by its RID with children 1 and no attributes. [C]

Type-info object attributes [C]:

| Attribute | Type | Meaning |
|---|---|---|
| 233 | WString | name (empty for most types; `IArea` etc. for areas) |
| 392 | DWord | 0x80000001 areas, 0x80000002 user types, 0x80000003 system types |
| 404 | UDInt | |
| 529 | ULInt | **interface timestamp**: for system types nanoseconds since 1970 (for example 2008-10-23 for DTL); for user types a 64-bit stamp. Must match the timestamp in packed structs. |
| 410 | ULInt | for user types a time in ns since 1970 (looks like the last interface change), 0 for system types |
| 1502 | UDInt | size of the type in the **classic** (non-optimized) layout. Not the size of a packed-struct value (11.5) and not the optimized size: a STRUCT of one INT and 14 BBOOLs has 1502 = 4 but is 16 bytes in the optimized layout. For arrays of structs use the struct sizes in offset-info types 6 / 13 instead. [C] |
| 1503 | DInt | form of the type-info object: 0 = struct form, 1 = DB form, 2 = FB / instance type (13.5) [C] |
| 611 | Struct 1542 {1543, 1544, 1545 UDInt} | layout sizes. Struct forms: 1543 = classic size (= 1502), 1544 and 1545 = optimized size (16 and 16 for the STRUCT above). DB forms: one value per section, for example 0 / 16 / 8 for a retain variant; read as classic / retain / volatile section sizes. [C for the values, the section reading is inferred] |
| 412 / 413 / 414 | Word / UDInt / UDInt | |

Then one `AB` vartype list and one `AC` varname list (absent when the type has no members). Element *i* of the
vartype list is named by entry *i* of the varname list.

### 13.5 Vartype list (`AB`) and varname list (`AC`) [C]

Vartype list:

| Field | Encoding |
|---|---|
| block length | 2 bytes BE: bytes in this block |
| first ID | 4 bytes LE (only at the start of the first block; for example 0x80000004) |
| elements | until the block length is used up |
| next block length | 2 bytes BE; `00 00` ends the list, otherwise another block of elements follows |

Element:

| Field | Encoding |
|---|---|
| LID | 4 bytes LE: the access ID of the member |
| member CRC | 4 bytes LE (section 11.7) |
| softdatatype | 1 byte |
| attribute flags | 2 bytes **BE** |
| bit-offset info | 1 byte |
| offset info | variable, selected by the attribute flags |

Attribute flags:

| Mask | Meaning |
|---|---|
| `F000` | offset-info type (>> 12) |
| `0800` | visible in HMI engineering |
| `0400` | read-only for HMI |
| `0200` | accessible from HMI / OPC UA / web server |
| `0100` | (unknown) |
| `0080` | (unknown) set on every element seen, in classic and optimized types alike; **do not** use it to choose a layout [C] |
| `0070` | section (>> 4) |
| `0008` | (unknown) |
| `0007` | bit number of a BOOL in struct-form elements (offset-info type 1), see 11.8 [C] |

Bit-offset info (DB-form elements, offset-info types 8 to 15): `80` retain, `70` classic bit offset (>> 4), `08`
classic layout, `07` optimized bit offset. In struct-form elements it is only ever 0 or 1, and 1 is not a bit
number (11.8). [C]

**Type forms and RID variants** [C]. Attribute 1503 tells which form a type-info object has:

| 1503 | Form | Offset-info types of its members | Used as |
|---|---|---|---|
| 0 | struct form | 1 to 7 (classic u16 first in type 1) | target of relation IDs; packed-struct IDs (8.5) |
| 1 | DB form | 8 to 14 (optimized u16 first in type 8) | type of a global DB, or of a DB declared with a PLC data type or system type |
| 2 | FB / instance type | 8 to 15 | type of FB instance DBs and target of FB-instance relation IDs (type 15) |

Many PLC data types and system types exist four times in the type information: the struct form and three DB-form
variants, one per DB layout. All members of a variant carry the same bit-offset info: 0x00 (optimized), 0x80
(optimized, retain) or 0x08 (classic). The variant RIDs seen:

| Struct form | Optimized | Retain | Classic |
|---|---|---|---|
| 0x9100nnnn (PLC data types) | 0x91FDnnnn | 0x91FEnnnn | 0x91FFnnnn |
| 0x0208nnnn (system structs) | 0x0248nnnn | 0x0288nnnn | 0x02C8nnnn |
| 0x0200nnnn (system types; IEC_TIMER is 0x0200001F) | + 0x4000 (0x0200401F) | + 0x8000 (0x0200801F) | + 0xC000 (0x0200C01F) |

In the optimized variant every optimized offset is the struct form's optimized offset + 8; in the classic variant
the offsets equal the struct form's classic offsets. Relation IDs in offset info always point at the struct form
(or, for type 15, at an FB type), never at a variant; a DB's LID-1 value can be a variant (a 0x91FDnnnn value was seen).
A client that only browses DBs, areas and relation IDs never needs the variant numbering.

Offset-info types and their layouts (all fields little endian) [C for 1, 2, 5, 6, 8, 9, 10, 11, 12, 13, 15 (all seen in the type information); R for 0, 3, 4, 7, 14 (never seen)]:

| Type | Meaning | Size | Layout |
|---|---|---|---|
| 8 / 1 | elementary | 4 | type 8: optimized offset u16, non-optimized offset u16; type 1 (struct element): non-optimized u16, optimized u16 |
| 9 / 2 | string | 12 | u16, u16 (max length and max length + 2, order differs by firmware: take the smaller as max length), optimized u32, non-optimized u32 |
| 10 / 3 | 1-dim array | 20 | u16, u16, optimized u32, non-optimized u32, lower bound i32, element count u32 |
| 11 / 4 | n-dim array | 68 | as type 10, then 6 lower bounds i32, 6 element counts u32 (unused dimensions 0) |
| 12 / 5 | struct | 32 | u16, u16, optimized u32, non-optimized u32, **relation ID u32** (type RID of the member's type), 4 more u32 |
| 13 / 6 | 1-dim array of struct | 48 | u16, u16, opt u32, non-opt u32, lower bound i32, count u32, non-opt struct size u32, opt struct size u32, relation ID u32, 4 u32 |
| 14 / 7 | n-dim array of struct | 96 | as 11, then the 28 bytes of struct info as in 13 |
| 15 | FB / SFB instance | 40 | u16, u16, opt u32, non-opt u32, relation ID u32, 4 u32, retain offset u32, volatile offset u32 |
| 0 | array of FB instances | 104 | as 15, then element count u32, classic / retain / volatile section sizes u32, 6 lower bounds, 6 counts |

Varname list: same block structure (2-byte BE block length, `00 00` terminator), each entry 1-byte length, UTF-8
name, `00`.

Example, the DTL system type (type RID 0x02000043) as returned by the CPU:

```
a102000043837f2000a38169001500a38308000c80000003a38314000400a38411000588bfe9adb6ffaaf74ca38b5e00
040ca38b5f000800a384630017000006068c0700040c8c0800040c8c0900040c00a3831a000500a3831c000b0001a383
1d000400a3831e000404ab0084040000800900000093973bd7351a8000000000000a000000147f4ed7341a8000020002
000b0000006de7eef6341a8000030003000c0000004101e2c2341a8000040004000d00000084d6a870341a8000050005
000e0000006086d75e341a8000060006000f0000006ea81211341a8000070007001000000073001b76361a8000080008
000000ac003d045945415200054d4f4e5448000344415900075745454b4441590004484f555200064d494e5554450006
5345434f4e44000a4e414e4f5345434f4e44000000a2
```

* `a1 02000043 837f 20 00`: object RID 0x02000043, class 511, flags 0x20.
* Attributes: 233 = "", 392 = 0x80000003, 404 = 0, 529 = 1224779910406829900, 1502 = 12, 1503 = 0, 611,
  410 = 0, 412 = 1, 413 = 0, 414 = 4.
* `ab 0084`: vartype block of 132 bytes; first ID `04000080` (LE 0x80000004); 8 elements of 16 bytes, the first
  `09000000 93973bd7 35 1a80 00 00000000` = LID 9, member CRC 0xD73B9793, softdatatype 53 (UINT), flags 0x1A80
  (offset-info type 1, HMI visible, HMI accessible, flag 0x0080), offsets 0/0; the last one LID 0x10, softdatatype
  54 (UDINT), offsets 8/8. `00 00` ends the list.
* `ac 003d`: names YEAR, MONTH, DAY, WEEKDAY, HOUR, MINUTE, SECOND, NANOSECOND; `00 00` ends the list.
* `a2`: end of object.

### 13.6 Building the symbol table

* Start with each DB of class 2574 (name from step 1, area 0x8A0E0000 + n, type RID from step 2) and with the areas
  I, Q, M (names `IArea`, `QArea`, `MArea` as used by the observed client; tags in these areas are the PLC
  tag-table tags). Skip class 4600 and all other classes (13.2).
* For each member of the type: symbol = parent symbol + `.` + name; access sequence = parent sequence + `.` +
  LID (hex in the human-readable form).
* Offset-info types 12 / 5 / 15 (struct, UDT, system type, FB instance): recurse into the type-info object whose RID
  equals the relation ID (a struct form or an FB type, 13.5).
* Arrays: elementary arrays can be offered as one aggregate tag (read as a whole, 11.6) or expanded; elements use
  LID = zero-based index. Arrays of structs / FB instances are expanded: LID = index, then `1`, then the member LIDs.
* System structs such as DTL can be offered both ways: as one tag read as a whole (packed struct, 11.6) and as
  member tags. The observed client's symbol table listed DTL members (YEAR .. NANOSECOND) with access sequence
  `<DTL sequence>.<member LID>` (member LIDs 9 .. 0x10 from the DTL type, 13.5), and reading one member (MONTH,
  with its full address CRC) returned USInt without error. [C]
* HMI flags: a member is HMI-visible / HMI-accessible only if it and every containing member have the flag.
* The tested program yielded 18,633 symbols from 92 DBs and the I/Q/M areas. [C]

### 13.7 CPU information [C]

All via GetVarSubStreamed (section 13.8):

| Object RID | Attribute | Type | Content |
|---|---|---|---|
| 1 (AS root) | 2459 | USInt[8] | two 4-part versions, for example 19.0.0.0 and 19.0.0.0 (engineering version) |
| 50 (CPU common) | 233 | WString | PLC (station) name |
| 49 (CPU proxy) | 3753 | Blob, 60 bytes | identification, see below |
| 0x894A0000 (release management root) | 8342 | WString address-array of 3 | `V<tia version>`, `<tia version>`, **project name** |
| 52 (CPU exec unit) | 2237 | Struct | contains 3486 operating state [R] |

Identification blob (RID 49 / attribute 3753):

| Offset | Size | Content |
|---|---|---|
| 0 | 8 | header (`00 20 00 38 01 00 00 2a` observed) |
| 8 | 19 | order number (MLFB), ASCII, for example `6ES7 5XX-XXXXX-XAB0` |
| 27 | 1 | space |
| 28 | 16 | serial number, ASCII |
| 44 | 1 | `00` |
| 45 | 1 | hardware version (4 observed) |
| 46 | 1 | `V` |
| 47 | 3 | firmware major, minor, patch (3, 1, 3) |
| 50 | 10 | further bytes (rack / slot and others, not decoded) |

CPU text languages: Explore RID 114 (text container), children 0, parents 1, attribute 2717: the response contains
RID 1 > RID 114 (class 4672) with attribute 2717 = UInt address-array of Windows LCIDs (1033 = en-US observed). [C]

```
request  0231000004bb0000000a70000a103400000072000001010001951d070000000000
```

### 13.8 GetVarSubStreamed

Request body [C]:

| Field | Encoding |
|---|---|
| object ID | 4 bytes BE (RID of the object, or the session ID) |
| address | `20 04 01` (address-array of UDInt, 1 element) then the attribute ID (VLQ32) |
| object qualifier | section 9.1 |
| (unknown) | `00 01` (meaning unknown; send as shown) |
| integrity ID | VLQ32 |
| end | `00 00 00 00` (protocol version 3 adds one more `00` [R]) |

Response body: one byte `00` (meaning unknown), the value, integrity ID (VLQ32), `00 00 00 00`. [C]

Example: PLC name `PLC_Line1` would be returned as `00 00 15 09 504c435f4c696e6531 <integrity> 00000000`.

---

## 14. Symbol comments

### 14.1 Request

Explore the block RID (for example 0x8A0E0005), children 1, parents 0, attributes 233 (name), 2546
(DataInterface_LineComments), 2544 (DataInterface_InterfaceDescription): [C]

```
0231000004bb0000000b70000a10348a0e0005000101000003816993729370080000000000
```

### 14.2 Response [C]

Object RID 0x8A0E0005, class 2574, with:

* 233: WString block name.
* 2544: Blob, the compressed **interface description** XML.
* 2546: sparse Blob array; key 1 holds the compressed **line comments** XML. A block **without** member comments
  still returns the attribute: key 1 with a 16-byte blob `98000002 787d 3c55436a 0300 00000001` (prefix, zlib
  header, DICTID, a deflate stream that is one empty final block `03 00`, Adler-32 of empty data `00000001`). It
  inflates to **zero bytes**. Because an empty deflate stream does not reference the dictionary, a client can
  detect "no comments" without the dictionary: raw-inflate the bytes after the DICTID and get an empty result, or
  compare with the 16 bytes above. Seen for 3 of 3 blocks without comments. [C]

Response size about 1 to 3 KB per DB in the test.

### 14.3 Blob compression [C]

Each blob is: a 4-byte prefix (`98 00 00 02` observed for both attributes), then a zlib stream (RFC 1950) whose
header has the FDICT flag set (`78 7D`), followed by a 4-byte big-endian **DICTID** (Adler-32 of a preset
dictionary), then raw deflate data.

| Attribute | Prefix | DICTID observed |
|---|---|---|
| 2544 interface description | `98 00 00 02` | `66 05 2B 13` |
| 2546 line comments | `98 00 00 02` | `3C 55 43 6A` |
| 4275 PLC structure (section 15) | none | no preset dictionary (`78 DA`) |

The streams cannot be inflated without the matching preset dictionary (except an empty stream, see 14.2). The
dictionaries are fixed byte strings of XML fragments defined by the PLC firmware family; **this page does not
contain them** (see open questions). Other DICTIDs exist for other block attributes and older firmware.

Consequence for implementers: **symbol comments cannot be implemented from this page alone.** Both the comment
texts (2546) and the interface description (2544) that maps a comment's `Path` to LIDs are dictionary streams.
Without the dictionaries a client can only report "this block has no member comments" (the 16-byte empty blob of
14.2) and must treat every other block as "comments not available". Sections 14.4 and 14.5 describe the inflated
XML for when the dictionaries become available by a clean route.

Stream termination [C]:

* The 2544 / 2546 streams (12 checked) are complete zlib streams: final block, then the Adler-32 trailer, no bytes
  after it.
* The 4275 stream (122,531 bytes, `78 DA`) is **not terminated**: the blob ends inside the deflate data, with no
  final block and no Adler-32. A one-shot "decompress whole buffer" call fails with an incomplete-stream error,
  while a streaming inflate of all the bytes returns the complete XML document (762,294 bytes ending with
  `</PlcContentInfo>`). A client must use a streaming inflate, take all output produced, and accept a missing end
  of stream (it cannot verify the Adler-32 then).

### 14.4 Line-comment XML (after inflating) [C]

```xml
<InterfaceLineComments><Part Kind="Comments">
  <Comment Path="51:52"><DictEntry Language="en-US">Conveyor running feedback</DictEntry></Comment>
  <Comment Path="53"><DictEntry Language="en-US">Total parts produced</DictEntry></Comment>
  ...
</Part></InterfaceLineComments>
```

* `Path` is a colon-separated list of **member IDs** from the interface description, from the block root down
  (not LIDs).
* One `DictEntry` per language; `Language` is a culture name (`en-US`), corresponding to LCID 1033 in the CPU's text
  language list.

### 14.5 Interface description XML (after inflating) [C]

```xml
<BlockInterface Version="2.0"> ...
  <Part Kind="DBSource" ... BlockRID="0x92000005" ...>
    <Payload><Root ...>
      <Member ID="51" Name="Conveyor" RID="0x92010000" SubPartIndex="0" StdO="0" LID="10" />
      <Member ID="53" Name="Total" RID="0x02000031" StdO="64" LID="13" Remanence="Retain" />
    </Root></Payload>
    <SubParts>
      <Part Kind="Structure" ...><Payload><Member ParentId="51">
        <Member ID="51" Name="Speed" RID="0x02000008" StdO="0" LID="11" />
        <Member ID="52" Name="Running" RID="0x02000001" StdO="32" LID="9" />
      </Member></Payload></Part>
    </SubParts>
  </Part>
</BlockInterface>
```

Mapping a comment to a symbol: walk `Path` through the `Member ID` values (root members, then the sub-part whose
`ParentId` matches) to get member names and `LID`s; the resulting LID chain matches the access sequence from the
browse. Member IDs are unique only within one level. [C]

---

## 15. Program-change indicators

No dedicated "program changed" counter was found. Candidates (all read-only, none verified across a real
program change because the bench may not be modified):

* Type-info attribute 529 (interface timestamp) and 410 (looks like last interface change time) per type
  (section 13.4). Re-exploring RID 537 and comparing is expensive (466 KB); exploring single type RIDs is cheaper.
* The symbol CRC in read requests: after a member is renamed or retyped, reads that send the CRC fail with
  item error low word -17 instead of returning a different variable. [C for the error, R for the change case]
* Packed-struct reads fail when the interface timestamp no longer matches. [R]
* The PLC structure XML: Explore RID 0x8A11FFFF, children 1, parents 1, attribute 4275 (ConstantsGlobal_Symbolics).
  The response (RID 1 > RID 3 > 0x8A11FFFF, class 4273) carries a Blob, plain zlib without dictionary and without stream end (14.3), 122 KB
  compressed for the test program, which inflates to a `<PlcContentInfo>` XML with `LastModified` time stamps per
  tag table and block, and per-entity fingerprints. A hash of this document changes when anything is downloaded. [C
  for content, R for change behaviour]

---

## 16. Request size limits [C]

* GetMultiVariables: at most 100 items per request (system limit LID 1000); SetMultiVariables likewise 100 (LID 1001).
* The studied implementation additionally keeps every request within one COTP frame (1024 bytes minus TPKT, COTP,
  TLS record header, AES-GCM overhead and the 72-header and trailer, about 987 bytes of PDU data) and splits by
  that size as well as by the item limit. [R] This is stricter than needed: a 1,581-byte request was accepted.
* Frame length field is 16 bits, so one frame carries at most 65,535 data bytes; PDUs may be longer by using several
  frames.
* COTP TPDU 1024 bytes.
* Largest request sent: 100 items with 2 to 6 LIDs each, frame data part 1,581 bytes (1,582 with the version byte),
  one frame, accepted. Nothing larger and nothing above 100 items was tried, so the real maximum request size and
  the reaction to more than 100 items are unknown.
* Max PLC frame data part 979 bytes; Explore responses up to 466 KB.

---

## 17. Writing tags: SetMultiVariables

Tags are written with SetMultiVariables (`05 42`), the function that also sets up the session (10.4). A tag write
uses object ID 0 and the same item addresses as a read (11.2). Captured: one session that wrote a single BOOL tag
twice (true, then false), reading it back after each write; both writes succeeded and the read-backs returned the
written values. [C] Everything this capture does not show (other types, several items, item errors) is marked [R].

### 17.1 Request

| Field | Encoding | |
|---|---|---|
| object ID | 4 bytes BE: **0** for tag writes (the session setup writes into the session object instead) | [C] |
| item count | VLQ32 | [C] |
| field count | VLQ32 = sum over items of (4 + number of LIDs), as in 11.1 | [C] |
| item addresses | one per item, exactly as in 11.2 (symbol CRC, area, ID count, sub-area, LIDs) | [C] |
| values | one per item: item number (VLQ32, 1-based position in the address list) + value (section 8) | [C] |
| fill byte | `00` | [C] |
| object qualifier | section 9.1 | [C] |
| integrity ID | VLQ32, from the "set" counter (6.6) | [C] |
| end | `00 00 00 00` | [C] |

* All addresses come first, then all values, the values numbered 1, 2, 3, ... in address order. [C for one item,
  R for several]
* At most "max tags per write request" items per request (LID 1001, 100 on the tested CPU, 10.5); the client splits
  larger writes. [C for the limit value, R for its enforcement]
* The symbol CRC is checked as for reads (11.7); 0 disables the check. The captured writes sent the full address
  CRC. [C] Elements of arrays are addressed as in 11.6. [R for writes]
* Writes were sequential (one request in flight) and interleaved with reads in the same session. [C]

### 17.2 Response

| Field | Encoding | |
|---|---|---|
| return value | VLQ64; 0 = every item written | [C] |
| error list | repeated: item number (VLQ32) + item error (VLQ64); ended by `00`. Items that were written do not appear. | [C for the empty list, R for entries] |
| integrity ID | VLQ32 = request sequence number + request integrity ID | [C] |
| end | `00 00 00 00` | [C] |

There is no value list (unlike the GetMultiVariables response). When at least one item fails the return value is
non-zero and the failed items are listed with their item errors, which are classified by their low 16 bits as in
section 12. [R] Which item errors a write can produce (read-only tag, value out of range, wrong datatype, write
protection by the CPU's protection level) is not known.

### 17.3 Value to send per PLC type

Send the value in the **same wire form the PLC returns when the same address is read** (table in 11.5), with the
same flags and datatype code. [C for BOOL, R for every other type: this is how the studied implementation builds
its writes.]

| PLC type | Value to send | |
|---|---|---|
| BOOL / BBOOL | `00 01` + `00` or `01` | [C] |
| elementary types (BYTE ... LREAL, TIME, LDT, ...) | the scalar datatype of 11.5, for example `00 0E` + 4-byte REAL for REAL | [R] |
| STRING[n] | USInt array of **n + 2** bytes: n, the actual length, the characters, zero padding up to n; always the full declared size | [R] |
| WSTRING[n] | UInt array of n + 2 elements, built the same way | [R] |
| DATE_AND_TIME | USInt array of 8 BCD bytes as in 11.5 | [R] |
| DTL | packed struct 0x02000043: interface timestamp = attribute 529 of type 0x02000043, transport flags 2, byte count 12, the 12 bytes of 11.5 (the studied implementation sends weekday 0) | [R] |
| whole elementary array | flags `10`, the element datatype, the element count, the elements | [R] |
| whole struct / UDT | packed struct with the struct ID, interface timestamp, transport flags and byte count exactly as a read of the same address returned, with the changed bytes | [R, untested] |

* The interface timestamp of a packed struct must match the type's attribute 529; otherwise the PLC rejects the
  item ("invalid timestamp in type-safe blob" in the studied implementation). [R]
* Whole BOOL arrays: a read returns a Byte array (8 elements per byte, 11.6) while the studied implementation writes
  a Bool array with one byte per element; which form the PLC accepts is unknown. Write BOOL array elements one by
  one until this is tested. [R]
* Safe practice for structs: read the packed struct, change the member bytes using 11.8, write it back.

### 17.4 Example: write one BOOL (invented tag)

`Line1.Conveyor.Running` (BOOL, access sequence `8A0E0005.A.9`, address CRC 0x2556A63B as in 11.4) set to true.
Sequence 42; "set" counter value 1 (the first write of the session).

```
0231000005420000002a70000a103400000000010682aadacc3b88d0b880050393760a090100010100000004e8896900
1200000000896a001300896b000400000100000000
```

| Bytes | Meaning |
|---|---|
| `02 31 0000 0542 0000 002a` | version 2, request, SetMultiVariables, sequence 42 |
| `70000a10 34` | session ID, transport flags |
| `00000000` | object ID 0: tag write |
| `01` | item count 1 |
| `06` | field count 6 (4 + 2 LIDs) |
| `82 aa da cc 3b  88 d0 b8 80 05  03  93 76  0a  09` | address: CRC 0x2556A63B, area 0x8A0E0005, 3 IDs, sub-area 2550, LIDs 0xA, 0x9 |
| `01  00 01 01` | item 1: Bool true |
| `00` | fill byte |
| `000004e8 ... 00` | object qualifier (9.1) |
| `01` | integrity ID 1 ("set" counter) |
| `00000000` | end |

Response (18 bytes):

```
0232000005420000002a3400002b00000000
```

| Bytes | Meaning |
|---|---|
| `02 32 0000 0542 0000 002a 34` | version 2, response, SetMultiVariables, sequence 42, transport flags |
| `00` | return value 0 |
| `00` | end of error list (no failed items) |
| `2b` | integrity ID 43 = 42 + 1 |
| `00000000` | end |

### 17.5 Example: several items, one failing (invented; layout [R])

Three items in one request: `Line1.Conveyor.Speed` (REAL) = 2.25, `Line1.Recipe` (STRING[10]) = "Mix2", and an INT
to a LID that does not exist. Sequence 43, "set" integrity 2.

```
0231000005420000002b70000a103400000000031086f292ce3a88d0b880050393760a0b88e2bad41d88d0b880050293
760e0088d0b8800502937681ff7f01000e401000000210020c0a044d697832000000000000030007000500000004e889
69001200000000896a001300896b000400000200000000
```

| Bytes | Meaning |
|---|---|
| `00000000 03 10` | object ID 0, 3 items, field count 16 (6 + 5 + 5) |
| `86f292ce3a 88d0b88005 03 9376 0a 0b` | item address 1: CRC 0x6E44A73A, `8A0E0005.A.B` |
| `88e2bad41d 88d0b88005 02 9376 0e` | item address 2: CRC 0x8C4EAA1D, `8A0E0005.E` |
| `00 88d0b88005 02 9376 81ff7f` | item address 3: CRC 0, `8A0E0005.7FFF` |
| `01 00 0e 40100000` | value 1: Real 2.25 |
| `02 10 02 0c 0a 04 4d697832 000000000000` | value 2: USInt array of 12: max 10, length 4, "Mix2", padding |
| `03 00 07 0005` | value 3: Int 5 |
| `00`, object qualifier, `02`, `00000000` | fill byte, qualifier, integrity ID 2, end |

Response with item 3 failing (return value and item error borrowed from the read example in 11.4; the values a
write really returns were not captured):

```
0232000005420000002b349089f0808082c2801303c0d3d18080a5c5ff01002d00000000
```

| Bytes | Meaning |
|---|---|
| `9089f0808082c28013` | return value 0x2027800000A10013 (non-zero: at least one item failed) |
| `03 c0d3d18080a5c5ff01` | error list: item 3, item error 0x814E88000962FF01 (low 16 bits -255) |
| `00` | end of error list |
| `2d` | integrity ID 45 = 43 + 2 |
| `00000000` | end |

---

## Out of scope

Not captured; listed so a parser can recognise them. Implement nothing here without new captures.

| Feature | Identifiers |
|---|---|
| SetVariable | `04 F2`: writes one attribute of an object (used for CPU control and legitimation, not for tags). |
| Subscriptions | CreateObject `04 CA` of class 1001 (Subscription) below the second session object ID, attributes 1048 (reference list), 1049 cycle time, 1050 delay, 1051 disabled, 1052 count, 1053 credit limit, 1054 ticks, 1040 route mode, 1041 active; notifications use opcode `33`; DeleteObject to remove. |
| Alarms | subscription with function class 2, alarm subsystem RID 8, class 2662. |
| Password login (legitimation) | GetVarSubStreamed of attribute 1842, 303 challenge, SetVariable of 304 / 1846 with an encrypted response; firmware >= 3.1 uses a new method keyed with the TLS exporter `EXPERIMENTAL_OMS`. |
| CPU start / stop | SetVariable on RID 52 attribute 2167 (operating state request). |
| Traces, online block view | TIS objects (RID 7, classes 2700, 2709, 8138). |

### Legacy (non-TLS) mode

CPUs or projects without secure PG/HMI communication (S7-1500 before firmware 2.9, S7-1200 before 4.5, or projects
from TIA Portal before V17) do not use InitSsl/TLS. Instead the CreateObject response carries a server challenge and
a public-key fingerprint; the client must answer with a key blob derived from the challenge and a Siemens
firmware-family public key, and afterwards every PDU (protocol version 3) carries a 33-byte field (1 length byte + a
32-byte digest) right after the frame header. This mode needs key material that is not part of this page and is not
planned for the first client.

---

## Open questions

Everything below is **not** answered by the captures. An implementer follows the stated default, or treats the
point as unsupported until new captures exist.

TLS

* TLS 1.2, ChaCha20, SNI and ALPN: untested. Default: TLS 1.3, AES-GCM, no SNI, no ALPN (as captured).
* Session resumption / tickets: two post-handshake records were received (4.2); resumption never tried. Default:
  full handshake on every connect.
* Certificate check: a custom check is mandatory (4.3). Which policy (pinning, trust on first use, accept any) is a
  client decision. Behaviour with a TIA project CA: untested.
* Timeouts: only the observed timings in 4.2 are known; the PLC's own handshake and response timeouts are unknown.
  Default: connect timeout 10 s or more.

Session

* PLC idle timeout for a session without traffic (more than 40 s, upper bound unknown). Default: a cheap request
  every 10 to 20 s when idle (10.7).
* Meaning of the CreateObject client RID 0x80C3C901 (the studied implementation also sends only this value) and
  whether other values work; meaning of the second object ID of the CreateObject response. Default: send the value
  shown, ignore the second ID.
* Whether the CreateObject object-ID count is one byte or a VLQ32: both read 2 as `02`. Default: one byte (the
  studied implementation reads one byte).
* Reaction to a wrong sequence number or integrity ID (never provoked). Default: never send one; close the
  connection on any response whose sequence or integrity ID does not match.
* Sequence wrap (0xFFFF to 1) and integrity wrap (0xFFFFFFFF to 0, response sum modulo 2^32): taken from the
  studied implementation, never observed (6.5, 6.6).
* Several requests in flight: never captured (6.8). Default: one at a time.
* Session ID reuse after a connection dropped without DeleteObject: not shown by the captures (10.3).
* Meaning of the high return-value bits on successful CreateObject / DeleteObject.

Never captured (parsers should recognise them, behaviour unknown)

* Error PDUs (functions `04 B1` / `05 A9`): layout unknown; the studied implementation does not parse them either.
  Default: close the connection.
* Negative return values and error objects after bit 0x4000000000000000. Default: fatal for the request; close the
  connection if it is not a GetMultiVariables / SetMultiVariables item error.
* Version `fe` system-event frames. Studied implementation [R]: after the version byte, four 4-byte BE integers
  (reserved, confirmed bytes, reserved, reserved), then either a value encoded with fixed-width integers instead of
  VLQs (a Struct holding a return value, element 40305, LInt) or a UTF-8 text up to the end; it treats a negative
  return value as fatal. Default: accept and ignore unless the return value is negative.
* Opcode `02` responses, `A4` relation elements, value flag `80`, the [R] datatypes in 8.2, blobs with root ID > 1,
  the packed-struct 0x400 double count.
* Offset-info types 0, 3, 4, 7 and 14; multi-dimensional struct arrays; multi-dimensional arrays with more than two
  dimensions or non-zero lower bounds.
* Explore paging or splitting of responses larger than about 466 KB; client requests split over several frames.
* Write item errors and writes of anything other than a single BOOL (17).

Fixed bytes whose meaning is unknown (send exactly as shown)

* The 4 zero bytes after the request value in CreateObject (10.2).
* The `00` fill byte after the values in every SetMultiVariables request (10.4, 17.1).
* The `01` byte after "children" and the 5th zero end byte in Explore requests (13.1); the 5 (not 4) zero bytes
  after the return value in the InitSsl response (section 3).
* `00 01` before the integrity ID in GetVarSubStreamed requests, and the leading `00` of its response (13.8).

Value semantics

* Encodings marked [R]: DATE, TOD, S5TIME, LTIME, LTOD, CHAR, WCHAR, LWORD; none of these types existed in the test
  program.
* Order of a multi-dimensional array's flat index (11.6). The studied implementation stores the dimensions in the
  offset info innermost first (count 1 belongs to the **last** declared dimension) and lets the last declared
  dimension vary fastest. [R] The meaning of an address with two index LIDs is unknown.
* n-dimensional CRC beyond the 2-dimensional, zero-lower-bound case (11.7). Default: use the vartype CRC, or 0.
* Time zone of DT, DTL and LDT values: not on the wire. Default: present them as PLC local time without conversion.
* STRING code page: not on the wire; only ASCII was seen. The studied implementation defaults to ISO-8859-1 and lets
  the user change it. Default: ISO-8859-1 / Windows-1252, configurable.
* CRC type codes for OB/event types and AOM identifiers (11.7), never seen. Default: use the vartype CRC, or 0.
* Limits: behaviour above 100 items per request and the maximum request PDU size (16). Default: at most 100 items
  and one frame per request.

Other

* Preset dictionaries for the compressed comment / interface blobs are needed and must be obtained by a clean
  route (see the maintainers). Until then symbol comments are not implementable (14.3).
* Block comment sparse key (1034 and 1032 observed, CPU text language 1033).
* Meaning of DB class flag 0x40000000 (seen only on safety-program DBs), of attribute flags 0x0080 and 0x0100, and
  of bit-offset info 1 in struct-form elements.
* Whether technology-object DBs (class 4600) and the unknown block classes of 13.2 hold readable tags.
* How program changes appear in attributes 529 / 410 and in an open session.
