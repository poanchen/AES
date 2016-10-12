# AES
AES-256 implementation in Java.

## Requirement
- [Java SE Runtime Environment](http://www.oracle.com/technetwork/java/javase/downloads/jre8-downloads-2133155.html)

## Installation
Once you have Java SE runtime environment set up, then you may run the following command to start with.
```
git clone https://github.com/poanchen/AES.git
cd AES
javac AES.java
```

## Assumption
Your key file should contains a single line of 64 hex characters, which represents a 256-bit key.<br>
Your inputFile or plaintext should have 32 hex characters per line.<br>
For example, your input file might look something like this,<br>
0A935D11496532BC1004865ABDCA4295<br>
00112233445566778899AABBCCDDEEFF<br>
...

## Usage
Run encryption command
```
java AES e key plaintext
```
Run decryption command
```
java AES d key plaintext.enc
```
