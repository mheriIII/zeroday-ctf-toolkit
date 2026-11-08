# zero day ctf toolkit

ngl i didnt plan to build a "project", i just wanted to finish the HackUTD 2026 **Zero Day** CTF. but by the end i had written a whole pile of python to crack each stage so im calling that the project lol.

everything here is from-scratch — no wireshark, no ghidra. just python, `capstone`, `numpy` and `pillow`.

## tools

| file | what it does |
|------|--------------|
| `pcap_parse.py` | reads a raw `.pcap` (ethernet/ip/tcp/udp, no tshark), rebuilds HTTP streams + TLS SNI so you can fingerprint who was on a wifi |
| `jpeg_comments.py` | pulls `COM` (comment) segments out of a folder of jpegs and decodes `index:base64` fragments in order |
| `zipcrypto_crack.py` | recovers a Traditional-PKZIP (ZipCrypto) password from a wordlist using the fast 12-byte check-byte test, then extracts |
| `dlq_reassemble.py` | rebuilds a file split into N parts across relay scratch objects + a dead-letter queue, picking the right part by sha256 |
| `vm_solver.py` | disassembles a small x86-64 PE, recovers a custom accumulator-VM bytecode, and inverts its access check to recover the key |

## quick start

```bash
pip install capstone numpy pillow
python pcap_parse.py capture.pcap
python jpeg_comments.py ./images
python zipcrypto_crack.py secret.zip wordlist.txt
python vm_solver.py Vault.exe maintenance.dat
```

## what i learned

- zipcrypto is weak: you can test a password against just 12 header bytes before decrypting anything
- sqlite leaves deleted/"purged" rows lying around in slack space and the WAL
- TLS SNI basically deanonymizes you even when everything else is "encrypted"
- you can hide a whole access check inside a fake ~8-opcode cpu

## challenges

the shell one stage gave me had almost nothing in it — no `grep`, no `unzip`, no `python` — so i had to get creative with plain `curl`. and the final challenge needed a `maintenance.dat` file that wasnt even next to the exe, it was hidden as an attachment in the hackerpack.

## whats next

clean these up into actual cli tools instead of the one-off scripts they are right now.

*(educational / CTF use only.)*
