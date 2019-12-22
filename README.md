
# Currently detected BOT
* Andromeda
* ArcolotBot
* Quasar
* Ghost
* Awesome Rat
* Kage

# How it works
This is a simple shell (BASH) script, which uses known signatures to detect hidden malware, BOT and RAT on Linux systems.

```bash
git clone https://github.com/ChriSanders22/BotScanner.git
cd BotScanner
chmod +x scanner.sh
sudo ./scanner.sh
BotScanner v1.1
Simple utility to scan the system for known malicious BOT indicators

Starting scan...
Analysing /bin/bash
Analysing /bin/busybox
Analysing /bin/ip
Analysing /bin/systemctl
Analysing /bin/udevadm
Analysing /boot/grub/unicode.pf2
@@@ MATCH FOUND at file /tmp/fsock.bin
...
```
