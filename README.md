# lanchat

Tiny encrypted 1:1 terminal chat for two machines on the same network. macOS, Windows, Linux.

## Install

macOS / Linux: `./install.sh`  
Windows: double-click `install.bat` (or run it in a terminal)

(or just `pip install -r requirements.txt`; Python 3.8+)

## Use

One person hosts, the other joins with the host's IP (printed on start). Both use the same password.

```bash
# host (macOS)
.venv/bin/python lanchat.py -p "our secret" -n nassif

# join (Windows)
.venv\Scripts\python lanchat.py -p "our secret" -c 172.21.x.x -n friend
```

Options: `-p` password (or `LANCHAT_PASSWORD` env var, or prompted), `-c IP` join, `-n` name, `--port` (default 5757).
Prefer the env var / prompt over `-p` if you don't want the password in shell history.

## Security

AES-256-GCM, key derived from the password with PBKDF2-SHA256 (300k iterations) and fresh random salts every session.
Messages are authenticated, direction-bound and sequence-numbered (no tampering/replay). A wrong password fails the handshake.
Use a long password: someone sniffing the network can try guessing offline. There is no identity verification beyond the password.

## Troubleshooting

- Allow Python through the Windows firewall (private networks) / macOS prompt on the hosting machine.
- eduroam often enables client isolation, blocking device-to-device traffic. If `-c` times out, use a phone hotspot, or a tunnel like Tailscale and use the Tailscale IP.
