# Changelog

## [1.0.0] - Initial release

- Pure-JS WebSocket C2 agent running inside the IDE extension host
- Mythic `websocket` profile support (`aes256_hmac` envelope)
- Optional EKE (RSA-4096 staging) for profiles with encrypted exchange enabled
- Fully config-driven: no infrastructure values in the package
- Cover features: path autocomplete, word count status bar
- Tasking: shell, filesystem ops, recon, download/upload, sleep, exit
- Reconnect with exponential backoff; survives VPN/interface changes
