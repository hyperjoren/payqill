# Payqill BharatPe Relay

Tiny HTTP relay so Payqill (Cloudflare Workers) can reach BharatPe's Cloudflare-protected APIs. Cloudflare blocks Worker-to-Worker (CF-to-CF) egress with a `530`, so we forward via a normal Node host.

## Deploy on Railway

1. New Project -> Deploy from this repo.
2. Variables: set `RELAY_SECRET` to a random 32+ char string (same value you pasted into Payqill).
3. Settings -> Networking -> Generate Domain.
4. Paste the domain into Payqill secret `BHARATPE_RELAY_URL` and the secret into `BHARATPE_RELAY_SECRET`.

## Request shape

```
POST /
x-relay-secret: <RELAY_SECRET>
Content-Type: application/json

{ "url": "https://transaction.bharatpe.in/...", "headers": { ... } }
```

Only `*.bharatpe.in` hosts are allowed.
