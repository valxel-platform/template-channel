# template-channel

The Valxel template for a **conversation channel**: people talk to the product (often to its
agent) over Slack, Microsoft Teams, SMS or email, and get replies there. Messages become a data
contract on Kafka. The product's replies come back as one, and go out only to people who linked
their identity and didn't opt out.

```
Slack/Teams/SMS/email ──signed──▶ /channels/<kind> ─▶ verified? linked? consent? rate? ─▶ outbox ─▶ Kafka (messages)
                      ◀── provider API (allowlisted) ◀── linked, not opted out, notice or full ◀── Kafka (replies)
```

## What you write

- **`channel.yaml`:** the channels (`slack`, `teams`, `sms`, `email`). For each: content (`full`, or
  `notice` for a sign-in notice instead of text; PHI in full needs `baa: true`), the names of its
  mounted secrets, the per-person rate, and for SMS and email the product's number or address. Also
  the product's sign-in page for linking and the two datasets. G4 reviews it with the design's
  *Channels* section.
- **`contracts/`** is written by the SDLC tool.

## How people get in

1. Someone messages the product. If they aren't linked, they get one reply with a sign-in link (a
   single-use, 10-minute nonce).
2. They sign in on the product's page, and the BFF calls `POST /links/{nonce}/confirm` with their
   token. Their identity on that channel is now theirs.
3. Their messages are published to the product. Replies reach them unless they've sent STOP.

## Secrets (mounted files)

- Per channel:
  - Slack: `signing`, `token`
  - Teams: `app_id`, `app_password`
  - SMS (Twilio): `auth_token`, `account_sid`
  - Email (Mailgun): `signing`, `api_key`
- For every product: `address-pepper` (a random string) and `address-key` (a Fernet key; put the
  old key on the second line while rotating).

## Ports

The API is on 8080, with `/healthz` and `/readyz` for Kubernetes' probes. `/metrics` is on the
management port, `MANAGEMENT_PORT` (8081), as Spring's actuator is in the Java templates. The
platform's metrics collector scrapes it there, and the product's mesh lets the collector reach that
port and no other. The API port serves no metrics.

## Running

```sh
uv sync
uv run pytest            # VALXEL_TEST_DATABASE_URL=postgresql://... also runs the Postgres store tests
```

See [SECURITY.md](SECURITY.md) for the access controls.
