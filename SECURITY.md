# Security policy

## Reporting a vulnerability

Do not open a public issue. Use **Security > Report a vulnerability** on this repository
(GitHub private vulnerability reporting), or email the product's security team. Include what you
found, how to reproduce it, and the impact you expect. We acknowledge reports within two
business days.

## What this repository does by default

- Secret scanning with push protection; Dependabot alerts and security updates.
- CodeQL code scanning on every pull request; merges are blocked on new high or critical alerts.
- Dependency review on pull requests; vulnerable additions at the platform's threshold block.
- The default branch is protected: pull requests only, code-owner review, required checks.

## Handling sensitive data

This repository may belong to a product that handles PHI or payment data. Never commit real
patient or cardholder data, including in tests, fixtures, logs or screenshots. Use synthetic
data. Do not log request bodies, identifiers or tokens.

## Access controls in the channel service

- **Inbound:** only `/channels/<kind>` is exposed outside the cluster. Each provider proves who it is
  in its own way before anything reads the message:
  - Slack: a v0 HMAC with a 5-minute window.
  - Twilio: a signature over the URL and parameters.
  - Mailgun: an HMAC over timestamp and token, each token accepted once.
  - Teams: a Bot Framework JWT checked for key, issuer and app id.
  Anything else gets a bare 401. Bodies are capped, and each message is handled at most once.
- **Who reaches the product:** only people who have linked their channel identity by signing in to
  the product. Unlinked people get a sign-in link with a single-use, 10-minute nonce (only its hash
  is stored); their messages go nowhere. Each identity is rate-limited.
- **Consent:** STOP, START and HELP are honoured on every channel. Nothing is sent to an identity that
  opted out, and SMS replies need opt-in.
- **Content:** for PHI products, a channel carries message text only with a BAA with its provider;
  otherwise replies are a sign-in notice (`content: notice`).
- **Addresses** (phone numbers, emails, user ids) are never stored, logged or audited in the clear:
  a keyed hash to find them, and Fernet encryption (rotatable) to reply to them.
- **Outbound:** https to the provider's own hosts only, no redirects, credentials from mounted files.
- **Audit:** links, consent changes, replies sent and replies withheld, by identity id. A reply isn't
  sent without its record.
