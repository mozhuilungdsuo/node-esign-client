# Node.js eSign example

A minimal Express application that integrates with the Nagaland IAM eSign broker.

It keeps the API key on the server, creates the broker request, stores state and transaction ownership in the browser session, validates IAM's completion redirect, downloads only completed documents, and retrieves eSign XML artifacts after completion.

See [API_DOCUMENTATION.md](API_DOCUMENTATION.md) for a framework-neutral IAM eSign Broker API reference.

## Prerequisites

- Node.js 20 or later.
- An IAM OAuth client with `esign.request` and `esign.read` enabled.
- An eSign API key generated for that client in IAM Admin.
- The exact `ESIGN_COMPLETION_URL` configured in the client's **eSign Completion URL** field in IAM Admin.

## Run locally

```bash
cp .env.example .env
npm install
npm start
```

Set the values in `.env`. With the defaults, configure this exact value in IAM Admin:

```text
http://localhost:3000/esign/complete
```

Then open `http://localhost:3000` and upload a document.

The form lets you choose a signing mode. **Direct** mode requires a PDF and should be used for documents that will receive multiple signatures. **Visible** mode requires the signer's name and should be used only for a single visible signature.

After a completed signing, the sample retrieves `esign_xml`, `esign_response_xml`, and `uid_token` from IAM. They are retained only in server memory, associated with the current server-side browser session. When a UID token is available, the next request displays a checked **Reuse the UID token** option; the application sends the token to IAM without placing it in the form, URL, or browser session data.

## Production notes

- Use HTTPS and set `ESIGN_COMPLETION_URL` to the public application URL.
- Replace Express's default in-memory session store with Redis, a database-backed store, or another durable shared store.
- Replace this sample's in-memory artifact and UID-token maps with encrypted application records, keyed to the authenticated signer or business record. Do not expose XML artifacts or UID tokens to browser JavaScript, URLs, or logs.
- Put `IAM_ESIGN_API_KEY` and `SESSION_SECRET` in a secret manager; never expose either value to the browser.
- Use an application-owned `client_reference` tied to the business record instead of this example's random UUID.
