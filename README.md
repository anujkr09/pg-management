# StayWise PG Hostel Management

Dynamic PG/hostel management app with a Node.js backend, MongoDB storage, admin and tenant portals, payment proof verification, invoices, audit logs, backups, and email/SMS outbox support.

## Setup

```bash
npm install
cp .env.example .env
npm start
```

Open:

```txt
http://localhost:3002
```

## Environment

Copy `.env.example` to `.env` and set your own values:

```env
MONGODB_URI=
MONGODB_DB=pghostel
ADMIN_EMAIL=owner@example.com
ADMIN_PASSWORD=replace-with-a-strong-admin-password
TENANT_PASSWORD=replace-with-a-temporary-tenant-password
PAYMENT_WEBHOOK_SECRET=replace-with-provider-webhook-secret
PUBLIC_BASE_URL=https://your-domain.example
```

Never commit `.env`, `data/db.json`, `backups/`, or `node_modules/`.

## Checks

```bash
npm run check
npm run smoke
```

For `npm run smoke`, set `SMOKE_ADMIN_PASSWORD` in your local `.env`.

## Data

`data/db.sample.json` is safe demo seed data for fresh clones.

`data/db.json` is ignored because it may contain tenant contact data, payment records, password hashes, audit logs, and uploaded QR images.

## Production Notes

- Use HTTPS.
- Store secrets as deployment environment variables.
- Rotate any credentials that were shared in chat, screenshots, commits, or logs.
- Use MongoDB Atlas backups.
- Use UPI QR/manual admin verification for free payments.
- Add Razorpay keys for hosted payment links.
- Add SMTP credentials for real email delivery.
- Add Twilio credentials and set `NOTIFY_CHANNELS=email,sms,whatsapp` for SMS/WhatsApp notifications.
