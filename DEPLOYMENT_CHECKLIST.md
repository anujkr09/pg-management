# StayWise Deployment Checklist

Before public deployment:

- Set `NODE_ENV=production`.
- Set `MONGODB_URI` as a deployment environment variable. Do not commit the real URI.
- Rotate the MongoDB password if it was ever pasted in chat, screenshots, or logs.
- Set `PAYMENT_WEBHOOK_SECRET` and configure the same secret in your payment gateway webhook settings.
- Set `BACKUP_INTERVAL_HOURS=24` or enable managed Atlas backups.
- Set `PUBLIC_BASE_URL=https://your-domain` before production. Production startup blocks insecure base URLs unless explicitly overridden.
- Optional: set `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` to enable hosted Razorpay payment links.
- Optional: set SMTP variables to send queued password/reminder emails automatically.
- Free testing: set `ALLOW_ETHEREAL_TEST_EMAIL=true` to send email previews through Ethereal. Use real SMTP before live.
- Set strong `ADMIN_PASSWORD` and `TENANT_PASSWORD` environment variables.
- Run behind HTTPS, for example Nginx/Caddy/Render/Railway/Vercel proxy.
- Do not expose the project folder as static hosting. Run `node server.js`.
- Confirm `/data/db.json` returns `404`.
- Take backups from `/api/admin/backup` after admin login.
- Change admin password after first login.
- Create tenant users through tenant creation flow and share temporary passwords privately.
- Use the Security screen to inspect audit logs and queued email/SMS messages.
- Replace demo tenant/payment data before going live.
- Use a real payment gateway webhook. The app accepts signed HMAC webhook verification at `/api/payments/webhook`.
- Free payment mode is UPI QR/intent plus admin verification. Real automatic bank-confirmed verification needs a gateway.
- Run `npm run check` and `npm run smoke` before deployment.

Remaining production upgrade:

- Keep regular MongoDB Atlas backups enabled.
- Connect SMS/WhatsApp provider if you need non-email reminders.
- Add Cashfree/PhonePe/Paytm checkout adapters if you do not want Razorpay payment links.
