# Two-Factor Authentication Testing Guide

## Development Mode (No Email Configuration)

When running in development mode without email configuration, the system will:
1. Log OTP codes to the console: `[DEV MODE] OTP Code for user@email.com: 123456`
2. Store plain text code in database (dev mode only) for testing
3. Provide a debug endpoint at `/auth/debug/otp-codes` to view all active OTP codes

### How to Test 2FA in Development:

#### Method 1: Using the Debug Endpoint (Recommended)
1. Go to **Login** page: `http://localhost:5000/auth/login`
2. Enter email and password → You'll be redirected to OTP verification page
3. In another tab, go to **Debug OTP Codes**: `http://localhost:5000/auth/debug/otp-codes`
4. Find your email in the table and copy the **Plain Code**
5. Return to OTP verification page and paste the code
6. Click "Verify" to complete login

#### Method 2: Using Console Output
1. Go to **Login** page
2. Enter email and password
3. Check your terminal/console where Flask is running
4. Look for message: `[DEV MODE] OTP Code for your-email@test.com: XXXXXX`
5. Enter that code on the OTP verification page

#### Method 3: Using Browser Console
1. Go to **Login** page
2. Open Browser Developer Tools (F12)
3. Go to **Console** tab
4. Enter email and password
5. Check console logs for OTP code output
6. Enter code on OTP verification page

## Production Mode (With Email Configuration)

To enable actual email sending:

### Set Environment Variables:
```bash
export MAIL_SERVER=smtp.gmail.com
export MAIL_PORT=587
export MAIL_USE_TLS=True
export MAIL_USERNAME=your-email@gmail.com
export MAIL_PASSWORD=your-app-specific-password
export MAIL_DEFAULT_SENDER=noreply@yourdomain.com
```

### For Gmail:
1. Enable 2-Step Verification on your Gmail account
2. Go to myaccount.google.com/apppasswords
3. Create an "App password" for "Mail" → "Windows"
4. Use this app password as `MAIL_PASSWORD`

### For Gmail Alternatives:
- **SendGrid**: `MAIL_SERVER=smtp.sendgrid.net`, `MAIL_PORT=587`, `MAIL_USERNAME=apikey`
- **Mailgun**: `MAIL_SERVER=smtp.mailgun.org`, `MAIL_PORT=587`
- **AWS SES**: `MAIL_SERVER=email-smtp.region.amazonaws.com`, `MAIL_PORT=587`

## Testing 2FA Features

### Test Invalid OTP
- Enter wrong code
- System should reject after each attempt (1/5, 2/5, etc.)
- After 5 failed attempts, code is blocked

### Test Code Expiry
- Generate OTP code
- Wait 10 minutes (or manually check database)
- Try to enter code
- System should reject as expired

### Test Request New Code
- On OTP verification page, click "Didn't receive code? Get a new one"
- New code should be generated
- Old code should be invalidated
- Use new code to verify

## Security Properties (Even in Dev Mode)

✅ **OTP codes are always hashed with PBKDF2-HMAC before storage**
- Plain text ONLY stored in dev mode for testing
- Never stored in production
- Each code has unique salt (32 bytes)

✅ **100K iterations PBKDF2** for all codes
- Same as password hashing
- Prevents brute-force attacks

✅ **Constant-time comparison** during verification
- Prevents timing attacks
- Same execution time for valid/invalid codes

✅ **Rate limiting**
- Max 5 failed attempts
- After 5, code is blocked
- User must request new code

✅ **Code expiry**
- 10-minute timeout
- Expired codes automatically rejected

## Troubleshooting

### "Email not received"
- **Dev Mode**: Check browser console or terminal for `[DEV MODE]` output
- **Production**: Check email spam folder, verify SMTP credentials

### "Too many failed attempts"
- Use the debug endpoint at `/auth/debug/otp-codes`
- Click "Request new code" button on verification page
- Or wait for code to expire (10 minutes)

### "Verification code expired"
- Request a new code via "Request new code" button
- Codes are valid for 10 minutes

### SMTP Configuration Issues
- Verify MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD are correct
- For Gmail, use app-specific password, not regular password
- Check firewall doesn't block port 587 (TLS)
- Enable "Less secure apps" if not using app passwords (Gmail)

## Database Fields

```sql
verification_code table:
- id: Unique ID
- user_id: User this code belongs to
- code_hash: PBKDF2 hash of the 6-digit code
- code_salt: Random salt for the hash
- plain_code_dev: Plain text code (dev mode only, NULL in production)
- created_at: When code was generated
- expires_at: When code becomes invalid (created + 10 min)
- is_verified: True after successful verification
- attempts: Number of failed verification attempts
- max_attempts: Maximum attempts allowed (5)
```

## Code Generation Algorithm

OTP codes are generated using HMAC-based derivation (from scratch):

```
1. Generate 16 random bytes
2. Apply HMAC-SHA256 with 'OTP-GENERATION-KEY'
3. Convert first 4 bytes to integer
4. Take modulo 1,000,000 for 6-digit number
5. Pad with zeros if necessary (e.g., 000123)
```

This ensures:
- Random but deterministic generation
- No external RNG dependencies
- All crypto from scratch
- 1 in 1,000,000 brute-force difficulty per attempt

## Security Best Practices

1. **Never log OTP codes in production** (plain_code_dev is NULL)
2. **Use HTTPS only** in production
3. **Rotate email credentials** regularly
4. **Monitor failed login attempts** for security threats
5. **Implement IP-based rate limiting** for additional protection
6. **Store codes in encrypted database** (all codes are hashed)
