# WhatsApp Webhook Decrypt API

A Vercel serverless function to decrypt WhatsApp Business API webhook data encrypted with RSA + AES.

## Overview

This API decrypts WhatsApp webhook data that uses hybrid encryption:
1. **RSA encryption** for the AES key (using OAEP padding)
2. **AES-256-CBC encryption** for the actual webhook data

## Deployment

### Vercel Deployment

1. Deploy to Vercel:
   ```bash
   vercel --prod
   ```

2. Set the environment variable in Vercel dashboard:
   - `PRIVATE_KEY`: Your RSA private key in PEM format

### Environment Variables

- `PRIVATE_KEY`: RSA private key for decrypting the AES key

## API Usage

### Endpoint
`POST /api/decrypt`

### Request Body
```json
{
  "encrypted_aes_key": "base64-encoded-encrypted-aes-key",
  "encrypted_flow_data": "base64-encoded-encrypted-data", 
  "initial_vector": "base64-encoded-iv"
}
```

### Response
```json
{
  "decrypted": "raw-decrypted-text",
  "json": "parsed-json-if-valid"
}
```

### Error Response
```json
{
  "error": "error-message"
}
```

## Public Key

Configure your WhatsApp Business API with this public key:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqYYR/W8QmfjaNe/sLRzC
LYXwoUCvAe0eeiFDDAP1grfDVkV4VNCQiI9zMMaFRV3GXJnIloYforEzqVNEv+Mr
t6xpHK3vzCKvaxYI+SOHO+ugdQYTd/Jo37JrCJPoo2JUHNEfTlRbhKwfPIJrb5eK
m6ipz0pLMk8upseFAokZ07EWhTNafHKl9cmt3a7kQfHPyoB7aatwLR4uVWs+9WTD
zFbV1u1IdoaOEIRH+vI58Po1obJdfEIj3Fs3x5mKh2xRbsHo9TUways6igMPjbq1
XsatcOd1+8FUub9Z7K/L9yXpeBemM9SdxW6LS3xzuPysg+j1hwJ7iqBkHdYwuIzH
mwIDAQAB
-----END PUBLIC KEY-----
```

## Local Development

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create `.env` file with your private key:
   ```
   PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
   ...your private key...
   -----END PRIVATE KEY-----"
   ```

3. Test locally:
   ```bash
   vercel dev
   ```

## Security Notes

- Keep your private key secure and never commit it to version control
- The private key should only be stored in Vercel's environment variables
- Ensure your WhatsApp Business API is configured with the corresponding public key

## Troubleshooting

### "Cannot read properties of undefined (reading 'RSA_PKCS1_OAEP_PADDING')"
- Fixed by importing the full crypto module: `import crypto, { ... } from "crypto"`

### "OAEP decoding error"
- Ensure the webhook data was encrypted with your public key
- Verify the environment variable `PRIVATE_KEY` is correctly set
- Check that the webhook data is properly base64 encoded

## Files Structure

```
├── api/
│   └── decrypt.js          # Main API endpoint
├── vercel.json            # Vercel configuration
├── package.json           # Dependencies
├── .gitignore            # Git ignore rules
└── README.md             # This file
```