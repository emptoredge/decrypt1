# N8N Workflow Fix

## Current Issue:
Your "Respond to Webhook" node has:
```
responseBody: "={{ $json.data }}"
```

## Problem:
1. Your decrypt API returns a Base64 encrypted string, not JSON with a "data" field
2. You need to capture form data for your business logic
3. You need the user's mobile number

## Solution: Use the New N8N Endpoint

### Update Your HTTP Request Node:
Change the URL from:
```
https://decrypt1.vercel.app/api/decrypt
```
To:
```
https://decrypt1.vercel.app/api/decrypt-n8n
```

### Updated N8N Workflow:

1. **Webhook** (receives WhatsApp request)
2. **HTTP Request** → `https://decrypt1.vercel.app/api/decrypt-n8n`
3. **Function Node** (process response)
4. **Respond to Webhook** (return Base64)

### Function Node Code:
```javascript
// Get the response from decrypt-n8n API
const apiResponse = $input.first().json;

// Extract mobile number from WhatsApp webhook headers or body
const webhookData = $node["Webhook"].json;
const mobileNumber = webhookData.contacts?.[0]?.wa_id || 
                    webhookData.from || 
                    'unknown';

// Log/store the form data for your business logic
if (apiResponse.formData) {
  console.log('📱 Mobile:', mobileNumber);
  console.log('📋 Form Data:', apiResponse.formData);
  
  // TODO: Save to database, send to CRM, etc.
  // Example:
  // await saveToDatabase({
  //   mobile: mobileNumber,
  //   screen: apiResponse.formData.screen,
  //   data: apiResponse.formData.data,
  //   timestamp: apiResponse.timestamp
  // });
}

// Return the encrypted response for WhatsApp
return [{
  json: apiResponse.encryptedResponse
}];
```

### Respond to Webhook Node:
```
respondWith: "text"
responseBody: "={{ $json }}"
options: {}
```

## Getting Mobile Number:

The mobile number comes in the WhatsApp webhook payload. Check these fields:
- `$node["Webhook"].json.contacts[0].wa_id`
- `$node["Webhook"].json.from`
- `$node["Webhook"].json.entry[0].changes[0].value.contacts[0].wa_id`

### Example Webhook Structure:
```json
{
  "entry": [{
    "changes": [{
      "value": {
        "contacts": [{"wa_id": "1234567890"}],
        "messages": [{"from": "1234567890"}]
      }
    }]
  }]
}
```

## What You Get From decrypt-n8n API:

```json
{
  "encryptedResponse": "dPpWZoECk6Lsnh3L...", // For WhatsApp
  "decryptedRequest": {
    "action": "data_exchange",
    "screen": "FIRST_NAME", 
    "data": {"first_name": "John"},
    "version": "3.0"
  },
  "formData": {
    "screen": "FIRST_NAME",
    "data": {"first_name": "John"},
    "timestamp": "2025-10-06T10:00:00.000Z"
  },
  "responseData": {
    "screen": "LAST_NAME",
    "data": {"first_name": "John"}
  }
}
```

This gives you:
1. ✅ **Encrypted response** for WhatsApp
2. ✅ **Form data** for your business logic  
3. ✅ **Mobile number** from webhook headers
4. ✅ **Complete visibility** into the flow