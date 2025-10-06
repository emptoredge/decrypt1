import crypto, { createPrivateKey, privateDecrypt } from "crypto";

const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY;

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }
  
  try {
    // Capture ALL request information
    const debugInfo = {
      timestamp: new Date().toISOString(),
      headers: req.headers,
      body: req.body,
      method: req.method,
      url: req.url,
      query: req.query
    };
    
    // Return comprehensive debug information
    res.status(200).json({
      message: "Webhook received successfully",
      debug: debugInfo,
      suggestions: [
        "Check the data_api_version in headers or body",
        "Look for additional encryption-related fields",
        "Verify the webhook payload structure matches WhatsApp documentation",
        "Consider that different WhatsApp product APIs might use different encryption"
      ]
    });
    
  } catch (error) {
    res.status(500).json({ 
      error: error.message,
      debug: {
        headers: req.headers,
        body: req.body
      }
    });
  }
}