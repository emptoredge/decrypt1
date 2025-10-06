import { promises as fs } from "fs";
import crypto, { createPrivateKey, privateDecrypt, createDecipheriv } from "crypto";

// Optional: Store your private key in Vercel env as PRIVATE_KEY with actual PEM data
const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY;

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }
  try {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = req.body;
    if (!encrypted_aes_key || !encrypted_flow_data || !initial_vector) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    
    // RSA Decrypt AES Key - Try both padding modes
    const privateKey = createPrivateKey(PRIVATE_KEY_PEM);
    let decryptedAesKey = null;
    
    // Try PKCS1 padding first (WhatsApp appears to use this)
    try {
      decryptedAesKey = privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        Buffer.from(encrypted_aes_key, "base64")
      );
    } catch (pkcs1Error) {
      // Fallback to OAEP padding
      try {
        decryptedAesKey = privateDecrypt(
          {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          },
          Buffer.from(encrypted_aes_key, "base64")
        );
      } catch (oaepError) {
        return res.status(500).json({ 
          error: "RSA decryption failed with both padding modes",
          details: {
            pkcs1Error: pkcs1Error.message,
            oaepError: oaepError.message
          }
        });
      }
    }
    
    // Handle AES key length - WhatsApp sends padded keys
    // Based on debug output, we get 102 bytes but need 32
    if (decryptedAesKey.length === 102) {
      // PKCS1 padding structure: 0x00 0x02 [random padding] 0x00 [actual data]
      // Find the separator (0x00) after the padding
      let separatorIndex = -1;
      for (let i = 2; i < decryptedAesKey.length; i++) {
        if (decryptedAesKey[i] === 0x00) {
          separatorIndex = i;
          break;
        }
      }
      
      if (separatorIndex !== -1 && (decryptedAesKey.length - separatorIndex - 1) === 32) {
        // Extract the 32-byte AES key after the separator
        decryptedAesKey = decryptedAesKey.subarray(separatorIndex + 1);
      } else {
        // Fallback: try last 32 bytes
        decryptedAesKey = decryptedAesKey.subarray(-32);
      }
    } else if (decryptedAesKey.length > 32) {
      // If still longer, try first 32 bytes
      decryptedAesKey = decryptedAesKey.subarray(0, 32);
    } else if (decryptedAesKey.length !== 32) {
      return res.status(500).json({ 
        error: `Invalid AES key length: ${decryptedAesKey.length} bytes, expected 32 bytes` 
      });
    }

    // AES Decrypt Flow Data (AES-256-CBC)
    const decipher = createDecipheriv(
      "aes-256-cbc",
      decryptedAesKey,
      Buffer.from(initial_vector, "base64")
    );
    let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), null, "utf8");
    decrypted += decipher.final("utf8");

    // Try parse as JSON
    let parsed;
    try {
      parsed = JSON.parse(decrypted);
    } catch {
      parsed = null;
    }

    res.status(200).json({ decrypted, json: parsed });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

// Vercel (API Routes) expects default export
