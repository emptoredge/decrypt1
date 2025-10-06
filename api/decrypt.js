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
      // Try the first 32 bytes - WhatsApp might put the key at the beginning
      decryptedAesKey = decryptedAesKey.subarray(0, 32);
    } else if (decryptedAesKey.length > 32) {
      // If still longer, try first 32 bytes
      decryptedAesKey = decryptedAesKey.subarray(0, 32);
    } else if (decryptedAesKey.length !== 32) {
      return res.status(500).json({ 
        error: `Invalid AES key length: ${decryptedAesKey.length} bytes, expected 32 bytes` 
      });
    }

    // AES Decrypt Flow Data using AES-GCM (not CBC!)
    // WhatsApp Flow data_api_version "3.0" uses AES-GCM
    const encryptedData = Buffer.from(encrypted_flow_data, "base64");
    const iv = Buffer.from(initial_vector, "base64");
    
    // For AES-GCM, we need to extract the auth tag (last 16 bytes typically)
    // and the actual encrypted data (everything except the last 16 bytes)
    const authTagLength = 16; // AES-GCM standard auth tag length
    const authTag = encryptedData.subarray(-authTagLength);
    const ciphertext = encryptedData.subarray(0, -authTagLength);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', decryptedAesKey, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(ciphertext, null, 'utf8');
    decrypted += decipher.final('utf8');

    // Try parse as JSON
    let parsed;
    try {
      parsed = JSON.parse(decrypted);
    } catch {
      parsed = null;
    }

    res.status(200).json({ 
      decrypted, 
      json: parsed,
      algorithm: "AES-256-GCM",
      authTagLength: authTagLength
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

// Vercel (API Routes) expects default export
