import { promises as fs } from "fs";
import crypto, { createPrivateKey, privateDecrypt } from "crypto";

// Store your private key in Vercel env as PRIVATE_KEY
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
    
    const privateKey = createPrivateKey(PRIVATE_KEY_PEM);
    
    // Step 1: RSA-OAEP decrypt the AES key with SHA-256
    let aesKey = null;
    try {
      // WhatsApp uses RSA-OAEP with SHA-256 for both MGF1 and hash
      aesKey = privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        Buffer.from(encrypted_aes_key, "base64")
      );
    } catch (oaepError) {
      return res.status(500).json({ 
        error: "RSA-OAEP decryption failed for encrypted_aes_key",
        details: oaepError.message,
        debug: {
          expectedKeyLength: "16 bytes (AES-128)",
          paddingUsed: "RSA_PKCS1_OAEP_PADDING with SHA-256"
        }
      });
    }

    // Validate AES key length (must be exactly 16 bytes for AES-128)
    if (aesKey.length !== 16) {
      return res.status(500).json({ 
        error: `Invalid AES key length: ${aesKey.length} bytes (expected exactly 16 for AES-128)`,
        debug: {
          aesKeyHex: aesKey.toString('hex'),
          aesKeyLength: aesKey.length
        }
      });
    }

    // Step 2: Decode the IV (16 bytes for AES-128-GCM)
    const iv = Buffer.from(initial_vector, "base64");
    if (iv.length !== 16) {
      return res.status(500).json({ 
        error: `Invalid IV length: ${iv.length} bytes (expected exactly 16 for AES-128-GCM)`,
        debug: {
          ivHex: iv.toString('hex'),
          ivLength: iv.length
        }
      });
    }

    // Step 3: Decode the encrypted payload
    const encryptedPayload = Buffer.from(encrypted_flow_data, "base64");

    // Step 4: AES-128-GCM decryption
    let decryptedText = null;
    
    try {
      // Split encrypted payload: last 16 bytes are the GCM authentication tag
      const tagLength = 16;
      if (encryptedPayload.length < tagLength) {
        return res.status(500).json({ 
          error: `Encrypted payload too short for GCM: ${encryptedPayload.length} bytes (need at least ${tagLength} for tag)`
        });
      }
      
      const ciphertext = encryptedPayload.subarray(0, encryptedPayload.length - tagLength);
      const tag = encryptedPayload.subarray(encryptedPayload.length - tagLength);

      // Create AES-128-GCM decipher with 16-byte IV
      const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
      decipher.setAuthTag(tag);
      
      let decrypted = decipher.update(ciphertext);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      decryptedText = decrypted.toString('utf8');
      
    } catch (gcmError) {
      return res.status(500).json({ 
        error: "AES-128-GCM decryption failed",
        details: gcmError.message,
        debug: {
          aesKeyLength: aesKey.length,
          aesKeyHex: aesKey.toString('hex'),
          ivLength: iv.length,
          ivHex: iv.toString('hex'),
          payloadLength: encryptedPayload.length,
          ciphertextLength: encryptedPayload.length - 16,
          tagLength: 16
        }
      });
    }

    // Step 5: Try to parse as JSON
    let parsed = null;
    try {
      parsed = JSON.parse(decryptedText);
    } catch (jsonError) {
      // Not JSON, that's okay
    }

    res.status(200).json({ 
      decrypted: decryptedText,
      json: parsed,
      algorithm: "RSA-2048-OAEP-SHA256 + AES-128-GCM",
      debug: {
        aesKeyLength: aesKey.length,
        ivLength: iv.length,
        payloadLength: encryptedPayload.length,
        ciphertextLength: encryptedPayload.length - 16,
        tagLength: 16
      }
    });
    
  } catch (e) {
    res.status(500).json({ error: e.message, stack: e.stack });
  }
}

// Vercel (API Routes) expects default export
