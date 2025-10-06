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
    
    // Step 1: RSA-decrypt the AES key
    let aesKeyBuffer = null;
    try {
      aesKeyBuffer = privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        Buffer.from(encrypted_aes_key, "base64")
      );
    } catch (pkcs1Error) {
      try {
        aesKeyBuffer = privateDecrypt(
          {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          },
          Buffer.from(encrypted_aes_key, "base64")
        );
      } catch (oaepError) {
        return res.status(500).json({ 
          error: "RSA decryption failed for encrypted_aes_key",
          details: {
            pkcs1Error: pkcs1Error.message,
            oaepError: oaepError.message
          }
        });
      }
    }

    // Extract the AES key (typically 32 bytes for AES-256)
    let aesKey;
    if (aesKeyBuffer.length === 32) {
      // Perfect AES-256 key
      aesKey = aesKeyBuffer;
    } else if (aesKeyBuffer.length > 32) {
      // Take first 32 bytes if longer (might have padding)
      aesKey = aesKeyBuffer.subarray(0, 32);
    } else {
      // Key too short, might need padding or different extraction
      return res.status(500).json({ 
        error: `Invalid AES key length: ${aesKeyBuffer.length} bytes (expected 32 for AES-256)`,
        debug: {
          aesKeyHex: aesKeyBuffer.toString('hex'),
          aesKeyLength: aesKeyBuffer.length
        }
      });
    }

    // Step 2: Decode the IV
    const iv = Buffer.from(initial_vector, "base64");
    if (iv.length !== 12) {
      return res.status(500).json({ 
        error: `Invalid IV length: ${iv.length} bytes (expected 12 for AES-GCM)`,
        debug: {
          ivHex: iv.toString('hex'),
          ivLength: iv.length
        }
      });
    }

    // Step 3: Decode the encrypted payload
    const encryptedPayload = Buffer.from(encrypted_flow_data, "base64");
    
    // For AES-GCM, we need to separate the ciphertext from the authentication tag
    // The tag is typically the last 16 bytes
    const tagLength = 16;
    if (encryptedPayload.length < tagLength) {
      return res.status(500).json({ 
        error: `Encrypted payload too short: ${encryptedPayload.length} bytes (need at least ${tagLength} for tag)`
      });
    }
    
    const ciphertext = encryptedPayload.subarray(0, encryptedPayload.length - tagLength);
    const tag = encryptedPayload.subarray(encryptedPayload.length - tagLength);

    // Step 4: AES-GCM decryption
    let decryptedText = null;
    let decodingMethod = 'AES-GCM';
    
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
      decipher.setAuthTag(tag);
      
      let decrypted = decipher.update(ciphertext);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      decryptedText = decrypted.toString('utf8');
      
    } catch (aesError) {
      return res.status(500).json({ 
        error: "AES-GCM decryption failed",
        details: aesError.message,
        debug: {
          aesKeyLength: aesKey.length,
          aesKeyHex: aesKey.toString('hex'),
          ivLength: iv.length,
          ivHex: iv.toString('hex'),
          ciphertextLength: ciphertext.length,
          tagLength: tag.length,
          tagHex: tag.toString('hex')
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
      algorithm: "RSA-2048 + AES-256-GCM",
      decodingMethod: decodingMethod,
      debug: {
        aesKeyLength: aesKey.length,
        ivLength: iv.length,
        payloadLength: encryptedPayload.length,
        ciphertextLength: ciphertext.length,
        tagLength: tag.length
      }
    });
    
  } catch (e) {
    res.status(500).json({ error: e.message, stack: e.stack });
  }
}

// Vercel (API Routes) expects default export
