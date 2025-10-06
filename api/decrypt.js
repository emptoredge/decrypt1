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
    
    // Try different auth tag configurations for AES-GCM
    const authTagLengths = [16, 12, 8]; // Common GCM auth tag lengths
    let decrypted = null;
    let usedConfig = null;
    
    for (const tagLength of authTagLengths) {
      if (encryptedData.length <= tagLength) continue;
      
      try {
        // Try auth tag at the end
        const authTag = encryptedData.subarray(-tagLength);
        const ciphertext = encryptedData.subarray(0, -tagLength);
        
        const decipher = crypto.createDecipheriv('aes-256-gcm', decryptedAesKey, iv);
        decipher.setAuthTag(authTag);
        
        let result = decipher.update(ciphertext, null, 'utf8');
        result += decipher.final('utf8');
        
        decrypted = result;
        usedConfig = { tagLength, position: 'end' };
        break;
      } catch (endError) {
        // Try auth tag at the beginning
        try {
          const authTag = encryptedData.subarray(0, tagLength);
          const ciphertext = encryptedData.subarray(tagLength);
          
          const decipher = crypto.createDecipheriv('aes-256-gcm', decryptedAesKey, iv);
          decipher.setAuthTag(authTag);
          
          let result = decipher.update(ciphertext, null, 'utf8');
          result += decipher.final('utf8');
          
          decrypted = result;
          usedConfig = { tagLength, position: 'beginning' };
          break;
        } catch (beginError) {
          // Continue to next tag length
          continue;
        }
      }
    }
    
    // If AES-GCM didn't work, fall back to trying different AES key offsets with GCM
    if (!decrypted) {
      const offsetsToTry = [2, 6, 8, 16, 32, 64, 70];
      
      for (const offset of offsetsToTry) {
        if (offset + 32 > decryptedAesKey.length) continue;
        
        const altKey = decryptedAesKey.subarray(offset, offset + 32);
        
        for (const tagLength of authTagLengths) {
          if (encryptedData.length <= tagLength) continue;
          
          try {
            const authTag = encryptedData.subarray(-tagLength);
            const ciphertext = encryptedData.subarray(0, -tagLength);
            
            const decipher = crypto.createDecipheriv('aes-256-gcm', altKey, iv);
            decipher.setAuthTag(authTag);
            
            let result = decipher.update(ciphertext, null, 'utf8');
            result += decipher.final('utf8');
            
            decrypted = result;
            usedConfig = { offset, tagLength, position: 'end' };
            break;
          } catch (error) {
            continue;
          }
        }
        
        if (decrypted) break;
      }
    }
    
    if (!decrypted) {
      return res.status(500).json({ 
        error: "AES-GCM decryption failed with all configurations",
        encryptedDataLength: encryptedData.length,
        availableOffsets: [0, 2, 6, 8, 16, 32, 64, 70]
      });
    }

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
      config: usedConfig
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

// Vercel (API Routes) expects default export
