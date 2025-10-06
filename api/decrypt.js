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
    
    // Pure RSA decryption - no AES involved!
    // Both encrypted_aes_key and encrypted_flow_data are RSA-encrypted
    
    let decryptedAesKey = null;
    let decryptedFlowData = null;
    
    // Decrypt the AES key (which might actually be metadata or part of the flow)
    try {
      decryptedAesKey = privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        Buffer.from(encrypted_aes_key, "base64")
      );
    } catch (pkcs1Error) {
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
          error: "RSA decryption failed for encrypted_aes_key",
          details: {
            pkcs1Error: pkcs1Error.message,
            oaepError: oaepError.message
          }
        });
      }
    }
    
    // Decrypt the flow data directly with RSA
    try {
      decryptedFlowData = privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        Buffer.from(encrypted_flow_data, "base64")
      );
    } catch (pkcs1Error) {
      try {
        decryptedFlowData = privateDecrypt(
          {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          },
          Buffer.from(encrypted_flow_data, "base64")
        );
      } catch (oaepError) {
        return res.status(500).json({ 
          error: "RSA decryption failed for encrypted_flow_data",
          details: {
            pkcs1Error: pkcs1Error.message,
            oaepError: oaepError.message
          }
        });
      }
    }

    // Convert decrypted flow data to string and try different decodings
    let decryptedText = decryptedFlowData.toString('utf8');
    let parsed = null;
    let decodingMethod = 'utf8';
    
    // If the UTF-8 conversion produces non-printable characters, try other approaches
    const isPrintable = /^[\x20-\x7E\s]*$/.test(decryptedText);
    
    if (!isPrintable) {
      // Try different decoding approaches
      
      // 1. Try base64 decoding
      try {
        const base64Decoded = Buffer.from(decryptedFlowData.toString('base64'), 'base64').toString('utf8');
        if (/^[\x20-\x7E\s]*$/.test(base64Decoded)) {
          decryptedText = base64Decoded;
          decodingMethod = 'base64->utf8';
        }
      } catch (e) {}
      
      // 2. Try hex decoding
      if (!isPrintable) {
        try {
          const hexDecoded = Buffer.from(decryptedFlowData.toString('hex'), 'hex').toString('utf8');
          if (/^[\x20-\x7E\s]*$/.test(hexDecoded)) {
            decryptedText = hexDecoded;
            decodingMethod = 'hex->utf8';
          }
        } catch (e) {}
      }
      
      // 3. Try gzip decompression
      if (!isPrintable) {
        try {
          const zlib = require('zlib');
          const decompressed = zlib.gunzipSync(decryptedFlowData).toString('utf8');
          if (/^[\x20-\x7E\s]*$/.test(decompressed)) {
            decryptedText = decompressed;
            decodingMethod = 'gzip->utf8';
          }
        } catch (e) {}
      }
      
      // 4. Try deflate decompression
      if (!isPrintable) {
        try {
          const zlib = require('zlib');
          const decompressed = zlib.inflateSync(decryptedFlowData).toString('utf8');
          if (/^[\x20-\x7E\s]*$/.test(decompressed)) {
            decryptedText = decompressed;
            decodingMethod = 'deflate->utf8';
          }
        } catch (e) {}
      }
    }

    // Try parse as JSON
    try {
      parsed = JSON.parse(decryptedText);
    } catch {
      parsed = null;
    }

    res.status(200).json({ 
      decrypted: decryptedText,
      json: parsed,
      algorithm: "RSA-2048",
      decodingMethod: decodingMethod,
      rawHex: decryptedFlowData.toString('hex'),
      aesKeyInfo: {
        length: decryptedAesKey.length,
        hex: decryptedAesKey.toString('hex')
      }
    });
    
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

// Vercel (API Routes) expects default export
