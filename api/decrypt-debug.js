import crypto, { createPrivateKey, privateDecrypt, createDecipheriv } from "crypto";

const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY;

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }
  
  try {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = req.body;
    
    // Enhanced debugging information
    const debugInfo = {
      timestamp: new Date().toISOString(),
      hasPrivateKey: !!PRIVATE_KEY_PEM,
      privateKeyLength: PRIVATE_KEY_PEM ? PRIVATE_KEY_PEM.length : 0,
      inputValidation: {
        hasEncryptedAesKey: !!encrypted_aes_key,
        hasEncryptedFlowData: !!encrypted_flow_data,
        hasInitialVector: !!initial_vector,
        encryptedAesKeyLength: encrypted_aes_key ? encrypted_aes_key.length : 0,
        encryptedFlowDataLength: encrypted_flow_data ? encrypted_flow_data.length : 0,
        initialVectorLength: initial_vector ? initial_vector.length : 0
      }
    };

    if (!encrypted_aes_key || !encrypted_flow_data || !initial_vector) {
      return res.status(400).json({ 
        error: "Missing required fields",
        debug: debugInfo
      });
    }

    // Try to decode base64 first
    let aesKeyBuffer, flowDataBuffer, ivBuffer;
    try {
      aesKeyBuffer = Buffer.from(encrypted_aes_key, "base64");
      flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
      ivBuffer = Buffer.from(initial_vector, "base64");
      
      debugInfo.bufferSizes = {
        aesKeyBuffer: aesKeyBuffer.length,
        flowDataBuffer: flowDataBuffer.length,
        ivBuffer: ivBuffer.length
      };
    } catch (base64Error) {
      return res.status(400).json({ 
        error: "Invalid base64 encoding",
        debug: debugInfo,
        base64Error: base64Error.message
      });
    }

    // Create private key
    let privateKey;
    try {
      privateKey = createPrivateKey(PRIVATE_KEY_PEM);
      debugInfo.privateKeyInfo = {
        type: privateKey.asymmetricKeyType,
        size: privateKey.asymmetricKeySize
      };
    } catch (keyError) {
      return res.status(500).json({ 
        error: "Failed to create private key",
        debug: debugInfo,
        keyError: keyError.message
      });
    }

    // Try different padding modes for RSA decryption
    const paddingModes = [
      { name: 'OAEP', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
      { name: 'PKCS1', padding: crypto.constants.RSA_PKCS1_PADDING }
    ];

    let decryptedAesKey = null;
    let usedPadding = null;
    const paddingErrors = {};

    for (const mode of paddingModes) {
      try {
        decryptedAesKey = privateDecrypt(
          {
            key: privateKey,
            padding: mode.padding,
          },
          aesKeyBuffer
        );
        usedPadding = mode.name;
        debugInfo.rsaDecryption = {
          success: true,
          paddingUsed: usedPadding,
          decryptedAesKeyLength: decryptedAesKey.length
        };
        break;
      } catch (paddingError) {
        paddingErrors[mode.name] = paddingError.message;
      }
    }

    if (!decryptedAesKey) {
      return res.status(500).json({ 
        error: "RSA decryption failed with all padding modes",
        debug: debugInfo,
        paddingErrors: paddingErrors,
        suggestion: "The encrypted data was likely encrypted with a different public key"
      });
    }

    // Handle AES key length - detailed debugging
    debugInfo.aesKeyProcessing = {
      originalLength: decryptedAesKey.length,
      originalKeyHex: decryptedAesKey.toString('hex')
    };

    if (decryptedAesKey.length === 102) {
      // Try different offsets to find the correct AES key
      const possibleOffsets = [0, 2, 6, 8, 16, 32, 64, 70]; // Common offsets
      debugInfo.aesKeyProcessing.offsetTests = {};
      
      for (const offset of possibleOffsets) {
        if (offset + 32 <= decryptedAesKey.length) {
          const candidateKey = decryptedAesKey.subarray(offset, offset + 32);
          debugInfo.aesKeyProcessing.offsetTests[offset] = candidateKey.toString('hex');
        }
      }
      
      // Use first 32 bytes for now
      decryptedAesKey = decryptedAesKey.subarray(0, 32);
      debugInfo.aesKeyProcessing.method = 'first_32_bytes';
    } else if (decryptedAesKey.length > 32) {
      // If still longer, try first 32 bytes
      decryptedAesKey = decryptedAesKey.subarray(0, 32);
      debugInfo.aesKeyProcessing.method = 'first_32_bytes';
    } else if (decryptedAesKey.length !== 32) {
      return res.status(500).json({ 
        error: `Invalid AES key length: ${decryptedAesKey.length} bytes, expected 32 bytes`,
        debug: debugInfo
      });
    }

    debugInfo.aesKeyProcessing.finalLength = decryptedAesKey.length;
    debugInfo.aesKeyProcessing.finalKeyHex = decryptedAesKey.toString('hex');

    // Try AES decryption with both CBC and GCM modes
    const encryptedData = Buffer.from(encrypted_flow_data, "base64");
    const iv = Buffer.from(initial_vector, "base64");
    
    debugInfo.aesDecryption = {
      encryptedDataLength: encryptedData.length,
      ivLength: iv.length
    };
    
    // Try AES-GCM first (WhatsApp Flow data_api_version "3.0")
    try {
      console.log('Trying AES-256-GCM...');
      
      // For AES-GCM, extract auth tag (last 16 bytes) and ciphertext
      const authTagLength = 16;
      const authTag = encryptedData.subarray(-authTagLength);
      const ciphertext = encryptedData.subarray(0, -authTagLength);
      
      const gcmDecipher = crypto.createDecipheriv('aes-256-gcm', decryptedAesKey, iv);
      gcmDecipher.setAuthTag(authTag);
      
      let gcmDecrypted = gcmDecipher.update(ciphertext, null, 'utf8');
      gcmDecrypted += gcmDecipher.final('utf8');
      
      debugInfo.aesDecryption.gcm = {
        success: true,
        authTagLength: authTagLength,
        ciphertextLength: ciphertext.length,
        decryptedLength: gcmDecrypted.length
      };

      // Try parse as JSON
      let parsed = null;
      try {
        parsed = JSON.parse(gcmDecrypted);
        debugInfo.jsonParsing = { success: true, mode: 'AES-GCM' };
      } catch (jsonError) {
        debugInfo.jsonParsing = { 
          success: false, 
          error: jsonError.message,
          mode: 'AES-GCM'
        };
      }

      res.status(200).json({ 
        success: true,
        decrypted: gcmDecrypted, 
        json: parsed,
        algorithm: "AES-256-GCM",
        debug: debugInfo
      });
      return;

    } catch (gcmError) {
      debugInfo.aesDecryption.gcm = {
        success: false,
        error: gcmError.message
      };
      
      // Try AES-CBC as fallback
      try {
        console.log('AES-GCM failed, trying AES-256-CBC...');
        
        const cbcDecipher = crypto.createDecipheriv("aes-256-cbc", decryptedAesKey, iv);
        let cbcDecrypted = cbcDecipher.update(encryptedData, null, "utf8");
        cbcDecrypted += cbcDecipher.final("utf8");

        debugInfo.aesDecryption.cbc = {
          success: true,
          decryptedLength: cbcDecrypted.length
        };

        // Try parse as JSON
        let parsed = null;
        try {
          parsed = JSON.parse(cbcDecrypted);
          debugInfo.jsonParsing = { success: true, mode: 'AES-CBC' };
        } catch (jsonError) {
          debugInfo.jsonParsing = { 
            success: false, 
            error: jsonError.message,
            mode: 'AES-CBC'
          };
        }

        res.status(200).json({ 
          success: true,
          decrypted: cbcDecrypted, 
          json: parsed,
          algorithm: "AES-256-CBC",
          debug: debugInfo
        });
        return;

      } catch (cbcError) {
        debugInfo.aesDecryption.cbc = {
          success: false,
          error: cbcError.message
        };
        
        return res.status(500).json({ 
          error: "AES decryption failed with both GCM and CBC modes",
          debug: debugInfo,
          gcmError: gcmError.message,
          cbcError: cbcError.message
        });
      }
    }

  } catch (e) {
    res.status(500).json({ 
      error: e.message,
      debug: {
        unexpectedError: true,
        errorStack: e.stack
      }
    });
  }
}