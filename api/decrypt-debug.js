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
      // PKCS1 padding structure: 0x00 0x02 [random padding] 0x00 [actual data]
      // Find the separator (0x00) after the padding
      let separatorIndex = -1;
      for (let i = 2; i < decryptedAesKey.length; i++) {
        if (decryptedAesKey[i] === 0x00) {
          separatorIndex = i;
          break;
        }
      }
      
      debugInfo.aesKeyProcessing.separatorIndex = separatorIndex;
      
      if (separatorIndex !== -1 && (decryptedAesKey.length - separatorIndex - 1) === 32) {
        // Extract the 32-byte AES key after the separator
        decryptedAesKey = decryptedAesKey.subarray(separatorIndex + 1);
        debugInfo.aesKeyProcessing.method = 'PKCS1_structure_parsing';
      } else {
        // Fallback: try last 32 bytes
        decryptedAesKey = decryptedAesKey.subarray(-32);
        debugInfo.aesKeyProcessing.method = 'last_32_bytes_fallback';
      }
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

    // Try AES decryption
    try {
      const decipher = createDecipheriv("aes-256-cbc", decryptedAesKey, ivBuffer);
      let decrypted = decipher.update(flowDataBuffer, null, "utf8");
      decrypted += decipher.final("utf8");

      debugInfo.aesDecryption = {
        success: true,
        decryptedLength: decrypted.length
      };

      // Try parse as JSON
      let parsed = null;
      try {
        parsed = JSON.parse(decrypted);
        debugInfo.jsonParsing = { success: true };
      } catch (jsonError) {
        debugInfo.jsonParsing = { 
          success: false, 
          error: jsonError.message 
        };
      }

      res.status(200).json({ 
        success: true,
        decrypted, 
        json: parsed,
        debug: debugInfo
      });

    } catch (aesError) {
      return res.status(500).json({ 
        error: "AES decryption failed",
        debug: debugInfo,
        aesError: aesError.message
      });
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