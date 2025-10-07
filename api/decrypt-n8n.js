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
        details: oaepError.message
      });
    }

    // Validate AES key length
    if (aesKey.length !== 16) {
      return res.status(500).json({ 
        error: `Invalid AES key length: ${aesKey.length} bytes (expected exactly 16 for AES-128)`
      });
    }

    // Step 2: Decode the IV
    const iv = Buffer.from(initial_vector, "base64");
    if (iv.length !== 16) {
      return res.status(500).json({ 
        error: `Invalid IV length: ${iv.length} bytes (expected exactly 16 for AES-128-GCM)`
      });
    }

    // Step 3: Decode the encrypted payload
    const encryptedPayload = Buffer.from(encrypted_flow_data, "base64");

    // Step 4: AES-128-GCM decryption
    let decryptedText = null;
    
    try {
      const tagLength = 16;
      if (encryptedPayload.length < tagLength) {
        return res.status(500).json({ 
          error: `Encrypted payload too short for GCM: ${encryptedPayload.length} bytes`
        });
      }
      
      const ciphertext = encryptedPayload.subarray(0, encryptedPayload.length - tagLength);
      const tag = encryptedPayload.subarray(encryptedPayload.length - tagLength);

      const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
      decipher.setAuthTag(tag);
      
      let decrypted = decipher.update(ciphertext);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      decryptedText = decrypted.toString('utf8');
      
    } catch (gcmError) {
      return res.status(500).json({ 
        error: "AES-128-GCM decryption failed",
        details: gcmError.message
      });
    }

    // Step 5: Parse the decrypted JSON
    let parsed = null;
    try {
      parsed = JSON.parse(decryptedText);
    } catch (jsonError) {
      return res.status(500).json({ 
        error: "Decrypted text is not valid JSON",
        decryptedText: decryptedText
      });
    }

    // Step 6: Create response based on the action
    let responseData = {};
    let formData = null; // Store form data for your business logic
    
    if (parsed.action === "ping") {
      responseData = {
        version: parsed.version,
        data: {
          status: "active"
        }
      };
    } else if (parsed.action === "data_exchange") {
      const currentScreen = parsed.screen;
      const submittedData = parsed.data || {};
      
      // CRITICAL: Extract mobile number from submitted data
      const mobileNumber = submittedData.mobile_number;
      
      // Capture form data for business logic (now includes mobile number!)
      formData = {
        screen: currentScreen,
        data: submittedData,
        mobileNumber: mobileNumber,
        timestamp: new Date().toISOString()
      };
      
      // Define the routing model from your flow2.json (includes PHONE_NUMBER_SCREEN)
      const routingModel = {
        "PHONE_NUMBER_SCREEN": "FIRST_NAME",
        "FIRST_NAME": "LAST_NAME",
        "LAST_NAME": "DATE_OF_BIRTH",
        "DATE_OF_BIRTH": "HEIGHT_CM",
        "HEIGHT_CM": "WEIGHT_KG",
        "WEIGHT_KG": "ALLERGIES",
        "ALLERGIES": "MEDICAL_FLAGS",
        "MEDICAL_FLAGS": "SUPPLEMENTS_TAKING",
        "SUPPLEMENTS_TAKING": "WAKE_TIME",
        "WAKE_TIME": "SLEEP_TIME",
        "SLEEP_TIME": "CITY",
        "CITY": "COUNTRY",
        "COUNTRY": "SEX_AT_BIRTH",
        "SEX_AT_BIRTH": "PREGNANCY_STATUS",
        "PREGNANCY_STATUS": "LACTATION_STATUS",
        "LACTATION_STATUS": "ACTIVITY_LEVEL",
        "ACTIVITY_LEVEL": "DIET_TYPE",
        "DIET_TYPE": "LANGUAGE_PREFERENCE",
        "LANGUAGE_PREFERENCE": "SPICE_LEVEL",
        "SPICE_LEVEL": "CUISINE_PREFERENCE",
        "CUISINE_PREFERENCE": "COOKING_OIL_USES",
        "COOKING_OIL_USES": "COOKING_FACILITIES",
        "COOKING_FACILITIES": "EATING_OUT_PER_WEEK",
        "EATING_OUT_PER_WEEK": "FASTING_PATTERN",
        "FASTING_PATTERN": "CAFFEINE_PREFERENCE",
        "CAFFEINE_PREFERENCE": "ALCOHOL_FREQUENCY",
        "ALCOHOL_FREQUENCY": "GOALS",
        "GOALS": "THANK_YOU_SCREEN"
      };
      
      const nextScreen = routingModel[currentScreen];
      
      if (!nextScreen) {
        return res.status(500).json({ 
          error: `Unknown screen or final screen: ${currentScreen}`,
          debug: { currentScreen, submittedData }
        });
      }
      
      // CRITICAL: For data_exchange, we must pass the mobile number to the next screen
      // This is the "baton pass" - we receive the mobile number and forward it
      responseData = {
        screen: nextScreen,
        data: {
          mobile_number: mobileNumber  // Always pass the mobile number forward!
        }
      };
    } else {
      return res.status(500).json({ 
        error: `Unknown action: ${parsed.action}`,
        receivedData: parsed
      });
    }

    // Step 7: Encrypt the response
    const responseIv = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) {
      responseIv[i] = iv[i] ^ 0xFF;
    }

    let base64Response = null;
    try {
      const responseJson = JSON.stringify(responseData);
      const responseBuffer = Buffer.from(responseJson, 'utf8');
      
      const cipher = crypto.createCipheriv('aes-128-gcm', aesKey, responseIv);
      
      let encryptedResponse = cipher.update(responseBuffer);
      encryptedResponse = Buffer.concat([encryptedResponse, cipher.final()]);
      
      const responseTag = cipher.getAuthTag();
      const finalResponse = Buffer.concat([encryptedResponse, responseTag]);
      base64Response = finalResponse.toString('base64');
      
    } catch (encryptionError) {
      return res.status(500).json({ 
        error: "Response encryption failed",
        details: encryptionError.message
      });
    }

    // Return BOTH the encrypted response AND the form data for n8n
    res.status(200).json({
      // This is what WhatsApp needs (for n8n to return)
      encryptedResponse: base64Response,
      
      // This is what YOU need for business logic
      decryptedRequest: {
        action: parsed.action,
        screen: parsed.screen,
        data: parsed.data,
        version: parsed.version
      },
      
      // Form data for easy access
      formData: formData,
      
      // Response data being sent back
      responseData: responseData,
      
      // Metadata
      timestamp: new Date().toISOString(),
      algorithm: "RSA-2048-OAEP-SHA256 + AES-128-GCM"
    });
    
  } catch (e) {
    res.status(500).json({ error: e.message, stack: e.stack });
  }
}