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
    let formData = null;
    
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
      
      // DEBUG: Log the entire parsed object to see what WhatsApp sends
      console.log('🔍 Full parsed data:', JSON.stringify(parsed, null, 2));
      
      // Extract mobile number from the data (baton pass pattern)
      // Filter out template string literals that WhatsApp doesn't evaluate
      let mobileNumber = submittedData.mobile_number || submittedData.PHONE_NUMBER_VAL || null;
      let countryCode = submittedData.country_code || submittedData.COUNTRY_CODE_VAL || null;
      
      // If we got template strings instead of actual values, ignore them
      if (mobileNumber && mobileNumber.includes('${')) {
        mobileNumber = null;
      }
      if (countryCode && countryCode.includes('${')) {
        countryCode = null;
      }
      
      // Capture form data for business logic
      formData = {
        screen: currentScreen,
        data: submittedData,
        mobileNumber: mobileNumber,
        countryCode: countryCode,
        timestamp: new Date().toISOString()
      };
      
      // Calculate Ayurveda quiz result if on final screen
      if (currentScreen === "QUESTION_TEN") {
        const answers = submittedData;
        let countA = 0, countB = 0, countC = 0;
        
        // Count answers
        Object.keys(answers).forEach(key => {
          if (key.startsWith('q')) {
            const answer = answers[key];
            if (answer === 'A') countA++;
            else if (answer === 'B') countB++;
            else if (answer === 'C') countC++;
          }
        });
        
        // Determine dominant dosha
        let result = 'Balanced';
        if (countA > countB && countA > countC) result = 'Vata';
        else if (countB > countA && countB > countC) result = 'Pitta';
        else if (countC > countA && countC > countB) result = 'Kapha';
        
        formData.quizResult = {
          vataCount: countA,
          pittaCount: countB,
          kaphaCount: countC,
          dominantDosha: result
        };
      }
      
      // Define the routing model for Ayurveda quiz (with PHONE_NUMBER_SCREEN as first)
      const routingModel = {
        "PHONE_NUMBER_SCREEN": "WELCOME_SCREEN",
        "WELCOME_SCREEN": "QUESTION_ONE",
        "QUESTION_ONE": "QUESTION_TWO",
        "QUESTION_TWO": "QUESTION_THREE",
        "QUESTION_THREE": "QUESTION_FOUR",
        "QUESTION_FOUR": "QUESTION_FIVE",
        "QUESTION_FIVE": "QUESTION_SIX",
        "QUESTION_SIX": "QUESTION_SEVEN",
        "QUESTION_SEVEN": "QUESTION_EIGHT",
        "QUESTION_EIGHT": "QUESTION_NINE",
        "QUESTION_NINE": "QUESTION_TEN",
        "QUESTION_TEN": "RESULTS",
        "RESULTS": null  // Terminal screen - end of flow
      };
      
      const nextScreen = routingModel[currentScreen];
      
      // Handle terminal screens (RESULTS)
      if (currentScreen === "RESULTS" || nextScreen === null) {
        // This is the final screen - calculate results and end flow
        const answers = submittedData;
        let countA = 0, countB = 0, countC = 0;
        
        // Count answers
        Object.keys(answers).forEach(key => {
          if (key.startsWith('q')) {
            const answer = answers[key];
            if (answer === 'A') countA++;
            else if (answer === 'B') countB++;
            else if (answer === 'C') countC++;
          }
        });
        
        // Determine dominant dosha
        let result = 'Balanced';
        if (countA > countB && countA > countC) result = 'Vata';
        else if (countB > countA && countB > countC) result = 'Pitta';
        else if (countC > countA && countC > countB) result = 'Kapha';
        
        formData.quizResult = {
          vataCount: countA,
          pittaCount: countB,
          kaphaCount: countC,
          dominantDosha: result
        };
        
        // Return success response indicating flow completion
        responseData = {
          status: "completed",
          data: {
            ...formData
          }
        };
      } else if (!nextScreen) {
        return res.status(500).json({ 
          error: `Unknown screen: ${currentScreen}`,
          debug: { currentScreen, submittedData }
        });
      } else {
        // CRITICAL: Baton pass - always forward mobile number and country code to next screen
        // On PHONE_NUMBER_SCREEN, we extract from form fields (PHONE_NUMBER_VAL, COUNTRY_CODE_VAL)
        // On all other screens, we receive from data and pass forward
        // BUT: Filter out template string literals that WhatsApp doesn't evaluate properly
        const cleanMobileNumber = mobileNumber && !mobileNumber.includes('${') ? mobileNumber : null;
        const cleanCountryCode = countryCode && !countryCode.includes('${') ? countryCode : null;
        
        const batonPassData = {};
        if (cleanCountryCode) {
          batonPassData.country_code = cleanCountryCode;
        }
        if (cleanMobileNumber) {
          batonPassData.mobile_number = cleanMobileNumber;
        }
        
        // Filter out template strings from submitted data
        const cleanedSubmittedData = {};
        Object.keys(submittedData).forEach(key => {
          const value = submittedData[key];
          // Only include non-template values
          if (typeof value === 'string' && value.includes('${')) {
            // Skip template strings
          } else {
            cleanedSubmittedData[key] = value;
          }
        });
        
        // Pass all previous data forward including mobile number
        responseData = {
          screen: nextScreen,
          data: {
            ...batonPassData,
            ...cleanedSubmittedData
          }
        };
      }
    } else if (parsed.action === "navigate") {
      // Handle flow navigation/initialization
      console.log('🧭 Navigate action received:', parsed);
      
      // Start at PHONE_NUMBER_SCREEN to collect mobile number first
      responseData = {
        screen: "PHONE_NUMBER_SCREEN",
        data: {}
      };
      
      formData = {
        screen: "navigate",
        data: parsed.data || {},
        timestamp: new Date().toISOString()
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

    // Return comprehensive data for n8n
    res.status(200).json({
      encryptedResponse: base64Response,
      decryptedRequest: {
        action: parsed.action,
        screen: parsed.screen,
        data: parsed.data,
        version: parsed.version
      },
      formData: formData,
      responseData: responseData,
      timestamp: new Date().toISOString(),
      flowType: "ayurveda_quiz",
      algorithm: "RSA-2048-OAEP-SHA256 + AES-128-GCM"
    });
    
  } catch (e) {
    res.status(500).json({ error: e.message, stack: e.stack });
  }
}
